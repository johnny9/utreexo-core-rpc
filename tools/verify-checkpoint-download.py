#!/usr/bin/env python3
"""Stream and authenticate the checkpoint referenced by the release manifest."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import BinaryIO


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "contrib" / "checkpoints" / "mainnet-943013.json"
CHUNK_BYTES = 1024 * 1024
PROGRESS_BYTES = 1024 * 1024 * 1024


class VerificationError(RuntimeError):
    """The remote object does not match the authenticated manifest."""


def validate_https_url(value: object) -> str:
    if not isinstance(value, str):
        raise VerificationError("download_url is not a string")
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port
    except ValueError as error:
        raise VerificationError(f"download_url is invalid: {error}") from error
    if parsed.scheme != "https" or not parsed.hostname:
        raise VerificationError("download_url must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise VerificationError("download_url must not contain credentials")
    return value


def load_manifest(path: pathlib.Path) -> tuple[str, int, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"could not read checkpoint manifest: {error}") from error

    if not isinstance(document, dict):
        raise VerificationError("checkpoint manifest must contain a JSON object")
    url = validate_https_url(document.get("download_url"))
    size = document.get("file_size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise VerificationError("file_size must be a positive integer")
    expected_sha256 = document.get("file_sha256")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or expected_sha256.lower() != expected_sha256
    ):
        raise VerificationError("file_sha256 must be 32-byte lowercase hexadecimal")
    try:
        bytes.fromhex(expected_sha256)
    except ValueError as error:
        raise VerificationError("file_sha256 must be 32-byte lowercase hexadecimal") from error
    return url, size, expected_sha256


class BoundedHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects: int) -> None:
        super().__init__()
        self.max_redirects = max_redirects
        self.redirects = 0

    def redirect_request(  # type: ignore[override]
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        validate_https_url(new_url)
        self.redirects += 1
        if self.redirects > self.max_redirects:
            raise VerificationError(
                f"checkpoint download exceeded {self.max_redirects} redirects"
            )
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def verify_stream(
    stream: BinaryIO,
    expected_size: int,
    expected_sha256: str,
    progress: Callable[[int], None] | None = None,
) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    next_progress = PROGRESS_BYTES
    while True:
        chunk = stream.read(CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            raise VerificationError(
                f"checkpoint is larger than declared size {expected_size}"
            )
        digest.update(chunk)
        if progress is not None and total >= next_progress:
            progress(total)
            next_progress = ((total // PROGRESS_BYTES) + 1) * PROGRESS_BYTES

    actual_sha256 = digest.hexdigest()
    if total != expected_size:
        raise VerificationError(
            f"checkpoint size mismatch: expected {expected_size}, got {total}"
        )
    if actual_sha256 != expected_sha256:
        raise VerificationError(
            "checkpoint SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    return total, actual_sha256


def verify_download(
    url: str,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: float,
    max_redirects: int,
) -> tuple[int, str]:
    validate_https_url(url)
    redirect_handler = BoundedHTTPSRedirectHandler(max_redirects)
    opener = urllib.request.build_opener(redirect_handler)
    request = urllib.request.Request(
        url,
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": "utreexo-bridge-release-verifier/1",
        },
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url = response.geturl()
            validate_https_url(final_url)
            status = response.getcode()
            if status != 200:
                raise VerificationError(
                    f"checkpoint download returned HTTP status {status}"
                )
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    advertised_size = int(content_length, 10)
                except ValueError as error:
                    raise VerificationError(
                        "checkpoint response has an invalid Content-Length"
                    ) from error
                if advertised_size != expected_size:
                    raise VerificationError(
                        "checkpoint Content-Length mismatch: "
                        f"expected {expected_size}, got {advertised_size}"
                    )

            return verify_stream(
                response,
                expected_size,
                expected_sha256,
                lambda count: print(
                    f"verified {count} checkpoint bytes...", file=sys.stderr
                ),
            )
    except VerificationError:
        raise
    except (OSError, http.client.HTTPException, urllib.error.URLError) as error:
        raise VerificationError(f"checkpoint download failed: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=DEFAULT_MANIFEST,
        help="checkpoint manifest (default: bundled mainnet manifest)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=60.0,
        help="per-operation network timeout (default: 60)",
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="maximum HTTPS redirects (default: 5)",
    )
    args = parser.parse_args()
    if not 0 < args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be in (0, 600]")
    if not 0 <= args.max_redirects <= 10:
        parser.error("--max-redirects must be between 0 and 10")

    try:
        url, expected_size, expected_sha256 = load_manifest(args.manifest)
        print(
            f"streaming checkpoint verification: bytes={expected_size} url={url}",
            file=sys.stderr,
        )
        size, sha256 = verify_download(
            url,
            expected_size,
            expected_sha256,
            args.timeout_seconds,
            args.max_redirects,
        )
    except VerificationError as error:
        print(f"checkpoint download verification error: {error}", file=sys.stderr)
        return 1

    print(f"checkpoint download verified: bytes={size} sha256={sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

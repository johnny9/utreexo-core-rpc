#!/usr/bin/env python3
"""Authenticate or availability-probe the checkpoint in the release manifest."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import pathlib
import re
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
RANGE_BYTES = 128 * 1024 * 1024


class VerificationError(RuntimeError):
    """The remote object does not match the authenticated manifest."""


class RetryableDownloadError(RuntimeError):
    """One bounded range could not be read completely."""


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
    max_retries: int = 5,
    range_bytes: int = RANGE_BYTES,
) -> tuple[int, str]:
    validate_https_url(url)
    if max_retries < 0:
        raise VerificationError("max_retries must not be negative")
    if range_bytes <= 0:
        raise VerificationError("range_bytes must be positive")
    redirect_handler = BoundedHTTPSRedirectHandler(max_redirects)
    opener = urllib.request.build_opener(redirect_handler)
    digest = hashlib.sha256()
    total = 0
    next_progress = PROGRESS_BYTES
    while total < expected_size:
        first = total
        last = min(expected_size, first + range_bytes) - 1
        expected_range_size = last - first + 1
        range_complete = False
        last_retry_error: Exception | None = None
        for attempt in range(max_retries + 1):
            redirect_handler.redirects = 0
            request = urllib.request.Request(
                url,
                headers={
                    "Accept-Encoding": "identity",
                    "Range": f"bytes={first}-{last}",
                    "User-Agent": "utreexo-bridge-release-verifier/1",
                },
            )
            candidate = digest.copy()
            range_size = 0
            try:
                with opener.open(request, timeout=timeout_seconds) as response:
                    validate_https_url(response.geturl())
                    status = response.getcode()

                    # Some endpoints ignore an initial Range header. Retain
                    # support for their complete 200 response, but any resumed
                    # request must start at the exact authenticated offset.
                    if status == 200 and first == 0:
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
                                f"verified {count} checkpoint bytes...",
                                file=sys.stderr,
                            ),
                        )
                    if status != 206:
                        raise VerificationError(
                            f"checkpoint range returned HTTP status {status}"
                        )

                    content_range = response.headers.get("Content-Range")
                    match = re.fullmatch(
                        r"bytes ([0-9]+)-([0-9]+)/([0-9]+)",
                        content_range or "",
                    )
                    if match is None:
                        raise VerificationError(
                            "checkpoint response has an invalid Content-Range"
                        )
                    advertised_first, advertised_last, advertised_total = (
                        int(value, 10) for value in match.groups()
                    )
                    if (
                        advertised_first != first
                        or advertised_last != last
                        or advertised_total != expected_size
                    ):
                        raise VerificationError(
                            "checkpoint Content-Range does not match the request"
                        )

                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            advertised_size = int(content_length, 10)
                        except ValueError as error:
                            raise VerificationError(
                                "checkpoint response has an invalid Content-Length"
                            ) from error
                        if advertised_size != expected_range_size:
                            raise VerificationError(
                                "checkpoint range Content-Length mismatch: "
                                f"expected {expected_range_size}, got {advertised_size}"
                            )

                    while range_size < expected_range_size:
                        chunk = response.read(
                            min(CHUNK_BYTES, expected_range_size - range_size)
                        )
                        if not chunk:
                            raise RetryableDownloadError(
                                "checkpoint range ended before its declared size"
                            )
                        range_size += len(chunk)
                        candidate.update(chunk)
                    if response.read(1):
                        raise VerificationError(
                            "checkpoint range is larger than its declared size"
                        )
            except VerificationError:
                raise
            except (
                OSError,
                RetryableDownloadError,
                http.client.HTTPException,
                urllib.error.URLError,
            ) as error:
                last_retry_error = error
                if attempt == max_retries:
                    break
                print(
                    "checkpoint range retry: "
                    f"bytes={first}-{last} attempt={attempt + 2} error={error}",
                    file=sys.stderr,
                )
                continue

            digest = candidate
            total += range_size
            range_complete = True
            if total >= next_progress:
                print(f"verified {total} checkpoint bytes...", file=sys.stderr)
                next_progress = ((total // PROGRESS_BYTES) + 1) * PROGRESS_BYTES
            break

        if not range_complete:
            raise VerificationError(
                "checkpoint download failed after retries: "
                f"bytes={first}-{last} error={last_retry_error}"
            )

    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise VerificationError(
            "checkpoint SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )
    return total, actual_sha256


def probe_download(
    url: str,
    expected_size: int,
    timeout_seconds: float,
    max_redirects: int,
    max_retries: int = 5,
) -> int:
    """Confirm that the remote object exposes its first and last byte ranges.

    This is an availability check, not a substitute for verify_download(). The
    compiled trust anchor still makes consumers authenticate the complete file
    size, SHA-256, block hash, leaf count, and roots before accepting it.
    """
    validate_https_url(url)
    if expected_size <= 0:
        raise VerificationError("expected size must be positive")
    if max_retries < 0:
        raise VerificationError("max_retries must not be negative")

    redirect_handler = BoundedHTTPSRedirectHandler(max_redirects)
    opener = urllib.request.build_opener(redirect_handler)
    offsets = (0,) if expected_size == 1 else (0, expected_size - 1)
    for offset in offsets:
        probe_complete = False
        last_retry_error: Exception | None = None
        for attempt in range(max_retries + 1):
            redirect_handler.redirects = 0
            request = urllib.request.Request(
                url,
                headers={
                    "Accept-Encoding": "identity",
                    "Range": f"bytes={offset}-{offset}",
                    "User-Agent": "utreexo-bridge-release-verifier/1",
                },
            )
            try:
                with opener.open(request, timeout=timeout_seconds) as response:
                    validate_https_url(response.geturl())
                    if response.getcode() != 206:
                        raise VerificationError(
                            "checkpoint availability probe requires HTTP byte ranges"
                        )

                    content_range = response.headers.get("Content-Range")
                    match = re.fullmatch(
                        r"bytes ([0-9]+)-([0-9]+)/([0-9]+)",
                        content_range or "",
                    )
                    if match is None:
                        raise VerificationError(
                            "checkpoint probe has an invalid Content-Range"
                        )
                    advertised_first, advertised_last, advertised_total = (
                        int(value, 10) for value in match.groups()
                    )
                    if (
                        advertised_first != offset
                        or advertised_last != offset
                        or advertised_total != expected_size
                    ):
                        raise VerificationError(
                            "checkpoint probe Content-Range does not match the request"
                        )

                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            advertised_size = int(content_length, 10)
                        except ValueError as error:
                            raise VerificationError(
                                "checkpoint probe has an invalid Content-Length"
                            ) from error
                        if advertised_size != 1:
                            raise VerificationError(
                                "checkpoint probe Content-Length is not one byte"
                            )

                    payload = response.read(2)
                    if not payload:
                        raise RetryableDownloadError(
                            "checkpoint probe ended before its declared byte"
                        )
                    if len(payload) != 1:
                        raise VerificationError(
                            "checkpoint probe returned more than its declared byte"
                        )
            except VerificationError:
                raise
            except (
                OSError,
                RetryableDownloadError,
                http.client.HTTPException,
                urllib.error.URLError,
            ) as error:
                last_retry_error = error
                if attempt == max_retries:
                    break
                print(
                    "checkpoint probe retry: "
                    f"bytes={offset}-{offset} attempt={attempt + 2} error={error}",
                    file=sys.stderr,
                )
                continue
            probe_complete = True
            break

        if not probe_complete:
            raise VerificationError(
                "checkpoint availability probe failed after retries: "
                f"bytes={offset}-{offset} error={last_retry_error}"
            )

    return len(offsets)


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
    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="maximum retries for each checkpoint range (default: 5)",
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help=(
            "only check first/last-byte availability; full-file authentication "
            "remains the default"
        ),
    )
    args = parser.parse_args()
    if not 0 < args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be in (0, 600]")
    if not 0 <= args.max_redirects <= 10:
        parser.error("--max-redirects must be between 0 and 10")
    if not 0 <= args.max_retries <= 10:
        parser.error("--max-retries must be between 0 and 10")

    try:
        url, expected_size, expected_sha256 = load_manifest(args.manifest)
        if args.probe_only:
            print(
                "probing checkpoint availability: "
                f"bytes={expected_size} url={url}",
                file=sys.stderr,
            )
            range_count = probe_download(
                url,
                expected_size,
                args.timeout_seconds,
                args.max_redirects,
                args.max_retries,
            )
            print(
                "checkpoint availability verified: "
                f"bytes={expected_size} ranges={range_count}"
            )
            return 0
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
            args.max_retries,
        )
    except VerificationError as error:
        print(f"checkpoint download verification error: {error}", file=sys.stderr)
        return 1

    print(f"checkpoint download verified: bytes={size} sha256={sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

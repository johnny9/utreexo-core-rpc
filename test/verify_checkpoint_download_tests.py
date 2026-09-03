#!/usr/bin/env python3
"""Offline tests for the release checkpoint streaming verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify-checkpoint-download.py"
SPEC = importlib.util.spec_from_file_location("verify_checkpoint_download", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class FakeResponse(io.BytesIO):
    def __init__(
        self, payload: bytes, url: str, status: int = 200, content_length: int | None = None
    ) -> None:
        super().__init__(payload)
        self._url = url
        self._status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def open(
        self, request: object, timeout: float | None = None
    ) -> FakeResponse:
        del request, timeout
        return self.response


class StreamingVerifierTests(unittest.TestCase):
    def test_accepts_exact_stream(self) -> None:
        payload = b"authenticated checkpoint fixture\x00" * 100
        expected = hashlib.sha256(payload).hexdigest()
        self.assertEqual(
            VERIFIER.verify_stream(io.BytesIO(payload), len(payload), expected),
            (len(payload), expected),
        )

    def test_rejects_short_long_and_hash_mismatch(self) -> None:
        payload = b"checkpoint"
        expected = hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "size mismatch"):
            VERIFIER.verify_stream(io.BytesIO(payload), len(payload) + 1, expected)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "larger"):
            VERIFIER.verify_stream(io.BytesIO(payload), len(payload) - 1, expected)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "SHA-256 mismatch"):
            VERIFIER.verify_stream(io.BytesIO(payload), len(payload), "00" * 32)

    def test_manifest_drives_url_size_and_hash(self) -> None:
        payload = b"fixture"
        document = {
            "download_url": "https://checkpoints.example/mainnet.chk",
            "file_size": len(payload),
            "file_sha256": hashlib.sha256(payload).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                VERIFIER.load_manifest(path),
                (document["download_url"], document["file_size"], document["file_sha256"]),
            )

    def test_download_path_streams_without_network(self) -> None:
        payload = b"remote checkpoint fixture"
        expected = hashlib.sha256(payload).hexdigest()
        response = FakeResponse(
            payload,
            "https://cdn.example/mainnet.chk",
            content_length=len(payload),
        )
        with mock.patch.object(
            VERIFIER.urllib.request,
            "build_opener",
            return_value=FakeOpener(response),
        ):
            self.assertEqual(
                VERIFIER.verify_download(
                    "https://checkpoints.example/mainnet.chk",
                    len(payload),
                    expected,
                    5.0,
                    2,
                ),
                (len(payload), expected),
            )

    def test_download_rejects_bad_advertised_size(self) -> None:
        payload = b"remote checkpoint fixture"
        response = FakeResponse(
            payload,
            "https://cdn.example/mainnet.chk",
            content_length=len(payload) + 1,
        )
        with mock.patch.object(
            VERIFIER.urllib.request,
            "build_opener",
            return_value=FakeOpener(response),
        ):
            with self.assertRaisesRegex(
                VERIFIER.VerificationError, "Content-Length mismatch"
            ):
                VERIFIER.verify_download(
                    "https://checkpoints.example/mainnet.chk",
                    len(payload),
                    hashlib.sha256(payload).hexdigest(),
                    5.0,
                    2,
                )

    def test_rejects_non_https_and_credential_urls(self) -> None:
        for url in (
            "http://checkpoints.example/mainnet.chk",
            "https:///mainnet.chk",
            "https://user:secret@checkpoints.example/mainnet.chk",
        ):
            with self.subTest(url=url):
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.validate_https_url(url)

    def test_redirect_limit_and_https_are_enforced(self) -> None:
        request = VERIFIER.urllib.request.Request(
            "https://checkpoints.example/mainnet.chk"
        )
        handler = VERIFIER.BoundedHTTPSRedirectHandler(1)
        redirected = handler.redirect_request(
            request,
            io.BytesIO(),
            302,
            "Found",
            {},
            "https://cdn.example/mainnet.chk",
        )
        self.assertIsNotNone(redirected)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "exceeded"):
            handler.redirect_request(
                request,
                io.BytesIO(),
                302,
                "Found",
                {},
                "https://cdn2.example/mainnet.chk",
            )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "HTTPS"):
            VERIFIER.BoundedHTTPSRedirectHandler(5).redirect_request(
                request,
                io.BytesIO(),
                302,
                "Found",
                {},
                "http://cdn.example/mainnet.chk",
            )


if __name__ == "__main__":
    unittest.main()

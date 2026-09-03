#!/usr/bin/env python3
"""Check that the distributable checkpoint manifest matches the compiled anchor."""

import argparse
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contrib" / "checkpoints" / "mainnet-943013.json"
SOURCE = ROOT / "src" / "trusted_checkpoint.cpp"
CHECKPOINT_HEADER = ROOT / "include" / "utreexo" / "checkpoint.h"

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--require-download-url",
    action="store_true",
    help="fail unless the authenticated checkpoint has an HTTPS download URL",
)
args = parser.parse_args()


def fail(message: str) -> None:
    print(f"checkpoint manifest error: {message}", file=sys.stderr)
    raise SystemExit(1)


document = json.loads(MANIFEST.read_text(encoding="utf-8"))
source = SOURCE.read_text(encoding="utf-8")


def match(pattern: str, label: str, contents: str = source) -> re.Match[str]:
    found = re.search(pattern, contents, re.DOTALL)
    if found is None:
        fail(f"could not parse compiled {label}")
    return found


def cpp_integer(value: str) -> int:
    return int(value.replace("'", ""))

if document.get("schema") != 1:
    fail("unsupported schema")
if document.get("network") != "mainnet" or document.get("height") != 943013:
    fail("unexpected network or height")
if document.get("checkpoint_format") != 3:
    fail("unexpected checkpoint format")
format_match = match(
    r"CHECKPOINT_FORMAT_VERSION\s*\{\s*([0-9']+)\s*\}",
    "checkpoint format",
    CHECKPOINT_HEADER.read_text(encoding="utf-8"),
)
if cpp_integer(format_match.group(1)) != document["checkpoint_format"]:
    fail("manifest checkpoint format differs from the compiled reader")
if document.get("roots_encoding") != (
    "sha512_256_internal_bytes_high_row_to_low_row_present_roots"
):
    fail("unexpected root encoding")

num_leaves = document.get("num_leaves")
roots = document.get("roots")
if not isinstance(num_leaves, int) or num_leaves < 0:
    fail("num_leaves is not an unsigned integer")
if not isinstance(roots, list) or len(roots) != num_leaves.bit_count():
    fail("root count does not match occupied accumulator rows")

required_hex = [document.get("block_hash"), document.get("file_sha256"), *roots]
for value in required_hex:
    if not isinstance(value, str) or len(value) != 64:
        fail("hash values must be 32-byte lowercase hex strings")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        fail(f"invalid hash: {error}")
    if value.lower() != value:
        fail("hash values must use lowercase hex")

roots_match = match(
    r"static const std::array<Hash256,\s*([0-9]+)> roots\s*\{(.*?)\n\s*\};",
    "ordered roots",
)
compiled_root_count = int(roots_match.group(1))
compiled_roots = re.findall(r'TrustedHash\("([0-9a-f]{64})"\)', roots_match.group(2))
if len(compiled_roots) != compiled_root_count or compiled_roots != roots:
    fail("ordered roots differ from the compiled anchor")

checkpoint_match = match(
    r"static const TrustedCheckpoint checkpoint\s*\{(.*?)\n\s*\};",
    "checkpoint initializer",
)
checkpoint = checkpoint_match.group(1)
compiled = {
    "name": match(r'\.name\s*=\s*"([^"]+)"', "name", checkpoint).group(1),
    "height": cpp_integer(match(r"\.point\s*=\s*ChainPoint\s*\{\s*([0-9']+)",
                                "height", checkpoint).group(1)),
    "block_hash": match(r'TrustedBitcoinHash\(\s*"([0-9a-f]{64})"\s*\)',
                        "block hash", checkpoint).group(1),
    "num_leaves": cpp_integer(match(r"\.num_leaves\s*=\s*([0-9']+)(?:ULL)?",
                                    "leaf count", checkpoint).group(1)),
    "file_size": cpp_integer(match(r"\.file_size\s*=\s*([0-9']+)(?:ULL)?",
                                   "file size", checkpoint).group(1)),
    "file_sha256": match(r'\.file_sha256\s*=\s*TrustedHash\(\s*"([0-9a-f]{64})"',
                         "file hash", checkpoint).group(1),
}
for field, compiled_value in compiled.items():
    if document.get(field) != compiled_value:
        fail(f"{field} differs from the compiled anchor")

if document.get("file_name") != f"{document['name']}-compact.chk":
    fail("checkpoint file name is inconsistent")
reference = document.get("reference")
if reference != {
    "implementation": "utreexod",
    "commit": "25deba281b612f8b87f734b0ac169d8a46ede988",
}:
    fail("unexpected reference implementation or commit")
if reference["commit"] not in source:
    fail("reference commit is not recorded with the compiled anchor")
download_url = document.get("download_url")
if download_url is not None and not (
    isinstance(download_url, str) and download_url.startswith("https://")
):
    fail("download_url must be null or an HTTPS URL")
if args.require_download_url and download_url is None:
    fail("a release requires an HTTPS checkpoint download_url")

print(
    "checkpoint manifest matches compiled anchor: "
    f"{document['name']} roots={len(roots)} bytes={document['file_size']}"
)

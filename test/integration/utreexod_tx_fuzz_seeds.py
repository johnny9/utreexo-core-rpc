#!/usr/bin/env python3
"""Extract binary fuzz seeds from the generated, pinned Go wire fixtures."""

import argparse
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    fixtures = Path(__file__).resolve().parents[1] / "data" / "utreexod_tx_vectors.h"
    fields = re.findall(r'\.(raw|announcement|request|response) = "([0-9a-f]+)"', fixtures.read_text())
    if len(fields) != 80:
        raise ValueError("expected four payloads for each of the 20 Go fixtures")
    for index, (kind, encoded) in enumerate(fields):
        (args.directory / f"{index:02d}-{kind}").write_bytes(bytes.fromhex(encoded))


if __name__ == "__main__":
    main()

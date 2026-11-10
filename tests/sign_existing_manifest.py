#!/usr/bin/env python3
"""
Test helper for T10b only - not part of the normal workflow.

Signs a release's manifest.json exactly as it is on disk, without rebuilding
it from payload/. This lets us simulate a publisher whose build pipeline was
tricked into signing a manifest containing a path like ../outside.txt, so we
can prove that check 4 (UNSAFE_PATH) still stops it even when the signature
is valid.

Usage: python3 tests/sign_existing_manifest.py <release_folder> <private_key.pem>
"""

import getpass
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    release, key_path = Path(sys.argv[1]), Path(sys.argv[2])
    passphrase = getpass.getpass("Private key passphrase: ")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase.encode())
    except (ValueError, TypeError):
        print("ERROR: wrong passphrase or damaged key.")
        return 2
    manifest_bytes = (release / "manifest.json").read_bytes()
    (release / "signature.sig").write_bytes(key.sign(manifest_bytes))
    print(f"Re-signed {release / 'manifest.json'} as-is.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

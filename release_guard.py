#!/usr/bin/env python3
"""
release_guard.py - signed software release verification for HarbourView.

CIT4020 Computer Security, Assignment 2.

Commands
    setup   create an Ed25519 key pair and the trusted publisher registry
    sign    hash every file in <release>/payload, write manifest.json, sign it
    verify  run the five checks and print ACCEPTED or REJECTED with a reason

The tool only ever reads file bytes. It never runs, installs or extracts
anything inside a release folder.
"""

import argparse
import getpass
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "signature.sig"
PAYLOAD_NAME = "payload"
REGISTRY_NAME = "trusted_publishers.json"
DEFAULT_LOG = "release_log.jsonl"
MIN_PASSPHRASE_LEN = 8
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class Rejected(Exception):
    """Raised by a verification check. `reason` is the code shown to the user."""

    def __init__(self, reason, detail=""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def sha256_file(path):
    """Return the SHA-256 hex digest of a file, read in 64 KB chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def public_key_fingerprint(public_key):
    """SHA-256 of the raw 32-byte Ed25519 public key (used for the bonus check)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def list_payload_files(payload_dir):
    """All regular files under payload/, as sorted POSIX paths relative to payload/."""
    files = []
    for path in payload_dir.rglob("*"):
        if path.is_file():
            files.append(path.relative_to(payload_dir).as_posix())
    return sorted(files)


def write_log(log_path, operation, release, publisher_id, result, reason):
    """Append one JSON line per sign/verify attempt. Keys and passphrases are never passed in."""
    entry = {
        "time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operation": operation,
        "release_folder": str(release),
        "publisher_id": publisher_id,
        "result": result,
        "reason": reason,
    }
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def load_registry(registry_path):
    """Read trusted_publishers.json. Returns a dict keyed by publisher_id."""
    with open(registry_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    publishers = data.get("publishers") if isinstance(data, dict) else None
    if not isinstance(publishers, list):
        raise ValueError("registry must contain a 'publishers' list")
    return {entry["publisher_id"]: entry for entry in publishers}


# ---------------------------------------------------------------------------
# Part A - setup
# ---------------------------------------------------------------------------

def cmd_setup(args):
    keys_dir = Path(args.keys_dir)
    verifier_dir = Path(args.verifier_dir)
    private_path = keys_dir / f"{args.publisher_id}_private.pem"
    public_path = verifier_dir / f"{args.publisher_id}_public.pem"
    registry_path = verifier_dir / REGISTRY_NAME

    # Refuse to overwrite existing keys. Losing the old private key would
    # break every release already signed with it.
    existing = [p for p in (private_path, public_path) if p.exists()]
    if existing:
        print("ERROR: key files already exist, setup will not overwrite them:")
        for path in existing:
            print(f"  {path}")
        return 2

    # Hidden prompt, asked twice. The passphrase only lives in memory.
    passphrase = getpass.getpass("New private key passphrase: ")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        print(f"ERROR: passphrase must be at least {MIN_PASSPHRASE_LEN} characters.")
        return 2
    if passphrase != getpass.getpass("Confirm passphrase: "):
        print("ERROR: passphrases do not match. Nothing was created.")
        return 2

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    keys_dir.mkdir(parents=True, exist_ok=True)
    verifier_dir.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)  # owner read/write only
    public_path.write_bytes(public_pem)

    # Add this publisher to the registry, keeping any publishers already there.
    if registry_path.exists():
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    else:
        registry = {"publishers": []}
    registry["publishers"] = [
        p for p in registry["publishers"] if p.get("publisher_id") != args.publisher_id
    ]
    registry["publishers"].append({
        "publisher_id": args.publisher_id,
        # Stored relative to the verifier folder so the folder can be moved.
        "public_key_path": public_path.name,
        "public_key_sha256": public_key_fingerprint(public_key),
        "enabled": True,
    })
    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")

    print(f"Private key (encrypted): {private_path}")
    print(f"Public key:              {public_path}")
    print(f"Registry updated:        {registry_path}")
    return 0


# ---------------------------------------------------------------------------
# Part B - sign
# ---------------------------------------------------------------------------

def cmd_sign(args):
    release = Path(args.release)
    payload = release / PAYLOAD_NAME
    log_path = Path(args.log)

    if not payload.is_dir():
        print(f"ERROR: {payload} does not exist or is not a folder.")
        write_log(log_path, "sign", release, args.publisher_id, "FAILED", "NO_PAYLOAD")
        return 2

    # Unlock the key first. If the passphrase is wrong we stop here, before
    # manifest.json or signature.sig are touched.
    passphrase = getpass.getpass("Private key passphrase: ")
    try:
        key_bytes = Path(args.key).read_bytes()
        private_key = serialization.load_pem_private_key(key_bytes, password=passphrase.encode())
    except FileNotFoundError:
        print(f"ERROR: private key not found: {args.key}")
        write_log(log_path, "sign", release, args.publisher_id, "FAILED", "KEY_NOT_FOUND")
        return 2
    except (ValueError, TypeError):
        # cryptography raises ValueError for a wrong passphrase or corrupt PEM.
        print("ERROR: could not unlock the private key. The passphrase is wrong "
              "or the key file is damaged. No files were changed.")
        write_log(log_path, "sign", release, args.publisher_id, "FAILED", "WRONG_PASSPHRASE")
        return 2

    if not isinstance(private_key, Ed25519PrivateKey):
        print("ERROR: the key file is not an Ed25519 private key.")
        write_log(log_path, "sign", release, args.publisher_id, "FAILED", "WRONG_KEY_TYPE")
        return 2

    files = [
        {"path": rel, "sha256": sha256_file(payload / rel)}
        for rel in list_payload_files(payload)
    ]
    manifest = {
        "publisher_id": args.publisher_id,
        "release_name": args.release_name or release.name,
        "files": files,
    }
    # These exact bytes are what gets signed and what is written to disk.
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    signature = private_key.sign(manifest_bytes)

    (release / MANIFEST_NAME).write_bytes(manifest_bytes)
    (release / SIGNATURE_NAME).write_bytes(signature)

    print(f"Signed {len(files)} file(s) in {release}")
    print(f"  {release / MANIFEST_NAME}")
    print(f"  {release / SIGNATURE_NAME}")
    write_log(log_path, "sign", release, args.publisher_id, "SIGNED", "OK")
    return 0


# ---------------------------------------------------------------------------
# Part C - verify (five checks, in order)
# ---------------------------------------------------------------------------

def check_1_manifest(release):
    """manifest.json and signature.sig exist, JSON parses, required fields present."""
    manifest_path = release / MANIFEST_NAME
    signature_path = release / SIGNATURE_NAME
    if not manifest_path.is_file() or not signature_path.is_file():
        raise Rejected("INVALID_MANIFEST", "manifest.json or signature.sig is missing")

    manifest_bytes = manifest_path.read_bytes()
    signature = signature_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Rejected("INVALID_MANIFEST", f"manifest.json is not readable JSON ({exc})")

    if not isinstance(manifest, dict):
        raise Rejected("INVALID_MANIFEST", "manifest.json must be a JSON object")
    for field, kind in (("publisher_id", str), ("release_name", str), ("files", list)):
        if not isinstance(manifest.get(field), kind):
            raise Rejected("INVALID_MANIFEST", f"field '{field}' is missing or the wrong type")

    seen = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) \
                or not isinstance(entry.get("sha256"), str) \
                or not SHA256_HEX.match(entry["sha256"]):
            raise Rejected("INVALID_MANIFEST", f"bad file entry: {entry}")
        if entry["path"] in seen:
            raise Rejected("INVALID_MANIFEST", f"duplicate path: {entry['path']}")
        seen.add(entry["path"])

    return manifest, manifest_bytes, signature


def check_2_publisher(manifest, registry_path):
    """publisher_id must be in the registry and enabled."""
    try:
        registry = load_registry(registry_path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # A broken registry means we cannot make a trust decision, so reject.
        raise Rejected("UNKNOWN_PUBLISHER", f"trusted registry unreadable ({exc})")

    entry = registry.get(manifest["publisher_id"])
    if entry is None:
        raise Rejected("UNKNOWN_PUBLISHER", f"'{manifest['publisher_id']}' is not in the registry")
    if entry.get("enabled") is not True:
        raise Rejected("PUBLISHER_DISABLED", f"'{manifest['publisher_id']}' is disabled")
    return entry


def check_3_signature(entry, registry_path, manifest_bytes, signature):
    """Verify with the public key named in the registry, never one shipped with the release."""
    key_path = Path(entry.get("public_key_path", ""))
    if not key_path.is_absolute():
        key_path = registry_path.parent / key_path
    try:
        public_key = serialization.load_pem_public_key(key_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise Rejected("BAD_SIGNATURE", f"registry public key cannot be loaded ({exc})")
    if not isinstance(public_key, Ed25519PublicKey):
        raise Rejected("BAD_SIGNATURE", "registry public key is not Ed25519")

    # Optional challenge: the registry pins the key's fingerprint, so swapping
    # the .pem file in the verifier folder is detected.
    pinned = entry.get("public_key_sha256")
    if pinned and public_key_fingerprint(public_key) != pinned:
        raise Rejected("KEY_FINGERPRINT_MISMATCH",
                       "public key file does not match the fingerprint in the registry")

    try:
        public_key.verify(signature, manifest_bytes)
    except InvalidSignature:
        raise Rejected("BAD_SIGNATURE", "signature does not match manifest.json")


def check_4_paths(manifest):
    """Reject any path that could point outside payload/."""
    for entry in manifest["files"]:
        path = entry["path"]
        # Treat backslashes as separators too, so ..\x is caught.
        parts = PurePosixPath(path.replace("\\", "/")).parts
        if path.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", path):
            raise Rejected("UNSAFE_PATH", f"unsafe path in manifest: {path}")


def check_5_files(manifest, release):
    """Every listed file exists, nothing extra, every hash matches."""
    payload = release / PAYLOAD_NAME
    payload_root = payload.resolve()
    listed = {entry["path"]: entry["sha256"] for entry in manifest["files"]}

    for rel in listed:
        target = payload / rel
        # Defence in depth: a symlink inside payload/ must not lead outside it.
        if not target.resolve().is_relative_to(payload_root):
            raise Rejected("UNSAFE_PATH", f"{rel} resolves outside payload/")
        if not target.is_file():
            raise Rejected("MISSING_FILE", f"listed file not found: {rel}")

    actual = set(list_payload_files(payload)) if payload.is_dir() else set()
    extra = sorted(actual - set(listed))
    if extra:
        raise Rejected("EXTRA_FILE", f"file not in manifest: {extra[0]}")

    for rel, expected in listed.items():
        if sha256_file(payload / rel) != expected:
            raise Rejected("HASH_MISMATCH", f"hash does not match for {rel}")


def cmd_verify(args):
    release = Path(args.release)
    registry_path = Path(args.registry)
    log_path = Path(args.log)
    publisher_id = None

    try:
        manifest, manifest_bytes, signature = check_1_manifest(release)
        publisher_id = manifest["publisher_id"]
        print("[1/5] Manifest readable ........ OK")
        entry = check_2_publisher(manifest, registry_path)
        print("[2/5] Publisher trusted ........ OK")
        check_3_signature(entry, registry_path, manifest_bytes, signature)
        print("[3/5] Signature valid .......... OK")
        check_4_paths(manifest)
        print("[4/5] Paths safe ............... OK")
        check_5_files(manifest, release)
        print("[5/5] Files match manifest ..... OK")
    except Rejected as rej:
        print(f"REJECTED - {rej.reason}")
        if rej.detail:
            print(f"  {rej.detail}")
        write_log(log_path, "verify", release, publisher_id, "REJECTED", rej.reason)
        return 1

    print(f"ACCEPTED - {manifest['release_name']} from {publisher_id}")
    write_log(log_path, "verify", release, publisher_id, "ACCEPTED", "OK")
    return 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description="HarbourView signed release verification tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="create keys and the trusted publisher registry")
    p_setup.add_argument("--publisher-id", default="harbourview")
    p_setup.add_argument("--keys-dir", default="publisher_keys")
    p_setup.add_argument("--verifier-dir", default="verifier")
    p_setup.set_defaults(func=cmd_setup)

    p_sign = sub.add_parser("sign", help="hash and sign a release folder")
    p_sign.add_argument("release", help="release folder containing payload/")
    p_sign.add_argument("--publisher-id", default="harbourview")
    p_sign.add_argument("--key", default="publisher_keys/harbourview_private.pem")
    p_sign.add_argument("--release-name", help="defaults to the folder name")
    p_sign.add_argument("--log", default=DEFAULT_LOG)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="verify a signed release folder")
    p_verify.add_argument("release", help="release folder to check")
    p_verify.add_argument("--registry", default=f"verifier/{REGISTRY_NAME}")
    p_verify.add_argument("--log", default=DEFAULT_LOG)
    p_verify.set_defaults(func=cmd_verify)
    return parser


def main():
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())

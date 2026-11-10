# release_guard - HarbourView signed release verification

CIT4020 Computer Security, Assignment 2.

`release_guard.py` lets a publisher sign a software release and lets a client
office check it before accepting it. A release is accepted only when the
publisher is approved, the signature is valid and every file matches the
signed manifest.

The tool reads file bytes only. It never runs, installs or extracts anything
in a release.

## Requirements

- Kali Linux or Ubuntu with Python 3.9 or later
- The `cryptography` package

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Folder layout after setup

```
release_guard.py
publisher_keys/harbourview_private.pem   publisher only - encrypted, never shared
verifier/harbourview_public.pem          copied to client offices
verifier/trusted_publishers.json         the client's list of approved publishers
release_A/payload/...                    files being shipped
release_A/manifest.json                  created by sign
release_A/signature.sig                  created by sign
release_log.jsonl                        one line per sign/verify attempt
```

## Commands

### 1. Setup (once)

```bash
python3 release_guard.py setup
```

You are asked for a passphrase twice (hidden). Setup creates the encrypted
private key, the public key and `verifier/trusted_publishers.json`. Running it
again refuses to overwrite the keys.

Check the key is encrypted:

```bash
head -1 publisher_keys/harbourview_private.pem
```

Expected: `-----BEGIN ENCRYPTED PRIVATE KEY-----`

### 2. Sign a release

```bash
python3 release_guard.py sign release_A --release-name "HarbourView Reporting Tool 1.0"
```

### 3. Verify a release

```bash
python3 release_guard.py verify release_A
```

Prints the five checks and then `ACCEPTED`, or `REJECTED - <REASON>`.
Exit code 0 means accepted, 1 means rejected, 2 means an error.

### Options

| Command | Option | Default |
|---|---|---|
| setup | `--publisher-id` | `harbourview` |
| setup | `--keys-dir` | `publisher_keys` |
| setup | `--verifier-dir` | `verifier` |
| sign | `--publisher-id` | `harbourview` |
| sign | `--key` | `publisher_keys/harbourview_private.pem` |
| sign | `--release-name` | folder name |
| sign / verify | `--log` | `release_log.jsonl` |
| verify | `--registry` | `verifier/trusted_publishers.json` |

## Verification checks (in order)

| # | Check | Reason on failure |
|---|---|---|
| 1 | manifest.json and signature.sig exist, JSON readable, required fields present | `INVALID_MANIFEST` |
| 2 | publisher_id is in the registry and enabled | `UNKNOWN_PUBLISHER` / `PUBLISHER_DISABLED` |
| 3 | signature valid using the registry's public key (and its fingerprint matches) | `BAD_SIGNATURE` / `KEY_FINGERPRINT_MISMATCH` |
| 4 | no path contains `..` or starts with `/` | `UNSAFE_PATH` |
| 5 | every listed file exists, no extra files, hashes match | `MISSING_FILE` / `EXTRA_FILE` / `HASH_MISMATCH` |

## Running the tests (T1-T10)

Sign `release_A` once, then copy it for every test so the clean version is
never touched:

```bash
for t in T3 T4a T4b T5 T6 T7 T8 T10a T10b T10c T10d BONUS; do cp -r release_A release_$t; done
```

| Test | Commands |
|---|---|
| T1 | `python3 release_guard.py setup` then `head -1 publisher_keys/harbourview_private.pem` then `python3 release_guard.py setup` again |
| T2 | `python3 release_guard.py verify release_A` then `tail -1 release_log.jsonl` |
| T3 | `echo 'import os  # injected' >> release_T3/payload/app.py` then verify `release_T3` |
| T4 | `rm release_T4a/payload/config/settings.ini`, verify; `echo surprise > release_T4b/payload/backdoor.sh`, verify |
| T5 | edit `release_name` in `release_T5/manifest.json` with nano, verify |
| T6 | `printf '\x00' \| dd of=release_T6/signature.sig bs=1 seek=0 count=1 conv=notrunc`, verify |
| T7 | `python3 release_guard.py setup --publisher-id coastal_updates --keys-dir rogue_keys --verifier-dir rogue_verifier`, then `python3 release_guard.py sign release_T7 --publisher-id coastal_updates --key rogue_keys/coastal_updates_private.pem`, verify |
| T8 | set `"enabled": false` in `verifier/trusted_publishers.json`, verify `release_T8`; set back to `true`, verify again |
| T9 | `sha256sum release_A/manifest.json release_A/signature.sig`, then sign `release_A` with a wrong passphrase, then run `sha256sum` again and compare |
| T10a | add `{"path": "../outside.txt", "sha256": "<64 zeros>"}` to the files list in `release_T10a/manifest.json`, verify |
| T10b | copy that manifest into `release_T10b`, run `python3 tests/sign_existing_manifest.py release_T10b publisher_keys/harbourview_private.pem`, verify |
| T10c | `python3 release_guard.py sign release_T10c --publisher-id harbourview --key rogue_keys/coastal_updates_private.pem`, verify |
| T10d | delete the last `}` from `release_T10d/manifest.json`, verify |
| Bonus | `cp rogue_verifier/coastal_updates_public.pem verifier/harbourview_public.pem` (back up first), verify `release_BONUS`, restore |

For T6, check that the first byte was not already `00`. If it was, use `\x01`.

## Log format

Each line of `release_log.jsonl`:

```json
{"time_utc": "2026-10-26T21:08:56Z", "operation": "verify", "release_folder": "release_A", "publisher_id": "harbourview", "result": "ACCEPTED", "reason": "OK"}
```

Keys and passphrases are never written to the log.

## What is not included in the ZIP

The private key, the passphrase and the `rogue_keys` folder are deliberately
left out. Run `setup` to create your own.

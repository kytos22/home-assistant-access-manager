"""Create/verify a private SQLite recovery bundle without starting Access Manager.

Not a Supervisor backup or restore command. Never overwrites an existing target,
imports the app, connects to HA, checkpoints the live DB, or prints secrets.
"""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time

from cryptography.fernet import Fernet


DATABASE = "fingerprint_admin.db"
COMPANIONS = ("credential_encryption.key", "esphome_connection.key", "options.json")


def private_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def companions(root):
    result = {}
    for name in COMPANIONS:
        path = root / name
        if path.is_symlink():
            raise ValueError("Recovery companion must not be a symlink")
        result[name] = path.read_bytes() if path.exists() else None
    return result


def readonly_database(path, immutable=False):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Recovery database must be an existing regular file")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro" + ("&immutable=1" if immutable else ""), uri=True, timeout=3)


def verify_data(root):
    """Read only a finalized offline copy; never instantiate Registry."""
    root = Path(root)
    if any((root / (DATABASE + suffix)).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("Recovery database must be self-contained")
    with closing(readonly_database(root / DATABASE, immutable=True)) as connection:
        connection.row_factory = sqlite3.Row
        if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
            raise ValueError("Recovery integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Recovery foreign-key check failed")
        settings = dict(connection.execute("SELECT key, value FROM settings"))
        counts = {}
        verified = 0
        legacy = 0
        cipher = None
        key = root / "credential_encryption.key"
        if key.is_file():
            cipher = Fernet(key.read_bytes().strip())
        for table in ("keypad_credentials", "shared_keypad_credentials"):
            rows = connection.execute(f"SELECT * FROM {table}").fetchall()
            counts[table] = len(rows)
            for row in rows:
                ciphertext = row["secret_ciphertext"]
                if not ciphertext:
                    legacy += 1
                    continue
                if cipher is None:
                    raise ValueError("Recovery credential key is missing")
                value = cipher.decrypt(ciphertext.encode("ascii")).decode("utf-8")
                version = row["hash_version"]
                if version == 2:
                    message = f"v2\0{row['reader_id']}\0{value}"
                elif version == 1:
                    message = f"{row['reader_id']}\0{value}\0{row['keypad_action']}"
                else:
                    raise ValueError("Unknown recovery credential hash version")
                digest = hmac.new(bytes.fromhex(settings["credential_hmac_key"]), message.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(digest, row["secret_hash"]):
                    raise ValueError("Recovery credential hash verification failed")
                verified += 1
        builder_verified = False
        if settings.get("esphome_token"):
            builder = Fernet((root / "esphome_connection.key").read_bytes().strip())
            builder.decrypt(settings["esphome_token"].encode("ascii")).decode("utf-8")
            builder_verified = True
        if (root / "options.json").exists():
            if not isinstance(json.loads((root / "options.json").read_text()), dict):
                raise ValueError("Invalid recovery options")
        for table in ("people", "users", "readers", "doors", "mobile_nfc_permissions"):
            counts[table] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return {"integrity": "ok", "foreign_keys": "ok", "record_counts": counts,
            "encrypted_credentials_verified": verified, "legacy_credentials_without_ciphertext": legacy,
            "builder_token_present_and_verified": builder_verified}


def verify_bundle(destination):
    destination = Path(destination).resolve(strict=True)
    manifest = json.loads((destination / "manifest.json").read_text())
    expected = manifest["files_sha256"]
    if set(expected) - {DATABASE, *COMPANIONS} or DATABASE not in expected:
        raise ValueError("Invalid recovery manifest files")
    for name, digest in expected.items():
        path = destination / "data" / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Recovery file verification failed")
    return verify_data(destination / "data")


def snapshot(source, destination, timeout=30):
    source = Path(source).resolve(strict=True)
    destination = Path(destination)
    if destination.is_symlink():
        raise ValueError("Recovery target must not be a symlink")
    resolved = destination.resolve()
    if resolved == source or resolved.is_relative_to(source):
        raise ValueError("Recovery target must be outside active data")
    before = companions(source)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    data = destination / "data"
    data.mkdir(mode=0o700)
    private_write(data / DATABASE, b"")
    deadline = time.monotonic() + timeout
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError("Recovery snapshot exceeded its deadline")
    with closing(readonly_database(source / DATABASE)) as live, closing(sqlite3.connect(data / DATABASE)) as target:
        live.execute("PRAGMA query_only=ON")
        live.backup(target, pages=128, progress=progress, sleep=0.05)
        target.execute("PRAGMA journal_mode=DELETE")
    after = companions(source)
    if before != after:
        raise ValueError("Recovery keys/options changed during snapshot; retry in a new directory")
    for name, value in before.items():
        if value is not None:
            private_write(data / name, value)
    report = verify_data(data)
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in data.iterdir()}
    manifest = {"format": 1, "method": "sqlite_online_backup_readonly_source",
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "files_sha256": files, "verification": report,
                "scope": "Application data only, not a Supervisor backup or a live restore"}
    # Reopen a separate reconstructed copy, still entirely offline.
    reconstructed = destination / "reopened"
    reconstructed.mkdir(mode=0o700)
    for name in files:
        private_write(reconstructed / name, (data / name).read_bytes())
    if verify_data(reconstructed) != report:
        raise ValueError("Reopened recovery copy failed verification")
    private_write(destination / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    return {"result": "passed", "destination": str(destination.resolve()),
            "reopened_copy_verified": True, "source_keys_options_unchanged": True,
            "files_copied": sorted(files), **verify_bundle(destination)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            result = verify_bundle(args.destination)
        else:
            if args.source is None:
                parser.error("--source is required when creating a snapshot")
            result = snapshot(args.source, args.destination)
    except Exception as error:
        print(json.dumps({"result": "failed", "error_class": type(error).__name__, "secrets_redacted": True}))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2))

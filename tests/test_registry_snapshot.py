import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet


SPEC = importlib.util.spec_from_file_location("registry_snapshot", Path(__file__).parents[1] / "tools/snapshot_registry.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class RegistrySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "live"
        self.source.mkdir()
        self.destination = self.root / "recovery"
        self.connection = sqlite3.connect(self.source / SNAPSHOT.DATABASE)
        self.addCleanup(self.connection.close)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA wal_autocheckpoint=0")
        self.connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)")
        for table in ("people", "users", "readers", "doors", "mobile_nfc_permissions"):
            self.connection.execute(f"CREATE TABLE {table}(id INTEGER)")
            self.connection.execute(f"INSERT INTO {table} VALUES (1)")
        self.key = Fernet.generate_key()
        (self.source / "credential_encryption.key").write_bytes(self.key)
        (self.source / "options.json").write_text('{"log_level":"info"}')
        self.secret = "synthetic-sensitive-value"
        self.hmac_key = "0a" * 32
        self.connection.execute("INSERT INTO settings VALUES ('credential_hmac_key',?)", (self.hmac_key,))
        for table in ("keypad_credentials", "shared_keypad_credentials"):
            self.connection.execute(f"CREATE TABLE {table}(reader_id TEXT, secret_hash TEXT, hash_version INTEGER, secret_ciphertext TEXT, keypad_action TEXT)")
            digest = hmac.new(bytes.fromhex(self.hmac_key), f"v2\0synthetic-reader\0{self.secret}".encode(), hashlib.sha256).hexdigest()
            self.connection.execute(f"INSERT INTO {table} VALUES (?,?,2,?,'')", ("synthetic-reader", digest, Fernet(self.key).encrypt(self.secret.encode()).decode()))
        self.connection.commit()

    def test_live_wal_snapshot_reopens_and_preserves_private_material(self):
        self.assertGreater((self.source / (SNAPSHOT.DATABASE + "-wal")).stat().st_size, 0)
        before = self.connection.total_changes
        report = SNAPSHOT.snapshot(self.source, self.destination)
        self.assertEqual(report["encrypted_credentials_verified"], 2)
        self.assertTrue(report["reopened_copy_verified"])
        self.assertEqual(self.connection.total_changes, before)
        self.assertNotIn(self.secret, json.dumps(report))
        self.assertNotIn(self.hmac_key, json.dumps(report))
        self.assertEqual(SNAPSHOT.verify_bundle(self.destination)["integrity"], "ok")
        self.connection.execute("INSERT INTO people VALUES (2)")
        self.connection.commit()
        self.assertEqual(SNAPSHOT.verify_bundle(self.destination)["record_counts"]["people"], 1)

    def test_builder_token_requires_matching_key_and_survives_reopening(self):
        key = Fernet.generate_key()
        (self.source / "esphome_connection.key").write_bytes(key)
        self.connection.execute("INSERT INTO settings VALUES ('esphome_token',?)", (Fernet(key).encrypt(b"synthetic-token").decode(),))
        self.connection.commit()
        self.assertTrue(SNAPSHOT.snapshot(self.source, self.destination)["builder_token_present_and_verified"])

    def test_committed_write_during_backup_remains_consistent(self):
        actual_reader = SNAPSHOT.readonly_database
        writes = []
        class ObservedReader:
            def __init__(inner, connection):
                inner.connection = connection
            def execute(inner, *args):
                return inner.connection.execute(*args)
            def close(inner):
                inner.connection.close()
            def backup(inner, target, **kwargs):
                original_progress = kwargs["progress"]
                def progress(status, remaining, total):
                    if remaining > 0 and not writes:
                        self.connection.execute("INSERT INTO people VALUES (2)")
                        self.connection.commit()
                        writes.append(True)
                    original_progress(status, remaining, total)
                inner.connection.backup(target, **{**kwargs, "pages": 1, "progress": progress})
        def reader(path, immutable=False):
            connection = actual_reader(path, immutable)
            return connection if immutable else ObservedReader(connection)
        with patch.object(SNAPSHOT, "readonly_database", side_effect=reader):
            report = SNAPSHOT.snapshot(self.source, self.destination)
        self.assertEqual(writes, [True])
        self.assertEqual(report["record_counts"]["people"], 2)
        self.assertEqual(report["integrity"], "ok")

    def test_private_permissions_and_failed_reopen_do_not_publish_manifest(self):
        SNAPSHOT.snapshot(self.source, self.destination)
        if os.name == 'posix':
            self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in (self.destination/'data').iterdir()))
        fresh = self.root / "failed-reopen"
        real_verify = SNAPSHOT.verify_data
        def verify(root):
            if Path(root).name == "reopened":
                raise ValueError("Synthetic reconstruction failure")
            return real_verify(root)
        with patch.object(SNAPSHOT, "verify_data", side_effect=verify), self.assertRaises(ValueError):
            SNAPSHOT.snapshot(self.source, fresh)
        self.assertFalse((fresh / "manifest.json").exists())

    def test_targets_must_be_fresh_and_outside_live_data(self):
        self.destination.mkdir()
        with self.assertRaises(FileExistsError):
            SNAPSHOT.snapshot(self.source, self.destination)
        with self.assertRaises(ValueError):
            SNAPSHOT.snapshot(self.source, self.source / "nested")

    def test_changed_companions_never_get_a_valid_manifest(self):
        original = SNAPSHOT.companions(self.source)
        with patch.object(SNAPSHOT, "companions", side_effect=[original, {**original, "options.json": b"changed"}]):
            with self.assertRaises(ValueError):
                SNAPSHOT.snapshot(self.source, self.destination)
        self.assertFalse((self.destination / "manifest.json").exists())

    def test_wrong_key_or_modified_bundle_fails_closed(self):
        SNAPSHOT.snapshot(self.source, self.destination)
        key = self.destination / "data/credential_encryption.key"
        key.write_bytes(Fernet.generate_key())
        with self.assertRaises(ValueError):
            SNAPSHOT.verify_bundle(self.destination)

    def test_missing_key_never_claims_success(self):
        (self.source / "credential_encryption.key").unlink()
        with self.assertRaises(ValueError):
            SNAPSHOT.snapshot(self.source, self.destination)
        self.assertFalse((self.destination / "manifest.json").exists())

    def test_deadline_aborts_without_claiming_a_complete_backup(self):
        with self.assertRaises(TimeoutError):
            SNAPSHOT.snapshot(self.source, self.destination, timeout=-1)
        self.assertFalse((self.destination / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()

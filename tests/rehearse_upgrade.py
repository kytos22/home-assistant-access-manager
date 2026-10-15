"""Offline upgrade/restore rehearsal using a released Registry and synthetic data.

Uses a local Git revision and temporary data. Does not start the app, connect to
Home Assistant, or accept real data paths. This is not a Supervisor backup test.
"""

import argparse
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
from types import ModuleType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "access_manager/app/main.py"
KEY_FILES = ("credential_encryption.key", "esphome_connection.key")
TABLES = (
    "people", "users", "doors", "readers", "keypad_credentials",
    "shared_keypad_credentials", "settings", "mobile_nfc_permissions",
)


def git_output(*args):
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.strip()


def load_app(source, name, data_dir):
    module = ModuleType(name)
    module.__file__ = str(APP_PATH)
    exec(compile(source, str(APP_PATH), "exec"), module.__dict__)
    module.DATA_DIR = data_dir
    module.DB_PATH = data_dir / "fingerprint_admin.db"
    module.TOKEN = ""
    return module


def snapshot_data(registry, source_dir, destination):
    """Snapshot committed WAL state plus this fixture's immutable keys."""
    destination.mkdir()
    with closing(sqlite3.connect(destination / "fingerprint_admin.db")) as target:
        registry.connection.backup(target)
    for filename in KEY_FILES:
        shutil.copy2(source_dir / filename, destination / filename)


def capture_rows(registry):
    rows = {}
    for table in TABLES:
        columns = [r[1] for r in registry.connection.execute(f'PRAGMA table_info("{table}")')]
        projection = ", ".join(f'"{column}"' for column in columns)
        values = [tuple(r) for r in registry.connection.execute(f'SELECT {projection} FROM "{table}" ORDER BY rowid')]
        rows[table] = (projection, values)
    return rows


def run_rehearsal(baseline_ref):
    commit = git_output("rev-parse", "--verify", "--end-of-options", f"{baseline_ref}^{{commit}}")
    released_source = git_output("show", f"{commit}:access_manager/app/main.py")
    candidate_source = APP_PATH.read_text(encoding="utf-8")
    passed = []

    def check(condition, label):
        if not condition:
            raise RuntimeError(f"Rehearsal failed: {label}")
        passed.append(label)

    def verify_rows(registry, expected, label):
        for table, (projection, values) in expected.items():
            actual = [tuple(r) for r in registry.connection.execute(f'SELECT {projection} FROM "{table}" ORDER BY rowid')]
            check(actual == values, f"{label}: {table}")

    with patch.object(socket.socket, "connect", side_effect=RuntimeError("Network disabled in rehearsal")), \
            patch.object(socket.socket, "connect_ex", side_effect=RuntimeError("Network disabled in rehearsal")), \
            tempfile.TemporaryDirectory(prefix="access-manager-upgrade-") as temporary, ExitStack() as cleanup:
        workspace = Path(temporary)
        released = load_app(released_source, "released_access_manager", workspace / "released")
        candidate = load_app(candidate_source, "candidate_access_manager", workspace / "candidate")
        original = released.Registry(released.DB_PATH)
        cleanup.callback(original.connection.close)
        original.connection.execute("PRAGMA wal_autocheckpoint=0")
        original.create_door("test-door", "Synthetic door", "lock.synthetic_only", "open")
        original.create_reader("test-finger", "Synthetic reader", "fingerprint", "test-door", {})
        original.create_reader("test-keypad", "Synthetic keypad", "keypad", "test-door", {})

        identities = {}
        ha_people = []
        for label in ("granted", "revoked", "suspended", "unlinked"):
            person_id = original.create_person(f"Synthetic {label}")
            identities[label] = person_id
            entity_id = f"person.synthetic_{label}"
            original.link_ha_person(person_id, entity_id)
            original.set_mobile_nfc_permission(person_id, "test-door", label != "revoked")
            if label == "suspended":
                entity_id = "person.synthetic_suspended_replacement"
                original.link_ha_person(person_id, entity_id)
            if label == "unlinked":
                original.unlink_ha_person(person_id)
            ha_people.append({
                "entity_id": entity_id, "ha_person_id": f"stable-{label}",
                "name": f"Synthetic {label}",
            })

        original.put_user(7, "Synthetic granted", "left_index", "active", "test-finger")
        personal_value, shared_value = "synthetic-personal-code", "synthetic-shared-code"
        personal = original.add_keypad_credential(identities["granted"], "test-keypad", personal_value)
        shared = original.add_shared_keypad_credential("Synthetic shared", "test-keypad", shared_value)
        original.save_esphome_connection("https://builder.example.test", "synthetic-builder-token", {}, 0)
        original.set_log_retention_days(90)
        original.set_setting("upgrade_rehearsal", "before-snapshot")
        before = capture_rows(original)
        key_digests = {name: hashlib.sha256((released.DATA_DIR / name).read_bytes()).hexdigest() for name in KEY_FILES}
        wal = Path(str(released.DB_PATH) + "-wal")
        check(wal.is_file() and wal.stat().st_size > 0, "released fixture has a populated WAL")
        snapshot = workspace / "snapshot"
        snapshot_data(original, released.DATA_DIR, snapshot)
        original.set_setting("upgrade_rehearsal", "after-snapshot")

        shutil.copytree(snapshot, candidate.DATA_DIR)
        upgraded = candidate.Registry(candidate.DB_PATH)
        cleanup.callback(upgraded.connection.close)
        check(upgraded.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "migrated SQLite integrity")
        check(not upgraded.connection.execute("PRAGMA foreign_key_check").fetchall(), "migrated foreign-key integrity")
        verify_rows(upgraded, before, "existing data preserved")
        check(all(upgraded.person(i)["ha_person_id"] is None for i in identities.values()), "stable IDs start unresolved")
        check(upgraded.reveal_keypad_credential(personal) == personal_value, "personal credential decrypts after upgrade")
        check(upgraded.reveal_shared_keypad_credential(shared) == shared_value, "shared credential decrypts after upgrade")
        check(upgraded.esphome_connection(include_token=True)["token"] == "synthetic-builder-token", "Device Builder credential decrypts after upgrade")
        check(all(hashlib.sha256((candidate.DATA_DIR / name).read_bytes()).hexdigest() == digest for name, digest in key_digests.items()), "encryption keys unchanged")

        upgraded.reconcile_ha_people(ha_people, True)
        ha_people[0]["entity_id"] = "person.synthetic_renamed"
        upgraded.reconcile_ha_people(ha_people, True)
        check(upgraded.person(identities["granted"])["ha_person_entity_id"] == "person.synthetic_renamed", "verified Person rename is retained")
        check(upgraded.mobile_nfc_allowed(identities["granted"], "test-door"), "verified rename preserves the existing NFC grant")
        check(not upgraded.mobile_nfc_allowed(identities["revoked"], "test-door"), "revoked NFC remains revoked")
        check(not upgraded.mobile_nfc_allowed(identities["suspended"], "test-door"), "suspended NFC remains suspended")
        check(upgraded.person(identities["unlinked"])["ha_person_entity_id"] is None, "unlink opt-out is preserved")
        upgraded.connection.close()
        restarted = candidate.Registry(candidate.DB_PATH)
        cleanup.callback(restarted.connection.close)
        check(restarted.mobile_nfc_allowed(identities["granted"], "test-door"), "migrated binding survives registry restart")
        check(restarted.reveal_keypad_credential(personal) == personal_value, "credential remains decryptable after restart")

        # Restore the pre-upgrade snapshot in another synthetic directory.
        # Never open a migrated live database with old code or overwrite it.
        released.DATA_DIR = workspace / "restored"
        released.DB_PATH = released.DATA_DIR / "fingerprint_admin.db"
        shutil.copytree(snapshot, released.DATA_DIR)
        restored = released.Registry(released.DB_PATH)
        cleanup.callback(restored.connection.close)
        verify_rows(restored, before, "released snapshot restored")
        check(restored.setting("upgrade_rehearsal") == "before-snapshot", "restore excludes post-snapshot writes")
        check(restored.reveal_keypad_credential(personal) == personal_value, "restored personal credential decrypts")
        check(restored.reveal_shared_keypad_credential(shared) == shared_value, "restored shared credential decrypts")
        check(restored.esphome_connection(include_token=True)["token"] == "synthetic-builder-token", "restored Device Builder credential decrypts")
        check(restored.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "restored SQLite integrity")

    return {
        "result": "passed", "baseline_ref": baseline_ref, "baseline_commit": commit,
        "candidate_sha256": hashlib.sha256(candidate_source.encode("utf-8")).hexdigest(),
        "checks_passed": len(passed), "checks": passed,
        "scope": "Synthetic SQLite/WAL and encryption-key snapshot only; no live HA, Supervisor backup, Ingress or OTA tested",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="v0.15.3", help="Locally available, trusted release tag/commit; never fetched automatically")
    args = parser.parse_args()
    print(json.dumps(run_rehearsal(args.baseline_ref), indent=2))

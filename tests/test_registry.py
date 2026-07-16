import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "access_manager" / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("access_manager", MODULE_PATH)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class RegistryTests(unittest.TestCase):
    def test_clean_install_starts_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "clean.db")
            self.assertEqual(registry.users(), [])
            self.assertEqual(registry.people(), [])
            self.assertEqual(registry.readers(), [])
            self.assertEqual(registry.doors(), [])
            self.assertEqual(registry.events(), [])
            self.assertEqual(registry.log_retention_days(), 30)
            registry.connection.close()

    def test_legacy_fingerprint_ids_migrate_to_original_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE users(
                    slot INTEGER PRIMARY KEY CHECK(slot BETWEEN 1 AND 240),
                    name TEXT NOT NULL,
                    finger TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    enrolled_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    person_id INTEGER
                );
                CREATE TABLE events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    slot INTEGER,
                    confidence INTEGER,
                    detail TEXT
                );
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE deletion_queue(
                    slot INTEGER PRIMARY KEY CHECK(slot BETWEEN 1 AND 50),
                    state TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    baseline_count INTEGER,
                    expected_count INTEGER,
                    last_error TEXT,
                    requested_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO users VALUES(
                    7, 'Example Person', 'right_index', 'active',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', NULL
                );
                """
            )
            connection.commit()
            connection.close()

            registry = APP.Registry(path)
            migrated = registry.user(7, "display1")
            self.assertIsNotNone(migrated)
            self.assertEqual(migrated["name"], "Example Person")
            self.assertEqual(registry.person(migrated["person_id"])["name"], "Example Person")
            registry.connection.close()

    def test_keypad_secret_is_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "credentials.db")
            person_id = registry.create_person("Example Person")
            registry.create_reader(
                "example_keypad",
                "Example Keypad",
                "keypad",
                "",
                {
                    "transaction_entity": "sensor.example_transaction",
                    "code_entity": "sensor.example_code",
                    "action_entity": "sensor.example_action",
                },
            )
            raw_secret = "example-secret-that-must-not-appear"
            registry.add_keypad_credential(
                person_id, "example_keypad", raw_secret, "disarm", "open"
            )
            self.assertNotIn(raw_secret, str(registry.people()))
            self.assertIsNotNone(
                registry.find_keypad_credential(
                    "example_keypad", raw_secret, "disarm"
                )
            )
            registry.connection.close()


if __name__ == "__main__":
    unittest.main()

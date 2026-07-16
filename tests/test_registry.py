import importlib.util
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "access_manager" / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("access_manager", MODULE_PATH)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class RegistryTests(unittest.TestCase):
    def test_manifest_version_has_matching_changelog_entry(self):
        root = Path(__file__).parents[1]
        manifest = (root / "access_manager" / "config.yaml").read_text(
            encoding="utf-8"
        )
        changelog = (root / "access_manager" / "CHANGELOG.md").read_text(
            encoding="utf-8"
        )
        match = re.search(r'^version:\s*"([0-9]+\.[0-9]+\.[0-9]+)"$', manifest, re.M)
        self.assertIsNotNone(match)
        self.assertIn(f"## {match.group(1)}", changelog)

    def test_clean_install_starts_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "clean.db")
            self.assertEqual(registry.users(), [])
            self.assertEqual(registry.people(), [])
            self.assertEqual(registry.readers(), [])
            self.assertEqual(registry.doors(), [])
            self.assertEqual(registry.managed_automations(), [])
            self.assertEqual(registry.events(), [])
            self.assertEqual(registry.log_retention_days(), 30)
            registry.connection.close()


class DoorActionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        APP.DATA_DIR = Path(self.directory.name)
        self.registry = APP.Registry(Path(self.directory.name) / "actions.db")
        self.person_id = self.registry.create_person("Example Person")
        self.registry.create_door(
            "front_door", "Front door", "lock.front_door", "open"
        )
        self.registry.create_reader(
            "front_reader", "Front reader", "fingerprint", "front_door", {}
        )
        self.ha = APP.HomeAssistant(self.registry)
        self.ha.states = {
            "lock.front_door": {
                "entity_id": "lock.front_door",
                "state": "locked",
                "attributes": {"supported_features": APP.LOCK_OPEN_FEATURE},
            }
        }
        self.service_calls = []
        self.events = []

        async def call_service(domain, service, payload):
            self.service_calls.append((domain, service, payload))

        async def fire_event(event_type, payload):
            self.events.append((event_type, payload.copy()))

        self.ha.call_service = call_service
        self.ha.fire_event = fire_event

    async def asyncTearDown(self):
        self.registry.connection.close()
        self.directory.cleanup()

    async def test_authorized_fingerprint_executes_door_default(self):
        person = self.registry.person(self.person_id)
        payload = await self.ha.emit_credential_event(
            "front_reader", person, "fingerprint", 7, "default", "123"
        )
        self.assertEqual(
            self.service_calls,
            [("lock", "open", {"entity_id": "lock.front_door"})],
        )
        self.assertTrue(payload["action_executed"])
        self.assertEqual(payload["requested_action"], "default")
        self.assertEqual(payload["action"], "open")
        self.assertEqual(self.events[0][0], "access_manager_credential")

    async def test_keypad_can_override_default_with_lock(self):
        person = self.registry.person(self.person_id)
        payload = await self.ha.emit_credential_event(
            "front_reader", person, "keypad", 3, "lock", "456"
        )
        self.assertEqual(self.service_calls[0][1], "lock")
        self.assertEqual(payload["action"], "lock")
        self.assertTrue(payload["action_executed"])

    async def test_denied_or_unsupported_action_never_controls_door(self):
        denied = await self.ha.emit_credential_event(
            "front_reader", None, "keypad", "unknown", "lock", "789",
            authorized=False,
        )
        self.assertFalse(denied["action_executed"])
        self.assertEqual(self.service_calls, [])

        person = self.registry.person(self.person_id)
        invalid = await self.ha.emit_credential_event(
            "front_reader", person, "fingerprint", 7, "invalid", "790"
        )
        self.assertFalse(invalid["action_executed"])
        self.assertIn("not supported", invalid["action_error"])
        self.assertEqual(self.service_calls, [])

    async def test_lock_open_is_only_offered_when_supported(self):
        self.assertEqual(
            self.ha.door_actions("lock.front_door"), ["open", "unlock", "lock"]
        )
        self.ha.states["lock.front_door"]["attributes"]["supported_features"] = 0
        self.assertEqual(
            self.ha.door_actions("lock.front_door"), ["unlock", "lock"]
        )

    async def test_fingerprint_event_action_is_explicit_and_safe(self):
        self.assertEqual(
            self.ha.parse_event("matched|1|7|90|lock")["action"], "lock"
        )
        self.assertEqual(
            self.ha.parse_event("matched|2|7|90")["action"], "default"
        )
        self.assertEqual(
            self.ha.parse_event("matched|3|7|90|unsupported")["action"], "invalid"
        )
        self.assertEqual(
            self.ha.parse_event("local_action|4|lock")["action"], "lock"
        )
        self.assertEqual(
            self.ha.parse_event("local_action|5|open")["action"], "open"
        )

    async def test_unauthenticated_local_control_can_only_lock(self):
        door = self.registry.doors()[0]
        reader = self.registry.reader("front_reader")
        locked = await self.ha.emit_door_action_event(
            door, "lock", "display", "front_reader:1",
            reader=reader, local_only=True,
        )
        self.assertTrue(locked["action_executed"])
        self.assertEqual(self.service_calls[0][1], "lock")
        self.assertEqual(self.events[-1][0], "access_manager_door_action")

        self.service_calls.clear()
        rejected = await self.ha.emit_door_action_event(
            door, "open", "display", "front_reader:2",
            reader=reader, local_only=True,
        )
        self.assertFalse(rejected["action_executed"])
        self.assertIn("only lock", rejected["action_error"])
        self.assertEqual(self.service_calls, [])

    async def test_local_reader_sequence_executes_only_once(self):
        raw = "local_action|42|lock"
        await self.ha.process_access_event(raw, "front_reader")
        await self.ha.process_access_event(raw, "front_reader")
        self.assertEqual(
            self.service_calls,
            [("lock", "lock", {"entity_id": "lock.front_door"})],
        )
        self.assertEqual(
            self.registry.setting("last_access_event:front_reader"), raw
        )

    async def test_keypad_identity_comes_from_code_and_current_map_controls_action(self):
        self.registry.create_reader(
            "front_keypad", "Front keypad", "keypad", "front_door", {
                "transaction_entity": "sensor.keypad_transaction",
                "code_entity": "sensor.keypad_code",
                "action_entity": "sensor.keypad_action",
                "action_map": {"disarm": "lock"},
            }
        )
        self.registry.add_keypad_credential(
            self.person_id, "front_keypad", "1234", "disarm", "open"
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.capture_sessions = {}
        await admin.process_keypad_event(
            self.registry.reader("front_keypad"), "1", "1234", "disarm"
        )
        self.assertEqual(self.service_calls[0][1], "lock")
        payload = self.events[-1][1]
        self.assertEqual(payload["person_name"], "Example Person")
        self.assertEqual(payload["action"], "lock")

        self.service_calls.clear()
        await admin.process_keypad_event(
            self.registry.reader("front_keypad"), "2", "1234", "unknown_button"
        )
        self.assertEqual(self.service_calls, [])

    async def test_keypad_transaction_is_not_consumed_until_code_and_action_arrive(self):
        self.registry.create_reader(
            "packet_keypad", "Packet keypad", "keypad", "front_door", {
                "transaction_entity": "sensor.packet_transaction",
                "code_entity": "sensor.packet_code",
                "action_entity": "sensor.packet_action",
                "action_map": {"disarm": "open"},
            }
        )
        self.ha.states.update({
            "sensor.packet_transaction": {"state": "17"},
            "sensor.packet_code": {"state": ""},
            "sensor.packet_action": {"state": "disarm"},
        })
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.capture_sessions = {}
        admin.keypad_learning_sessions = {}
        admin.last_keypad_actions = {}
        processed = []

        async def process(reader, transaction, code, action):
            processed.append((reader["id"], transaction, code, action))

        admin.process_keypad_event = process
        self.assertFalse(await admin.process_keypad_packet("packet_keypad"))
        self.assertIsNone(self.registry.setting("reader_transaction:packet_keypad"))

        self.ha.states["sensor.packet_code"]["state"] = "1234"
        self.assertTrue(await admin.process_keypad_packet("packet_keypad"))
        self.assertEqual(
            processed, [("packet_keypad", "17", "1234", "disarm")]
        )
        self.assertEqual(
            self.registry.setting("reader_transaction:packet_keypad"), "17"
        )
        self.assertFalse(await admin.process_keypad_packet("packet_keypad"))
        self.assertEqual(len(processed), 1)

    async def test_auto_lock_config_is_native_and_ownership_marked(self):
        door = self.registry.doors()[0]
        config_id = APP.FingerprintAdmin.auto_lock_automation_id(door["id"])
        config = APP.FingerprintAdmin.build_auto_lock_config(
            door, config_id, 10
        )
        self.assertEqual(config["id"], "access_manager_auto_lock_front_door")
        self.assertEqual(config["triggers"][0]["trigger"], "state")
        self.assertEqual(config["triggers"][0]["to"], "unlocked")
        self.assertEqual(config["actions"][0]["action"], "lock.lock")
        self.assertTrue(
            APP.FingerprintAdmin.owned_automation_config(config, config_id)
        )
        config["description"] = "Changed outside Access Manager"
        self.assertFalse(
            APP.FingerprintAdmin.owned_automation_config(config, config_id)
        )

    async def test_delete_refuses_automation_if_ownership_marker_changed(self):
        config_id = "access_manager_auto_lock_front_door"
        self.registry.upsert_managed_automation(
            config_id, "auto_lock", "front_door", config_id, True,
            {"delay_minutes": 10},
        )
        deleted = []

        async def automation_config(_config_id):
            return {
                "id": config_id,
                "alias": "Unrelated automation",
                "description": "Edited outside Access Manager",
            }

        async def delete_automation_config(config_id_to_delete):
            deleted.append(config_id_to_delete)

        self.ha.automation_config = automation_config
        self.ha.delete_automation_config = delete_automation_config
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha

        class Request:
            headers = {"X-Fingerprint-Admin": "1"}
            match_info = {"automation_id": config_id}

        with self.assertRaises(APP.web.HTTPConflict):
            await admin.delete_managed_automation(Request())
        self.assertEqual(deleted, [])
        self.assertIsNotNone(self.registry.managed_automation(config_id))

    async def test_restart_primes_stale_access_event_without_executing_it(self):
        self.registry.update_reader(
            "front_reader", "Front reader", "front_door", config={
                "access_event_entity": "sensor.front_access_event"
            }
        )
        raw = "matched|1|7|90|default"
        self.ha.states["sensor.front_access_event"] = {"state": raw, "attributes": {}}

        async def must_not_execute(*_args, **_kwargs):
            raise AssertionError("A stale event was executed during replay")

        self.ha.process_access_event = must_not_execute
        await self.ha.replay_current_events()
        self.assertEqual(
            self.registry.setting("last_access_event:front_reader"), raw
        )


class RegistryMigrationTests(unittest.TestCase):
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
            registry.add_keypad_credential(
                person_id, "example_keypad", raw_secret, "arm_all_zones", "lock"
            )
            self.assertNotIn(raw_secret, str(registry.people()))
            open_credential = registry.find_keypad_credential(
                "example_keypad", raw_secret, "disarm"
            )
            lock_credential = registry.find_keypad_credential(
                "example_keypad", raw_secret, "arm_all_zones"
            )
            self.assertEqual(open_credential["normalized_action"], "open")
            self.assertEqual(lock_credential["normalized_action"], "lock")
            registry.connection.close()


if __name__ == "__main__":
    unittest.main()

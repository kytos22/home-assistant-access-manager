import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).parents[1] / "access_manager" / "app" / "main.py"
)
SPEC = importlib.util.spec_from_file_location(
    "access_manager_lifecycle", MODULE_PATH
)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class LifecycleRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        APP.DATA_DIR = Path(self.tmp.name)
        self.path = Path(self.tmp.name) / "lifecycle.db"
        self.registry = APP.Registry(self.path)

    def tearDown(self):
        self.registry.connection.close()
        self.tmp.cleanup()

    def access_model(self):
        self.registry.create_door(
            "front", "Front", "lock.front", "open"
        )
        self.registry.create_reader(
            "finger", "Finger", "fingerprint", "front", {}
        )
        self.registry.create_reader(
            "keypad", "Keypad", "keypad", "front", {}
        )

    def test_unlink_opt_out_and_distinct_link_states(self):
        person_id = self.registry.create_person("Example Person")
        people = [{
            "entity_id": "person.example",
            "name": "Example Person",
        }]
        self.registry.reconcile_ha_people(people, True)
        self.assertEqual(
            self.registry.person(person_id)["ha_link_status"], "linked"
        )
        self.registry.unlink_ha_person(person_id)
        self.registry.reconcile_ha_people(people, True)
        person = self.registry.person(person_id)
        self.assertIsNone(person["ha_person_entity_id"])
        self.assertEqual(person["ha_link_status"], "unlinked")
        self.assertEqual(person["ha_auto_link_disabled"], 1)
        self.registry.link_ha_person(person_id, "person.example")
        self.registry.reconcile_ha_people([], True)
        self.assertEqual(
            self.registry.person(person_id)["ha_link_status"], "missing"
        )
        self.registry.reconcile_ha_people([], False)
        self.assertEqual(
            self.registry.person(person_id)["ha_link_status"], "unknown"
        )

    def test_relink_suspends_nfc_until_confirmed(self):
        self.registry.create_door(
            "front", "Front", "lock.front", "open"
        )
        person_id = self.registry.create_person("Example")
        self.registry.link_ha_person(person_id, "person.first")
        self.registry.set_mobile_nfc_permission(
            person_id, "front", True
        )
        self.assertTrue(
            self.registry.mobile_nfc_allowed(person_id, "front")
        )
        result = self.registry.link_ha_person(
            person_id, "person.second"
        )
        self.assertEqual(result["suspended_permissions"], 1)
        self.assertFalse(
            self.registry.mobile_nfc_allowed(person_id, "front")
        )
        record = self.registry.mobile_nfc_permissions(
            include_inactive=True
        )[0]
        self.assertTrue(record["requires_confirmation"])
        self.assertEqual(
            record["ha_person_entity_id"], "person.first"
        )
        self.registry.set_mobile_nfc_permission(
            person_id, "front", True
        )
        self.assertTrue(
            self.registry.mobile_nfc_allowed(person_id, "front")
        )

    def test_deletion_revokes_then_archives_after_confirmation(self):
        self.access_model()
        person_id = self.registry.create_person("Example")
        self.registry.link_ha_person(
            person_id, "person.example"
        )
        self.registry.put_user(
            77, "Example", "right_index", "active", "finger"
        )
        self.registry.put_user(
            78, "Example", "left_index", "active", "finger"
        )
        self.registry.add_keypad_credential(
            person_id, "keypad", "0123"
        )
        self.registry.set_mobile_nfc_permission(
            person_id, "front", True
        )
        preview = self.registry.person_deletion_preview(person_id)
        self.assertEqual(
            preview["counts"],
            {
                "fingerprints": 2,
                "keypad_credentials": 1,
                "mobile_nfc_permissions": 1,
            },
        )
        result = self.registry.begin_person_deletion(person_id)
        self.assertFalse(result["archived"])
        self.assertEqual(
            self.registry.person(person_id)["status"],
            "deletion_pending",
        )
        self.assertEqual(
            self.registry.user(77, "finger")["status"], "deleting"
        )
        self.assertIsNotNone(
            self.registry.deletion(77, "finger")
        )
        self.assertIsNotNone(
            self.registry.deletion(78, "finger")
        )
        self.assertFalse(
            self.registry.person_access_allowed(person_id)
        )
        self.assertFalse(
            self.registry.mobile_nfc_allowed(person_id, "front")
        )
        deleted = self.registry.complete_delete(77, "finger")
        self.assertFalse(deleted["person_archived"])
        partial = self.registry.person(person_id)
        self.assertEqual(partial["status"], "deletion_pending")
        self.assertEqual(partial["deletion_completed"], 1)
        deleted = self.registry.complete_delete(78, "finger")
        self.assertTrue(deleted["person_archived"])
        archived = self.registry.person(person_id)
        self.assertEqual(archived["status"], "archived")
        self.assertEqual(archived["deletion_completed"], 2)

    def test_pending_deletion_recovers_after_restart(self):
        self.access_model()
        person_id = self.registry.create_person("Restart")
        self.registry.put_user(
            9, "Restart", "left_index", "active", "finger"
        )
        self.registry.begin_person_deletion(person_id)
        self.registry.connection.execute(
            """
            UPDATE deletion_queue SET state = 'sent'
            WHERE reader_id = 'finger' AND slot = 9
            """
        )
        self.registry.connection.commit()
        self.registry.connection.close()
        self.registry = APP.Registry(self.path)
        self.assertEqual(
            self.registry.person(person_id)["status"],
            "deletion_pending",
        )
        self.assertEqual(
            self.registry.deletion(9, "finger")["state"], "queued"
        )

    def test_legacy_schema_migrates_links_permissions_and_slot_range(self):
        self.registry.connection.close()
        legacy = sqlite3.connect(self.path)
        legacy.executescript(
            """
            DROP TABLE people;
            DROP TABLE mobile_nfc_permissions;
            DROP TABLE deletion_queue;
            CREATE TABLE people (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL UNIQUE,
                ha_person_entity_id TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE mobile_nfc_permissions (
                person_id INTEGER NOT NULL,
                door_id TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(person_id, door_id)
            );
            CREATE TABLE deletion_queue (
                reader_id TEXT NOT NULL DEFAULT 'display1',
                slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 50),
                state TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                baseline_count INTEGER,
                expected_count INTEGER,
                last_error TEXT,
                requested_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(reader_id, slot)
            );
            INSERT INTO people(
                id, name, normalized_name, ha_person_entity_id,
                status, created_at, updated_at
            ) VALUES (
                1, 'Legacy', 'legacy', 'person.legacy',
                'active', '2026-01-01', '2026-01-01'
            );
            INSERT INTO mobile_nfc_permissions(
                person_id, door_id, enabled, created_at, updated_at
            ) VALUES (
                1, 'front', 1, '2026-01-01', '2026-01-01'
            );
            """
        )
        legacy.commit()
        legacy.close()
        self.registry = APP.Registry(self.path)
        person = self.registry.person(1)
        self.assertEqual(person["ha_link_status"], "unknown")
        self.assertEqual(person["deletion_total"], 0)
        permission = self.registry.mobile_nfc_permissions(
            include_inactive=True
        )[0]
        self.assertEqual(
            permission["ha_person_entity_id"], "person.legacy"
        )
        self.registry.connection.execute(
            """
            INSERT INTO deletion_queue(
                reader_id, slot, requested_at, updated_at
            ) VALUES ('finger', 77, '2026-01-01', '2026-01-01')
            """
        )
        self.registry.connection.commit()
        self.assertIsNotNone(self.registry.deletion(77, "finger"))

    def test_lifecycle_routes_exist(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = APP.HomeAssistant(self.registry)
        routes = {
            (route.method, route.resource.canonical)
            for route in admin.application().router.routes()
        }
        self.assertIn(
            ("DELETE", "/api/people/{person_id}/ha-person"), routes
        )
        self.assertIn(
            ("GET", "/api/people/{person_id}/deletion-preview"),
            routes,
        )
        self.assertIn(
            ("DELETE", "/api/people/{person_id}"), routes
        )


class FreshnessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        APP.DATA_DIR = Path(self.tmp.name)
        self.registry = APP.Registry(
            Path(self.tmp.name) / "fresh.db"
        )
        self.person_id = self.registry.create_person("Example")
        self.registry.link_ha_person(
            self.person_id, "person.example"
        )
        self.ha = APP.HomeAssistant(self.registry)

    async def asyncTearDown(self):
        self.registry.connection.close()
        self.tmp.cleanup()

    async def test_missing_and_outage_are_distinct(self):
        async def present(_command):
            return {
                "storage": [{
                    "id": "example", "name": "Example"
                }]
            }

        self.ha.websocket_command = present
        self.assertTrue(
            await self.ha.refresh_people_storage_safely()
        )
        self.assertEqual(
            self.registry.person(self.person_id)["ha_link_status"],
            "linked",
        )

        async def missing(_command):
            return {"storage": []}

        self.ha.websocket_command = missing
        self.assertTrue(
            await self.ha.refresh_people_storage_safely()
        )
        self.assertEqual(
            self.registry.person(self.person_id)["ha_link_status"],
            "missing",
        )

        async def outage(_command):
            raise RuntimeError("offline")

        self.ha.websocket_command = outage
        self.assertFalse(
            await self.ha.refresh_people_storage_safely()
        )
        self.assertEqual(
            self.registry.person(self.person_id)["ha_link_status"],
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()

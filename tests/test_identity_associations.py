import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "access_manager_associations", Path(__file__).parents[1] / "access_manager/app/main.py"
)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


def person_state(stable_id):
    return {"state": "home", "attributes": {"id": stable_id, "friendly_name": "Alice"}}


class PersonAssociationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(APP, "DATA_DIR", Path(self.tmp.name))
        self.data_patch.start()
        self.db_path = Path(self.tmp.name) / "identities.db"
        self.registry = APP.Registry(self.db_path)
        self.person_id = self.registry.create_person("Alice")
        self.registry.create_door("front", "Front", "lock.front", "open")
        self.ha = APP.HomeAssistant(self.registry)
        self.ha.states = {"person.alice": person_state("immutable-person-a")}
        self.ha.people_storage = [{
            "id": "immutable-person-a", "name": "Alice", "user_id": "user-a",
        }]
        self.ha.people_api_ready = True
        self.ha.people_storage_refreshed_at = asyncio.get_running_loop().time()

    async def asyncTearDown(self):
        self.registry.connection.close()
        self.data_patch.stop()
        self.tmp.cleanup()

    def grant(self, stable_id="immutable-person-a"):
        self.registry.link_ha_person(self.person_id, "person.alice", stable_id)
        self.registry.set_mobile_nfc_permission(self.person_id, "front", True)

    def rename(self, entity_id="person.renamed"):
        self.ha.update_cached_state("person.alice", None)
        self.ha.update_cached_state(entity_id, person_state("immutable-person-a"))

    def test_storage_maps_real_entity_ids_not_names_or_slugs(self):
        self.ha.states = {"person.custom_alias": person_state("immutable-person-a")}
        people = self.ha.storage_people()
        self.assertEqual(people[0]["entity_id"], "person.custom_alias")
        self.assertEqual(people[0]["ha_person_id"], "immutable-person-a")
        self.assertEqual(self.ha.person_storage_id("person.custom_alias"), "immutable-person-a")

    def test_unresolved_or_ambiguous_ids_are_not_guessed(self):
        self.ha.states = {"person.immutable-person-a": {"attributes": {}}}
        self.assertEqual(self.ha.storage_people(), [])
        self.assertEqual(APP.Registry.normalized_ha_people([{"id": "alice"}]), [])
        self.ha.states = {
            "person.first": person_state("immutable-person-a"),
            "person.second": person_state("immutable-person-a"),
        }
        self.assertEqual(self.ha.storage_people(), [])
        self.assertIsNone(self.ha.person_entity_id("immutable-person-a"))

    async def test_legacy_link_learns_stable_id_and_survives_restart_and_rename(self):
        self.grant(stable_id=None)
        self.assertTrue(await self.ha.ensure_people_storage_fresh())
        self.assertEqual(self.registry.person(self.person_id)["ha_person_id"], "immutable-person-a")
        self.registry.connection.close()
        self.registry = APP.Registry(self.db_path)
        self.ha.registry = self.registry
        self.rename()
        person = await self.ha.access_person_for_user_id("user-a")
        self.assertEqual(person["id"], self.person_id)
        self.assertEqual(person["ha_person_entity_id"], "person.renamed")
        self.assertTrue(self.registry.mobile_nfc_allowed(self.person_id, "front"))
        permission = self.registry.mobile_nfc_permissions()[0]
        self.assertEqual(permission["ha_person_entity_id"], "person.renamed")
        self.assertNotIn("person.alice", self.ha.states)

    def test_rename_does_not_unsuspend_a_permission(self):
        self.grant()
        with self.registry.connection:
            self.registry.connection.execute(
                "UPDATE mobile_nfc_permissions SET suspended = 1 WHERE person_id = ?", (self.person_id,)
            )
        self.rename()
        self.assertEqual(self.registry.person(self.person_id)["ha_link_status"], "linked")
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    async def test_reused_entity_id_does_not_inherit_access(self):
        self.grant()
        self.ha.people_storage = [{"id": "different-person", "name": "Alice", "user_id": "user-b"}]
        self.ha.update_cached_state("person.alice", person_state("different-person"))
        self.assertEqual(self.registry.person(self.person_id)["ha_link_status"], "missing")
        self.assertIsNone(await self.ha.access_person_for_user_id("user-b"))
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))
        result = self.registry.link_ha_person(self.person_id, "person.alice", "different-person")
        self.assertEqual(result["suspended_permissions"], 1)
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))
        self.registry.set_mobile_nfc_permission(self.person_id, "front", True)
        self.assertTrue(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    def test_same_name_cannot_recover_an_unverified_legacy_link(self):
        self.grant(stable_id=None)
        self.rename()
        self.assertEqual(self.registry.person(self.person_id)["ha_link_status"], "missing")
        self.assertIsNone(self.registry.person(self.person_id)["ha_person_id"])
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    def test_a_binding_collision_keeps_existing_permission_snapshots(self):
        self.grant()
        other = self.registry.create_person("Bob")
        self.registry.link_ha_person(other, "person.renamed", "immutable-person-b")
        self.rename()
        self.assertEqual(self.registry.person(self.person_id)["ha_link_status"], "missing")
        self.assertEqual(self.registry.person(self.person_id)["ha_person_entity_id"], "person.alice")
        self.assertEqual(self.registry.mobile_nfc_permissions()[0]["ha_person_entity_id"], "person.alice")
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    def test_one_ha_identity_cannot_be_linked_twice(self):
        self.grant()
        other = self.registry.create_person("Bob")
        with self.assertRaises(ValueError):
            self.registry.link_ha_person(other, "person.other_alias", "immutable-person-a")
        self.assertIsNone(self.registry.person(other)["ha_person_id"])
        self.assertTrue(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    def test_unlink_clears_stable_id_and_keeps_auto_link_opt_out(self):
        self.grant()
        self.registry.unlink_ha_person(self.person_id)
        self.registry.reconcile_ha_people(self.ha.storage_people(), True)
        person = self.registry.person(self.person_id)
        self.assertIsNone(person["ha_person_id"])
        self.assertIsNone(person["ha_person_entity_id"])
        self.assertEqual(person["ha_link_status"], "unlinked")
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    def test_unchanged_reconciliation_does_not_rewrite_people(self):
        self.grant()
        with self.registry.connection:
            self.registry.connection.execute("UPDATE people SET updated_at = 'unchanged' WHERE id = ?", (self.person_id,))
        changes = self.registry.connection.total_changes
        self.registry.reconcile_ha_people(self.ha.storage_people(), True)
        self.assertEqual(self.registry.person(self.person_id)["updated_at"], "unchanged")
        self.assertEqual(self.registry.connection.total_changes, changes)

    def test_archiving_clears_the_stable_identity(self):
        self.grant()
        self.registry.begin_person_deletion(self.person_id)
        person = self.registry.person(self.person_id)
        self.assertEqual(person["status"], "archived")
        self.assertIsNone(person["ha_person_id"])
        self.assertIsNone(person["ha_person_entity_id"])

    async def test_outage_does_not_use_cached_mobile_identity(self):
        self.grant()
        self.ha.people_storage_refreshed_at -= 120
        self.ha.websocket_command = AsyncMock(side_effect=RuntimeError("offline"))
        self.assertIsNone(await self.ha.access_person_for_user_id("user-a"))
        self.assertEqual(self.registry.person(self.person_id)["ha_link_status"], "unknown")
        self.assertFalse(self.registry.mobile_nfc_allowed(self.person_id, "front"))

    async def test_duplicate_storage_ids_or_users_fail_closed(self):
        self.grant()
        self.ha.people_storage.append(dict(self.ha.people_storage[0]))
        self.assertEqual(self.ha.storage_people(), [])
        self.assertIsNone(await self.ha.access_person_for_user_id("user-a"))
        self.ha.people_storage[1]["id"] = "immutable-person-b"
        self.ha.states["person.bob"] = person_state("immutable-person-b")
        self.assertIsNone(await self.ha.access_person_for_user_id("user-a"))

    async def test_create_returns_the_actual_entity_id(self):
        self.ha.states = {"person.custom_alias": person_state("immutable-person-a")}
        self.ha.refresh_states = AsyncMock()

        async def command(payload):
            if payload["type"] == "person/create":
                return {"id": "immutable-person-a"}
            return {"storage": self.ha.people_storage}

        self.ha.websocket_command = AsyncMock(side_effect=command)
        self.assertEqual(await self.ha.create_ha_person("Alice"), "person.custom_alias")

    async def test_update_uses_stable_person_id_and_preserves_ha_fields(self):
        self.ha.states = {"person.custom_alias": person_state("immutable-person-a")}
        item = {**self.ha.people_storage[0], "device_trackers": ["device_tracker.phone"], "picture": "/local/avatar.png"}
        self.ha.websocket_command = AsyncMock(return_value={"storage": [item]})
        self.ha.refresh_states = AsyncMock()
        await self.ha.update_ha_person("person.custom_alias", "Alice New")
        self.ha.websocket_command.assert_any_await({
            "type": "person/update", "person_id": "immutable-person-a", "name": "Alice New",
            "user_id": "user-a", "device_trackers": ["device_tracker.phone"], "picture": "/local/avatar.png",
        })


class ReaderAssociationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(APP, "DATA_DIR", Path(self.tmp.name))
        self.data_patch.start()
        self.registry = APP.Registry(Path(self.tmp.name) / "readers.db")
        self.ha = APP.HomeAssistant(self.registry)
        self.ha.states = {
            "select.front_reader_display_language": {
                "state": "English", "attributes": {"friendly_name": "Front reader Display language"},
            },
            "sensor.front_reader_fingerprint_reader_firmware_version": {
                "state": "0.6.3", "attributes": {},
            },
        }
        self.ha.resolve_entities()

    async def asyncTearDown(self):
        self.registry.connection.close()
        self.data_patch.stop()
        self.tmp.cleanup()

    def test_single_global_candidate_does_not_cross_readers(self):
        for config in ({}, {"device_name": "back-reader"}, {"device_name": "front"}, {"device_name": "reader"}):
            for key in ("display_language", "firmware_version"):
                with self.subTest(config=config, key=key):
                    self.assertIsNone(self.ha.optional_reader_entity(config, key))

    def test_exact_or_explicit_binding_is_supported(self):
        self.assertEqual(
            self.ha.optional_reader_entity({"firmware_profile": {"device_name": "front-reader"}}, "firmware_version"),
            "sensor.front_reader_fingerprint_reader_firmware_version",
        )
        self.assertEqual(
            self.ha.optional_reader_entity({"firmware_version_entity": "sensor.custom"}, "firmware_version"),
            "sensor.custom",
        )

    def test_ambiguous_friendly_names_are_not_auto_selected(self):
        self.ha.states["select.custom"] = self.ha.states["select.front_reader_display_language"].copy()
        self.ha.resolve_entities()
        self.assertIsNone(self.ha.optional_reader_entity({"device_name": "front-reader"}, "display_language"))

    def test_legacy_autodiscovery_is_scoped_to_its_reader(self):
        self.registry.create_reader("display1", "Old reader", "fingerprint", None, {"legacy_autodiscovery": True})
        self.assertIsNone(self.ha.reader_entity("display1", "firmware_version", required=False))
        self.ha.states["sensor.display1_fingerprint_reader_firmware_version"] = {"state": "0.6.3"}
        self.ha.resolve_entities()
        self.assertEqual(
            self.ha.reader_entity("display1", "firmware_version"),
            "sensor.display1_fingerprint_reader_firmware_version",
        )

    async def test_language_action_never_calls_a_different_reader(self):
        self.registry.create_reader("back", "Back", "fingerprint", None, {"device_name": "back-reader"})
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry, admin.ha = self.registry, self.ha
        self.ha.call_service = AsyncMock()

        class Request:
            headers = {"X-Fingerprint-Admin": "1"}
            match_info = {"reader_id": "back"}
            json = AsyncMock(return_value={"language": "es"})

        with self.assertRaises(APP.web.HTTPConflict):
            await admin.set_reader_display_language(Request())
        self.ha.call_service.assert_not_awaited()

    def firmware_admin(self):
        self.registry.create_reader("back", "Back", "fingerprint", None, {
            "device_name": "back-reader", "esphome_configuration": "back-reader.yaml",
        })
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry, admin.ha = self.registry, self.ha
        self.ha.refresh_states = AsyncMock()
        return admin

    async def test_other_reader_version_cannot_confirm_an_ota(self):
        admin = self.firmware_admin()
        self.assertIsNone(admin.reader_firmware_update_details("back")[3])
        clock = SimpleNamespace(time=Mock(side_effect=[0, 0, 2]))
        with patch.object(APP.asyncio, "get_running_loop", return_value=clock), patch.object(APP.asyncio, "sleep", new_callable=AsyncMock):
            result = await admin.verify_reader_firmware_version("back", "0.6.3", timeout_seconds=1)
        self.assertEqual(result, "device_did_not_reconnect")

    async def test_version_entity_appearing_after_refresh_is_verified(self):
        admin = self.firmware_admin()

        async def refresh():
            self.ha.states["sensor.back_reader_fingerprint_reader_firmware_version"] = {"state": "0.6.3"}
            self.ha.resolve_entities()

        self.ha.refresh_states = refresh
        self.assertEqual(await admin.verify_reader_firmware_version("back", "0.6.3", timeout_seconds=1), "completed_verified")

    async def test_refresh_failure_does_not_confirm_a_cached_version(self):
        admin = self.firmware_admin()
        self.ha.states["sensor.back_reader_fingerprint_reader_firmware_version"] = {"state": "0.6.3"}
        self.ha.resolve_entities()
        self.ha.refresh_states = AsyncMock(side_effect=RuntimeError("offline"))
        clock = SimpleNamespace(time=Mock(side_effect=[0, 0, 2]))
        with patch.object(APP.asyncio, "get_running_loop", return_value=clock), patch.object(APP.asyncio, "sleep", new_callable=AsyncMock):
            result = await admin.verify_reader_firmware_version("back", "0.6.3", timeout_seconds=1)
        self.assertNotEqual(result, "completed_verified")


if __name__ == "__main__":
    unittest.main()

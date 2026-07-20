import asyncio
import importlib.util
import inspect
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "access_manager" / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("access_manager", MODULE_PATH)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class RegistryTests(unittest.TestCase):
    def test_readme_has_one_click_home_assistant_repository_button(self):
        readme = (Path(__file__).parents[1] / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg",
            readme,
        )
        self.assertIn(
            "repository_url=https%3A%2F%2Fgithub.com%2Fkytos22%2Fhome-assistant-access-manager",
            readme,
        )

    def test_native_log_configuration_and_quiet_http_access_log(self):
        root = Path(__file__).parents[1]
        config = (root / "access_manager" / "config.yaml").read_text(
            encoding="utf-8"
        )
        main = (root / "access_manager" / "app" / "main.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("log_level: info", config)
        self.assertIn('log_level: "list(warning|info|debug)"', config)
        self.assertIn("access_log=None", main)
        self.assertNotIn(
            "refresh_states", inspect.getsource(APP.FingerprintAdmin.state)
        )

        with tempfile.TemporaryDirectory() as directory:
            options_path = Path(directory) / "options.json"
            options_path.write_text('{"log_level": "debug"}', encoding="utf-8")
            self.assertEqual(APP.configured_log_level(options_path), "debug")
            options_path.write_text('{"log_level": "invalid"}', encoding="utf-8")
            self.assertEqual(APP.configured_log_level(options_path), "info")
            options_path.write_text("[]", encoding="utf-8")
            self.assertEqual(APP.configured_log_level(options_path), "info")

    def test_installed_version_is_wired_from_the_build(self):
        root = Path(__file__).parents[1]
        dockerfile = (root / "access_manager" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        app_config = (root / "access_manager" / "config.yaml").read_text(
            encoding="utf-8"
        )
        html = (root / "access_manager" / "app" / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("ARG BUILD_VERSION", dockerfile)
        self.assertIn("ARG BUILD_ARCH", dockerfile)
        self.assertIn("ACCESS_MANAGER_VERSION=${BUILD_VERSION}", dockerfile)
        self.assertIn(
            "FROM ghcr.io/home-assistant/base-python:3.13-alpine3.24",
            dockerfile,
        )
        self.assertIn("io.hass.version", dockerfile)
        self.assertIn("pip==26.1.2", dockerfile)
        self.assertIn("aiohttp==3.14.1", dockerfile)
        self.assertIn("cryptography==49.0.0", dockerfile)
        self.assertNotIn("esphome==", dockerfile)
        self.assertNotIn("homeassistant_config", app_config)
        self.assertNotIn("esphome_dashboard_url", app_config)
        self.assertNotIn("BUILD_FROM", dockerfile)
        self.assertFalse((root / "access_manager" / "build.yaml").exists())
        self.assertIn('id="app-version"', html)
        self.assertIn('const PANEL_BUILD_VERSION = "0.14.1"', html)
        self.assertIn('cache:"no-store"', html)
        self.assertTrue(APP.APP_VERSION)

    def test_device_builder_inputs_are_strict_and_secrets_are_not_public(self):
        self.assertEqual(
            APP.validate_esphome_base_url("https://builder.example.test/"),
            "https://builder.example.test",
        )
        self.assertEqual(
            APP.validate_esphome_configuration("front-reader.yaml"),
            "front-reader.yaml",
        )
        for invalid in ("", "../front.yaml", "secrets.yaml", "front.txt"):
            with self.assertRaises(ValueError):
                APP.validate_esphome_configuration(invalid)
        for invalid in ("builder.local", "ftp://builder.local", "https://u:p@host"):
            with self.assertRaises(ValueError):
                APP.validate_esphome_base_url(invalid)

        main_source = MODULE_PATH.read_text(encoding="utf-8")
        source = main_source[
            main_source.index("class FingerprintAdmin:"):
            main_source.index('if __name__ == "__main__":')
        ]
        for command in (
            "devices/list", "devices/update_config", "firmware/install",
            "firmware/follow_job",
        ):
            self.assertIn(command, source)
        # Managed updates must read the canonical YAML and only its secret-key
        # metadata.  They must never read a secrets file or run a compiler here.
        for required in ("devices/get_config", "config/get_secrets"):
            self.assertIn(required, source)
        for forbidden in (
            "secrets.yaml", "create_subprocess_exec", "/edit?", '"/compile"',
            '"/upload"',
        ):
            self.assertNotIn(forbidden, source)

    def test_device_builder_token_is_encrypted_and_operations_survive_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            with patch.object(APP, "DATA_DIR", data_dir):
                registry = APP.Registry(data_dir / "registry.db")
                public = registry.save_esphome_connection(
                    "https://builder.example.test", "very-secret-token",
                    {"server_version": "1", "esphome_version": "2026.7.0"}, 2,
                    username="temporary-admin",
                )
                self.assertNotIn("token", public)
                self.assertNotIn("username", public)
                self.assertTrue(public["token_configured"])
                self.assertNotIn("very-secret-token", registry.setting("esphome_token"))
                self.assertNotIn("temporary-admin", registry.setting("esphome_connection"))
                self.assertEqual(
                    registry.esphome_connection(include_token=True)["token"],
                    "very-secret-token",
                )
                registry.create_firmware_operation(
                    "local-job", "front-reader.yaml", True,
                    remote_job_id="remote-compile",
                )
                registry.connection.close()

                restarted = APP.Registry(data_dir / "registry.db")
                operation = restarted.firmware_operations(pending_only=True)[0]
                self.assertEqual(operation["id"], "local-job")
                self.assertEqual(operation["remote_job_id"], "remote-compile")
                self.assertTrue(operation["install"])
                restarted.connection.close()

    def test_device_builder_device_projection_drops_unknown_and_secret_fields(self):
        devices = APP.FingerprintAdmin.public_esphome_devices({
            "configured": [{
                "configuration": "front-reader.yaml",
                "name": "front-reader",
                "friendly_name": "Front reader",
                "content": "wifi_password: secret-value",
                "secrets": {"wifi_password": "secret-value"},
            }]
        })
        self.assertEqual(devices, [{
            "configuration": "front-reader.yaml",
            "name": "front-reader",
            "friendly_name": "Front reader",
            "address": "",
            "state": "",
        }])

    def test_preview_blocks_unrelated_configuration_without_reading_yaml(self):
        class FakeClient:
            def __init__(self):
                self.commands = []

            async def command(self, command, args=None, **_kwargs):
                self.commands.append((command, args))
                if command == "devices/list":
                    return {"configured": [{
                        "configuration": "front-reader.yaml",
                        "name": "another-device",
                    }]}
                if command == "config/get_preferences":
                    return {"version_history_enabled": True}
                raise AssertionError(command)

        client = FakeClient()
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.esphome_devices_cache = []
        admin.device_builder_client = lambda: client
        preview = asyncio.run(admin.esphome_preview_data({
            "profile": "reader_only",
            "install_mode": "existing",
            "device_name": "front-reader",
            "friendly_name": "Front reader",
            "configuration": "front-reader.yaml",
            "board": "esp32dev",
            "fingerprint_tx_pin": "GPIO17",
            "fingerprint_rx_pin": "GPIO16",
        }))
        self.assertIn("belongs to", preview["collision"])
        self.assertNotIn("devices/get_config", [item[0] for item in client.commands])

    def test_install_follows_compile_and_dependent_upload(self):
        class FakeClient:
            def __init__(self):
                self.followed = []

            async def command(self, command, args=None, on_event=None, **_kwargs):
                if command == "firmware/follow_job":
                    self.followed.append(args["job_id"])
                    if on_event:
                        await on_event("output", f"finished {args['job_id']}\n")
                    return {"success": True, "code": 0}
                if command == "firmware/get_jobs":
                    return [{
                        "job_id": "remote-upload",
                        "depends_on": "remote-compile",
                    }]
                raise AssertionError(command)

        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            with patch.object(APP, "DATA_DIR", data_dir):
                registry = APP.Registry(data_dir / "registry.db")
                registry.create_firmware_operation(
                    "local-job", "front-reader.yaml", True,
                    remote_job_id="remote-compile",
                )
                client = FakeClient()
                admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
                admin.registry = registry
                admin.device_builder_client = lambda: client
                asyncio.run(admin.follow_device_builder_operation("local-job"))
                operation = registry.firmware_operation("local-job")
                self.assertEqual(client.followed, ["remote-compile", "remote-upload"])
                self.assertEqual(operation["remote_tail_job_id"], "remote-upload")
                self.assertEqual(operation["status"], "completed")
                self.assertIn("finished remote-upload", operation["logs"])
                registry.connection.close()

    def test_esphome_generator_pins_firmware_and_never_embeds_secrets(self):
        self.assertEqual(APP.READER_FIRMWARE_VERSION, "0.6.1")
        generated = APP.esphome_reader_config({
            "profile": "reader_only",
            "install_mode": "new",
            "device_name": "front-reader",
            "friendly_name": "Front reader",
            "board": "esp32-s3-devkitc-1",
            "fingerprint_tx_pin": "GPIO17",
            "fingerprint_rx_pin": "GPIO18",
        })
        self.assertIn("reader-only.yaml", generated)
        self.assertEqual(APP.READER_FIRMWARE_REF, "firmware-v0.6.1")
        self.assertIn("url: https://github.com/kytos22/home-assistant-access-manager", generated)
        self.assertIn(f"ref: {APP.READER_FIRMWARE_REF}", generated)
        self.assertIn("- esphome/reader-only.yaml", generated)
        self.assertIn('board: "esp32-s3-devkitc-1"', generated)
        self.assertIn("wifi_password", generated)
        self.assertIn("wifi_ssid_value: !secret wifi_ssid", generated)
        self.assertIn(
            "api_encryption_key_value: !secret api_encryption_key", generated
        )
        self.assertNotIn("CHANGE_ME", generated)
        self.assertIn("import this file into ESPHome Device Builder", generated)

        existing = APP.esphome_reader_config({
            "profile": "display",
            "install_mode": "existing",
            "device_name": "existing-reader",
            "friendly_name": "Existing reader",
            "configuration": "display1.yaml",
            "reader_id": "front_reader",
            "wifi_ssid_secret": "wifi_ssid2",
        })
        self.assertIn("- esphome/access-reader.yaml", existing)
        self.assertIn("keep device_name and all existing secret", existing)
        self.assertNotIn("secret-value", existing)
        self.assertIn('display_language: "English"', existing)
        self.assertIn("wifi_ssid_value: !secret wifi_ssid2", existing)
        self.assertIn("# Access Manager reader ID: front_reader", existing)
        self.assertIn("# Canonical Device Builder configuration: display1.yaml", existing)
        spanish = APP.esphome_reader_config({
            "profile": "display",
            "install_mode": "new",
            "device_name": "lector-entrada",
            "friendly_name": "Lector entrada",
            "display_language": "Español",
        })
        self.assertIn('display_language: "Español"', spanish)
        with self.assertRaisesRegex(ValueError, "display language"):
            APP.esphome_reader_config({
                "profile": "display",
                "install_mode": "new",
                "device_name": "front-reader",
                "friendly_name": "Front reader",
                "display_language": "French",
            })
        with self.assertRaisesRegex(ValueError, "secret key name"):
            APP.esphome_reader_config({
                "profile": "display",
                "install_mode": "existing",
                "device_name": "front-reader",
                "friendly_name": "Front reader",
                "wifi_ssid_secret": "wifi ssid",
            })


        with self.assertRaisesRegex(ValueError, "installation mode"):
            APP.esphome_reader_config({
                "profile": "display",
                "install_mode": "unsupported",
                "device_name": "front-reader",
                "friendly_name": "Front reader",
            })
        with self.assertRaisesRegex(ValueError, "must be different"):
            APP.esphome_reader_config({
                "profile": "reader_only",
                "device_name": "front-reader",
                "friendly_name": "Front reader",
                "fingerprint_tx_pin": "GPIO17",
                "fingerprint_rx_pin": "GPIO17",
            })

    def test_managed_firmware_ref_patch_is_exact_and_version_safe(self):
        original = (
            "# User-owned comment and substitutions stay unchanged\n"
            "substitutions:\n"
            "  wifi_ssid_value: !secret wifi_ssid2\n"
            "packages:\n"
            "  fingerprint_access_reader:\n"
            "    url: https://github.com/kytos22/home-assistant-access-manager\n"
            "    ref: firmware-v0.6.0  # managed package\n"
            "    files:\n"
            "      - esphome/access-reader.yaml\n"
            "wifi:\n"
            "  ssid: ${wifi_ssid_value}\n"
        )
        patched = APP.patch_managed_firmware_ref(
            original, "firmware-v0.6.1", "display"
        )
        self.assertEqual(
            patched["changed_lines"],
            ["-     ref: firmware-v0.6.0  # managed package", "+     ref: firmware-v0.6.1  # managed package"],
        )
        self.assertEqual(
            patched["patched_content"].replace("firmware-v0.6.1", "firmware-v0.6.0"),
            original,
        )
        self.assertEqual(APP.firmware_version_state("v0.6", "0.6.0"), "up_to_date")
        self.assertEqual(APP.firmware_version_state("0.6.2", "0.6.1"), "newer_than_supported")
        self.assertEqual(APP.firmware_version_state("unavailable", "0.6.1"), "unknown")
        with self.assertRaisesRegex(ValueError, "No managed"):
            APP.patch_managed_firmware_ref(original.replace("access-reader", "other"), "firmware-v0.6.1")

    def test_managed_firmware_operation_terminal_states_do_not_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            with patch.object(APP, "DATA_DIR", data_dir):
                registry = APP.Registry(data_dir / "registry.db")
                registry.create_firmware_operation(
                    "completed-job", "front-reader.yaml", True,
                    reader_id="front_reader", remote_job_id="remote-job",
                    target_version="0.6.1", update_kind="managed_update",
                )
                registry.update_firmware_operation(
                    "completed-job", status="completed_verified",
                    step="completed_verified",
                )
                self.assertEqual(registry.firmware_operations(pending_only=True), [])
                self.assertEqual(
                    APP.HomeAssistantIngressTransport._ingress_token(
                        {"ingress_entry": "/api/hassio_ingress/exampleToken_123"}
                    ),
                    "exampleToken_123",
                )
                with self.assertRaises(APP.DeviceBuilderError):
                    APP.HomeAssistantIngressTransport._ingress_token({})
                registry.connection.close()

    def test_local_ingress_discovers_supported_addons_without_public_url(self):
        class FakeHomeAssistant:
            def __init__(self, addons):
                self.addons = addons
                self.calls = []

            async def supervisor_api(self, method, path, data=None):
                self.calls.append((method, path, data))
                self.assertEqual(method, "GET")
                self.assertEqual(path, "/addons")
                return {"data": {"addons": self.addons}}

            def assertEqual(self, left, right):
                if left != right:
                    raise AssertionError((left, right))

        home_assistant = FakeHomeAssistant([{
            "slug": "a0d7b954_esphome",
            "name": "ESPHome Device Builder",
            "repository": "core",
            "state": "started",
            "ingress": True,
            "ingress_entry": "/api/hassio_ingress/local_ingress_token",
            "stage": "stable",
        }])
        transport = APP.HomeAssistantIngressTransport(home_assistant)
        addon = asyncio.run(transport._discover())
        self.assertEqual(addon["slug"], "a0d7b954_esphome")
        self.assertEqual(home_assistant.calls, [("GET", "/addons", None)])

        stopped = APP.HomeAssistantIngressTransport(FakeHomeAssistant([{
            "slug": "esphome_beta", "name": "ESPHome Device Builder Beta",
            "state": "stopped", "ingress": True,
        }]))
        with self.assertRaisesRegex(APP.DeviceBuilderError, "stopped"):
            asyncio.run(stopped._discover())
        self.assertEqual(stopped.status["status"], "stopped")

    def test_index_disables_document_caching(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        response = asyncio.run(admin.index(None))
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["X-Access-Manager-Version"], APP.APP_VERSION)
        self.assertNotIn("ETag", response.headers)
        self.assertNotIn("Last-Modified", response.headers)
        self.assertIn(b'http-equiv="Cache-Control"', response.body)
        self.assertIn(b"recoverPanelBuild", response.body)

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
            self.assertEqual(registry.shared_keypad_credentials(), [])
            self.assertEqual(registry.managed_automations(), [])
            self.assertEqual(registry.events(), [])
            self.assertEqual(registry.log_retention_days(), 30)
            registry.connection.close()

    def test_esphome_setup_persists_installation_defaults_and_reader_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "esphome-setup.db")
            self.assertEqual(
                registry.esphome_secret_keys()["wifi_ssid_secret"], "wifi_ssid"
            )
            saved = registry.set_esphome_secret_keys({
                "wifi_ssid_secret": "wifi_ssid2",
                "wifi_password_secret": "wifi_password",
                "api_encryption_key_secret": "api_encryption_key",
                "ota_password_secret": "ota_password",
            })
            self.assertEqual(saved["wifi_ssid_secret"], "wifi_ssid2")
            registry.create_reader(
                "front_reader", "Front reader", "fingerprint", None, {}
            )
            admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
            admin.registry = registry
            profile = admin.save_esphome_firmware_profile({
                "reader_id": "front_reader",
                "profile": "display",
                "device_name": "display1",
                "friendly_name": "Display1",
                "configuration": "display1.yaml",
                "display_language": "Español",
                **saved,
            })
            self.assertEqual(profile["reader_id"], "front_reader")
            self.assertEqual(profile["configuration"], "display1.yaml")
            self.assertEqual(profile["secret_keys"]["wifi_ssid_secret"], "wifi_ssid2")
            registry.connection.close()

            restarted = APP.Registry(Path(directory) / "esphome-setup.db")
            self.assertEqual(
                restarted.esphome_secret_keys()["wifi_ssid_secret"], "wifi_ssid2"
            )
            stored = restarted.reader("front_reader")["config"]["firmware_profile"]
            self.assertEqual(stored["device_name"], "display1")
            self.assertEqual(stored["display_language"], "Español")
            restarted.connection.close()

    def test_shared_keypad_credentials_are_encrypted_private_and_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "shared.db")
            person_id = registry.create_person("Example Person")
            registry.create_reader(
                "front_keypad", "Front keypad", "keypad", None, {}
            )
            credential_id = registry.add_shared_keypad_credential(
                "Cleaner", "front_keypad", "0123"
            )

            row = registry.connection.execute(
                "SELECT * FROM shared_keypad_credentials WHERE id = ?",
                (credential_id,),
            ).fetchone()
            self.assertNotIn("0123", row["secret_ciphertext"])
            self.assertNotEqual(row["secret_hash"], "0123")
            public = registry.shared_keypad_credentials()[0]
            self.assertEqual(public["label"], "Cleaner")
            self.assertIsNone(public["display_value"])
            self.assertNotIn("secret_hash", public)
            self.assertNotIn("secret_ciphertext", public)
            self.assertEqual(
                registry.reveal_shared_keypad_credential(credential_id), "0123"
            )

            registry.set_privacy_mode(False)
            self.assertEqual(
                registry.shared_keypad_credentials()[0]["display_value"], "0123"
            )
            with self.assertRaisesRegex(ValueError, "already linked"):
                registry.add_keypad_credential(
                    person_id, "front_keypad", "0123"
                )
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

    async def test_mobile_nfc_requires_linked_person_and_explicit_door_permission(self):
        self.registry.link_ha_person(self.person_id, "person.example_person")
        self.registry.save_mobile_nfc_tag(
            "door-tag", "Front door tag", "front_door", True
        )
        self.ha.people_storage = [{
            "id": "example_person", "user_id": "ha-user-1"
        }]
        self.ha.people_storage_refreshed_at = asyncio.get_running_loop().time()
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.recent_mobile_tag_scans = {}
        denied_event = {
            "data": {"tag_id": "door-tag", "device_id": "phone-device"},
            "context": {"id": "scan-1", "user_id": "ha-user-1"},
        }
        await admin.handle_mobile_tag_scan(denied_event)
        self.assertEqual(self.service_calls, [])
        self.assertFalse(self.events[-1][1]["authorized"])
        self.assertEqual(self.events[-1][1]["credential_type"], "mobile_nfc")

        await admin.handle_mobile_tag_scan({
            "data": {"tag_id": "door-tag", "device_id": "phone-device"},
            "context": {"id": "scan-unknown", "user_id": "unknown-user"},
        })
        self.assertIsNone(self.events[-1][1]["person_id"])
        self.assertEqual(self.events[-1][1]["scanner_device_id"], "phone-device")
        self.assertEqual(self.service_calls, [])

        self.registry.set_mobile_nfc_permission(
            self.person_id, "front_door", True
        )
        granted_event = {
            "data": {"tag_id": "door-tag", "device_id": "phone-device"},
            "context": {"id": "scan-2", "user_id": "ha-user-1"},
        }
        await admin.handle_mobile_tag_scan(granted_event)
        self.assertEqual(
            self.service_calls[-1],
            ("lock", "open", {"entity_id": "lock.front_door"}),
        )
        self.assertTrue(self.events[-1][1]["action_executed"])
        self.assertEqual(self.events[-1][1]["door_id"], "front_door")

    async def test_mobile_nfc_permission_endpoint_uses_tag_and_allows_revoke(self):
        self.registry.link_ha_person(self.person_id, "person.example_person")
        self.registry.save_mobile_nfc_tag(
            "door-tag", "Front door tag", "front_door", True
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        self.ha.people_api_ready = True
        self.ha.people_storage = [{
            "id": "example_person",
            "name": "Example Person",
            "user_id": "ha-user-1",
        }]
        self.ha.people_storage_refreshed_at = (
            asyncio.get_running_loop().time()
        )

        class Request:
            headers = {"X-Fingerprint-Admin": "1"}

            def __init__(self, payload):
                self.payload = payload

            async def json(self):
                return self.payload

        granted = await admin.set_mobile_nfc_permission(Request({
            "person_id": self.person_id,
            "tag_id": "door-tag",
            "enabled": True,
        }))
        self.assertEqual(granted.status, 200)
        self.assertTrue(
            self.registry.mobile_nfc_allowed(self.person_id, "front_door")
        )

        self.registry.connection.execute(
            "UPDATE people SET ha_person_entity_id = NULL WHERE id = ?",
            (self.person_id,),
        )
        self.registry.connection.commit()
        revoked = await admin.set_mobile_nfc_permission(Request({
            "person_id": self.person_id,
            "door_id": "front_door",
            "enabled": False,
        }))
        self.assertEqual(revoked.status, 200)
        self.assertFalse(
            self.registry.mobile_nfc_allowed(self.person_id, "front_door")
        )

        with self.assertRaises(APP.web.HTTPBadRequest) as rejected:
            await admin.set_mobile_nfc_permission(Request({
                "person_id": self.person_id,
                "tag_id": "door-tag",
                "enabled": True,
            }))
        self.assertIn("Link the user", rejected.exception.text)

    async def test_mobile_nfc_event_id_and_short_repeats_are_deduplicated(self):
        self.registry.link_ha_person(self.person_id, "person.example_person")
        self.registry.save_mobile_nfc_tag(
            "door-tag", "Front door tag", "front_door", True
        )
        self.registry.set_mobile_nfc_permission(self.person_id, "front_door", True)
        self.ha.people_storage = [{
            "id": "example_person", "user_id": "ha-user-1"
        }]
        self.ha.people_storage_refreshed_at = asyncio.get_running_loop().time()
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.recent_mobile_tag_scans = {}
        event = {
            "data": {"tag_id": "door-tag", "device_id": "phone-device"},
            "context": {"id": "scan-1", "user_id": "ha-user-1"},
        }
        await admin.handle_mobile_tag_scan(event)
        await admin.handle_mobile_tag_scan(event)
        self.assertEqual(len(self.service_calls), 1)
        await admin.handle_mobile_tag_scan({
            "data": {"tag_id": "door-tag", "device_id": "phone-device"},
            "context": {"id": "scan-2", "user_id": "ha-user-1"},
        })
        self.assertEqual(len(self.service_calls), 1)
        self.assertEqual(self.events[-1][1]["action_error"], "Duplicate mobile NFC scan")
        await admin.handle_mobile_tag_scan({
            "data": {"tag_id": "door-tag"},
            "context": {"id": "scan-3", "user_id": "ha-user-1"},
        })
        self.assertEqual(len(self.service_calls), 1)
        self.assertFalse(self.events[-1][1]["authorized"])
        self.assertIsNone(self.events[-1][1]["scanner_device_id"])
        self.assertEqual(self.events[-1][1]["authorization_reason"], "invalid_source")

    async def test_mobile_nfc_user_mapping_is_refreshed_when_stale(self):
        self.registry.link_ha_person(self.person_id, "person.example_person")
        replacement_id = self.registry.create_person("Replacement Person")
        self.registry.link_ha_person(replacement_id, "person.replacement_person")
        self.ha.people_storage = [{
            "id": "example_person", "user_id": "ha-user-1"
        }]
        self.ha.people_storage_refreshed_at = (
            asyncio.get_running_loop().time() - 301
        )

        async def refresh_people_storage():
            self.ha.people_storage = [{
                "id": "replacement_person", "user_id": "ha-user-1"
            }]
            self.ha.people_storage_refreshed_at = asyncio.get_running_loop().time()
            return self.ha.people_storage

        self.ha.refresh_people_storage = refresh_people_storage
        person = await self.ha.access_person_for_user_id("ha-user-1")
        self.assertEqual(person["id"], replacement_id)

    async def test_home_assistant_tags_use_the_websocket_registry(self):
        commands = []

        async def websocket_command(command):
            commands.append(command)
            return [
                {"id": "door-tag", "name": "Front door tag"},
                {"id": "unnamed-tag"},
            ]

        self.ha.websocket_command = websocket_command
        await self.ha.refresh_tags_storage()
        self.assertEqual(commands, [{"type": "tag/list"}])
        self.assertEqual(
            self.ha.ha_tags(),
            [
                {
                    "tag_id": "door-tag",
                    "name": "Front door tag",
                    "entity_id": None,
                },
                {
                    "tag_id": "unnamed-tag",
                    "name": "unnamed-tag",
                    "entity_id": None,
                },
            ],
        )

    async def test_home_assistant_tag_refresh_is_bounded(self):
        refreshes = []

        async def refresh_tags_storage():
            refreshes.append(True)
            self.ha.tags_storage_refreshed_at = asyncio.get_running_loop().time()

        self.ha.refresh_tags_storage = refresh_tags_storage
        self.assertIsNone(self.ha.tags_storage_refreshed_at)
        self.ha.schedule_tags_refresh()
        refresh_task = self.ha.tag_refresh_task
        self.assertIsNotNone(refresh_task)
        self.ha.schedule_tags_refresh()
        await refresh_task
        self.ha.schedule_tags_refresh()
        self.assertEqual(refreshes, [True])

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
            self.person_id, "front_keypad", "1234"
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

        self.registry.update_reader(
            "front_keypad", "Front keypad", "front_door", config={
                "transaction_entity": "sensor.keypad_transaction",
                "code_entity": "sensor.keypad_code",
                "action_entity": "sensor.keypad_action",
                "action_map": {"arm_all_zones": "unlock"},
            }
        )
        self.service_calls.clear()
        await admin.process_keypad_event(
            self.registry.reader("front_keypad"), "2", "1234", "arm_all_zones"
        )
        self.assertEqual(self.service_calls[0][1], "unlock")

        self.service_calls.clear()
        await admin.process_keypad_event(
            self.registry.reader("front_keypad"), "3", "1234", "unknown_button"
        )
        self.assertEqual(self.service_calls, [])

    async def test_shared_keypad_credential_executes_and_is_auditable(self):
        self.registry.create_reader(
            "shared_keypad", "Shared keypad", "keypad", "front_door", {
                "transaction_entity": "sensor.shared_transaction",
                "code_entity": "sensor.shared_code",
                "action_entity": "sensor.shared_action",
                "action_map": {"disarm": "open"},
            }
        )
        credential_id = self.registry.add_shared_keypad_credential(
            "Cleaner", "shared_keypad", "0123"
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.capture_sessions = {}

        await admin.process_keypad_event(
            self.registry.reader("shared_keypad"), "38", "0123", "disarm"
        )

        self.assertEqual(
            self.service_calls[-1],
            ("lock", "open", {"entity_id": "lock.front_door"}),
        )
        payload = self.events[-1][1]
        self.assertEqual(payload["credential_type"], "shared_keypad")
        self.assertEqual(payload["credential_id"], str(credential_id))
        self.assertEqual(payload["credential_label"], "Cleaner")
        self.assertIsNone(payload["person_id"])
        self.assertTrue(payload["action_executed"])

    async def test_keypad_capture_accepts_unmapped_action(self):
        self.registry.create_reader(
            "capture_keypad", "Capture keypad", "keypad", "front_door", {
                "transaction_entity": "sensor.capture_transaction",
                "code_entity": "sensor.capture_code",
                "action_entity": "sensor.capture_action",
                "action_map": {},
            }
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.capture_sessions = {
            "capture_keypad": {
                "person_id": self.person_id,
                "person_name": "Example Person",
                "expires_at": APP.asyncio.get_running_loop().time() + 60,
            }
        }
        display_events = []

        async def emit_display_event(door_id, kind, event_id, detail=""):
            display_events.append((door_id, kind, event_id, detail))
            return 1

        self.ha.emit_display_event = emit_display_event
        await admin.process_keypad_event(
            self.registry.reader("capture_keypad"),
            "1", "+0A1B2C3", "arm_day_zones",
        )
        credential = self.registry.find_keypad_credential(
            "capture_keypad", "+0A1B2C3", "disarm"
        )
        self.assertIsNotNone(credential)
        self.assertEqual(credential["hash_version"], 2)
        self.assertNotIn("capture_keypad", admin.capture_sessions)
        self.assertEqual(display_events, [(
            "front_door", "credential_captured",
            "capture:capture_keypad:1", "Example Person",
        )])

    async def test_display_events_only_target_readers_on_the_same_door(self):
        front_config = {
            "assigned_door_entity": "text.front_reader_access_manager_door_id",
            "display_event_entity": "text.front_reader_access_manager_display_event",
        }
        self.registry.update_reader(
            "front_reader", "Front reader", "front_door", True, front_config
        )
        self.registry.create_door(
            "back_door", "Back door", "lock.back_door", "unlock"
        )
        self.registry.create_reader(
            "back_reader", "Back reader", "fingerprint", "back_door", {
                "assigned_door_entity": "text.back_reader_access_manager_door_id",
                "display_event_entity": "text.back_reader_access_manager_display_event",
            }
        )
        self.ha.states.update({
            "text.front_reader_access_manager_door_id": {"state": ""},
            "text.front_reader_access_manager_display_event": {"state": ""},
            "text.back_reader_access_manager_door_id": {"state": "back_door"},
            "text.back_reader_access_manager_display_event": {"state": ""},
        })

        delivered = await self.ha.emit_display_event(
            "front_door", "door_opened", "front:123", "Example Person"
        )

        self.assertEqual(delivered, 1)
        text_calls = [
            payload for domain, service, payload in self.service_calls
            if domain == "text" and service == "set_value"
        ]
        self.assertEqual(
            [payload["entity_id"] for payload in text_calls],
            [
                "text.front_reader_access_manager_door_id",
                "text.front_reader_access_manager_display_event",
            ],
        )
        self.assertEqual(text_calls[0]["value"], "front_door")
        self.assertEqual(
            text_calls[1]["value"],
            "v1|front:123|front_door|door_opened|Example Person",
        )

    async def test_open_and_denied_keypad_results_emit_display_feedback(self):
        self.registry.update_reader(
            "front_reader", "Front reader", "front_door", True, {
                "assigned_door_entity": "text.front_reader_access_manager_door_id",
                "display_event_entity": "text.front_reader_access_manager_display_event",
            }
        )
        self.registry.create_reader(
            "front_keypad", "Front keypad", "keypad", "front_door", {}
        )
        self.ha.states.update({
            "text.front_reader_access_manager_door_id": {"state": "front_door"},
            "text.front_reader_access_manager_display_event": {"state": ""},
        })
        person = self.registry.person(self.person_id)

        await self.ha.emit_credential_event(
            "front_keypad", person, "keypad", 1, "open", "51"
        )
        await self.ha.emit_credential_event(
            "front_keypad", None, "keypad", "unknown", "open", "52",
            authorized=False,
        )

        display_values = [
            payload["value"] for domain, service, payload in self.service_calls
            if domain == "text" and service == "set_value"
            and payload["entity_id"].endswith("access_manager_display_event")
        ]
        self.assertEqual(display_values, [
            "v1|front_keypad:51|front_door|door_opened|Example Person",
            "v1|front_keypad:52|front_door|keypad_denied|Front keypad",
        ])

    async def test_manual_keypad_credential_endpoint_accepts_tag(self):
        self.registry.create_reader(
            "manual_keypad", "Manual keypad", "keypad", "front_door", {}
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha

        class Request:
            headers = {"X-Fingerprint-Admin": "1"}

            async def json(self):
                return {
                    "person_id": self_person_id,
                    "reader_id": "manual_keypad",
                    "code": "+0A1B2C3",
                }

        self_person_id = self.person_id
        response = await admin.create_keypad_credential(Request())
        self.assertEqual(response.status, 200)
        self.assertNotIn("+0A1B2C3", response.text)
        credential = self.registry.find_keypad_credential(
            "manual_keypad", "+0A1B2C3", "arm_all_zones"
        )
        self.assertIsNotNone(credential)
        self.assertEqual(credential["hash_version"], 2)

        class RevealRequest:
            headers = {"X-Fingerprint-Admin": "1"}
            match_info = {"credential_id": str(credential["id"])}

        revealed = await admin.reveal_keypad_credential(RevealRequest())
        self.assertEqual(APP.json.loads(revealed.text)["value"], "+0A1B2C3")
        self.assertEqual(revealed.headers["Cache-Control"], "no-store, max-age=0")

        with self.assertRaises(APP.web.HTTPConflict):
            await admin.create_keypad_credential(Request())

    async def test_disabling_privacy_requires_explicit_acknowledgement(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha

        class Request:
            headers = {"X-Fingerprint-Admin": "1"}

            def __init__(self, payload):
                self.payload = payload

            async def json(self):
                return self.payload

        with self.assertRaises(APP.web.HTTPBadRequest):
            await admin.set_privacy_mode(Request({"enabled": False}))
        response = await admin.set_privacy_mode(
            Request({"enabled": False, "acknowledge": True})
        )
        self.assertEqual(response.status, 200)
        self.assertFalse(self.registry.privacy_mode())
        await admin.set_privacy_mode(Request({"enabled": True}))
        self.assertTrue(self.registry.privacy_mode())

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

        # The transaction is an opaque deduplication token. It may jump rather
        # than behaving like a counter that increases exactly one by one.
        self.ha.states["sensor.packet_transaction"]["state"] = "103"
        self.assertTrue(await admin.process_keypad_packet("packet_keypad"))
        self.assertEqual(processed[-1], ("packet_keypad", "103", "1234", "disarm"))
        self.assertEqual(
            self.registry.setting("reader_transaction:packet_keypad"), "103"
        )

    async def test_keypad_capture_uses_transient_event_values_before_they_clear(self):
        self.registry.create_reader(
            "transient_keypad", "Transient keypad", "keypad", "front_door", {
                "transaction_entity": "sensor.transient_transaction",
                "code_entity": "sensor.transient_code",
                "action_entity": "sensor.transient_action",
                "action_map": {"disarm": "open"},
            }
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        admin.capture_sessions = {
            "transient_keypad": {
                "person_id": self.person_id,
                "person_name": "Example Person",
                "expires_at": APP.asyncio.get_running_loop().time() + 60,
            }
        }
        admin.keypad_learning_sessions = {}
        admin.last_keypad_actions = {}
        admin.keypad_packet_tasks = {}
        admin.keypad_packet_buffers = {}

        for entity_id, value in (
            ("sensor.transient_transaction", "57"),
            ("sensor.transient_code", "0426"),
            ("sensor.transient_action", "disarm"),
        ):
            await admin.handle_state_change(entity_id, {"state": value})
        for entity_id, value in (
            ("sensor.transient_transaction", ""),
            ("sensor.transient_code", ""),
            ("sensor.transient_action", "unknown"),
        ):
            self.ha.states[entity_id] = {"state": value}
            await admin.handle_state_change(entity_id, {"state": value})

        await APP.asyncio.sleep(APP.KEYPAD_PACKET_SETTLE_SECONDS + 0.1)
        credential = self.registry.find_keypad_credential(
            "transient_keypad", "0426", "disarm"
        )
        self.assertIsNotNone(credential)
        self.assertNotIn("transient_keypad", admin.capture_sessions)
        self.assertNotIn("transient_keypad", admin.keypad_packet_buffers)
        self.assertIsNone(self.registry.find_keypad_credential(
            "transient_keypad", "426", "disarm"
        ))

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
        self.assertEqual(len(config["conditions"]), 1)
        guarded = APP.FingerprintAdmin.build_auto_lock_config(
            door, config_id, 10, "binary_sensor.front_door_contact"
        )
        self.assertEqual(guarded["triggers"][0], {
            "trigger": "door.closed",
            "target": {"entity_id": "binary_sensor.front_door_contact"},
            "options": {},
        })
        self.assertEqual(guarded["actions"][0]["delay"]["minutes"], 10)
        self.assertEqual(
            guarded["actions"][1]["if"][1]["condition"], "door.is_closed"
        )
        self.assertTrue(
            APP.FingerprintAdmin.owned_automation_config(config, config_id)
        )
        config["description"] = "Changed outside Access Manager"
        self.assertFalse(
            APP.FingerprintAdmin.owned_automation_config(config, config_id)
        )

    async def test_door_open_and_denied_access_configs_are_native(self):
        door = self.registry.doors()[0]
        door_open_id = APP.FingerprintAdmin.door_open_automation_id(door["id"])
        door_open = APP.FingerprintAdmin.build_door_open_config(
            door, door_open_id, 5, "binary_sensor.front_door_contact"
        )
        self.assertEqual(door_open_id, "access_manager_door_open_front_door")
        self.assertEqual(door_open["triggers"][0]["to"], "on")
        self.assertEqual(door_open["triggers"][0]["for"]["minutes"], 5)
        self.assertEqual(
            door_open["conditions"][0]["entity_id"],
            "binary_sensor.front_door_contact",
        )
        self.assertEqual(
            door_open["actions"][0]["action"],
            "notify.persistent_notification",
        )

        denied_id = APP.FingerprintAdmin.denied_access_automation_id(door["id"])
        denied = APP.FingerprintAdmin.build_denied_access_config(
            door, denied_id, 3, 5, "notify.example_phone"
        )
        self.assertEqual(denied_id, "access_manager_denied_access_front_door")
        self.assertEqual(denied["triggers"][0], {
            "trigger": "event",
            "event_type": "access_manager_credential",
            "event_data": {"door_id": "front_door", "authorized": False},
        })
        self.assertEqual(denied["actions"][0]["timeout"]["minutes"], 5)
        self.assertEqual(denied["actions"][1]["repeat"]["count"], 1)
        self.assertEqual(
            denied["actions"][1]["repeat"]["sequence"][0]["timeout"],
            "{{ wait.remaining }}",
        )
        self.assertEqual(denied["actions"][-1], {
            "action": "notify.send_message",
            "target": {"entity_id": "notify.example_phone"},
            "data": {
                "message": (
                    "Access Manager detected 3 denied access attempts "
                    "at Front door within 5 minutes."
                )
            },
        })
        self.assertEqual(denied["mode"], "single")
        self.assertEqual(denied["max_exceeded"], "silent")

        immediate = APP.FingerprintAdmin.build_denied_access_config(
            door, denied_id, 1, 5
        )
        self.assertEqual(len(immediate["actions"]), 1)
        self.assertEqual(
            immediate["actions"][0]["action"],
            "notify.persistent_notification",
        )

    async def test_registry_allows_one_automation_of_each_type_per_door(self):
        for automation_type in ("auto_lock", "door_open", "denied_access"):
            automation_id = f"access_manager_{automation_type}_front_door"
            self.registry.upsert_managed_automation(
                automation_id, automation_type, "front_door", automation_id,
                True, {},
            )
        self.assertEqual(
            {item["automation_type"] for item in self.registry.managed_automations()},
            {"auto_lock", "door_open", "denied_access"},
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.registry.upsert_managed_automation(
                "alternate_auto_lock", "auto_lock", "front_door",
                "alternate_auto_lock", True, {},
            )

    async def test_door_sensor_entities_only_include_binary_sensors(self):
        self.ha.states.update({
            "binary_sensor.front_door_contact": {
                "state": "off",
                "attributes": {
                    "friendly_name": "Front door",
                    "device_class": "door",
                },
            },
            "binary_sensor.hall_motion": {
                "state": "off", "attributes": {"device_class": "motion"},
            },
            "binary_sensor.generic_contact": {"state": "off", "attributes": {}},
            "sensor.front_door_position": {"state": "closed", "attributes": {}},
        })
        self.assertTrue(
            self.ha.is_door_sensor("binary_sensor.front_door_contact")
        )
        self.assertFalse(self.ha.is_door_sensor("binary_sensor.hall_motion"))
        self.assertFalse(self.ha.is_door_sensor("binary_sensor.generic_contact"))
        self.assertEqual(self.ha.door_sensor_entities(), [{
            "entity_id": "binary_sensor.front_door_contact",
            "name": "Front door",
            "state": "off",
        }])

    async def test_external_lock_and_contact_openings_are_logged(self):
        self.registry.update_door(
            "front_door", "Front door", "lock.front_door", "open",
            "binary_sensor.front_door_contact",
        )
        self.registry.update_door(
            "front_door", "Front door", "lock.front_door", "open"
        )
        self.assertEqual(
            self.registry.doors()[0]["door_sensor_entity"],
            "binary_sensor.front_door_contact",
        )
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha

        await admin.handle_state_change(
            "lock.front_door", {"state": "unlocked"}, {"state": "locked"}
        )
        await admin.handle_state_change(
            "binary_sensor.front_door_contact", {"state": "on"}, {"state": "off"}
        )
        await admin.handle_state_change(
            "lock.front_door", {"state": "locked"}, {"state": "unlocked"}
        )
        await admin.handle_state_change(
            "binary_sensor.front_door_contact", {"state": "off"}, {"state": "on"}
        )

        events = self.registry.events()
        self.assertEqual(
            [event["event_type"] for event in events[:4]],
            [
                "door_physically_closed", "door_lock_closed",
                "door_physically_opened", "door_lock_opened",
            ],
        )
        self.assertEqual(events[2]["door_id"], "front_door")
        self.assertEqual(
            events[2]["entity_id"], "binary_sensor.front_door_contact"
        )
        self.assertEqual(events[2]["source"], "external")
        self.assertEqual(events[2]["previous_state"], "off")
        self.assertEqual(events[2]["new_state"], "on")
        self.assertEqual(events[3]["source"], "external")

    async def test_lock_opening_ignores_initial_and_settling_states(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha

        await admin.handle_state_change(
            "lock.front_door", {"state": "unlocked"}, None
        )
        await admin.handle_state_change(
            "lock.front_door", {"state": "unlocked"}, {"state": "unknown"}
        )
        await admin.handle_state_change(
            "lock.front_door", {"state": "open"}, {"state": "locked"}
        )
        await admin.handle_state_change(
            "lock.front_door", {"state": "unlocked"}, {"state": "open"}
        )

        events = self.registry.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "door_lock_opened")
        self.assertEqual(events[0]["previous_state"], "locked")
        self.assertEqual(events[0]["new_state"], "open")

    async def test_access_manager_door_command_is_correlated_with_state_change(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = self.registry
        admin.ha = self.ha
        door = self.registry.doors()[0]

        await self.ha.execute_door_action(door, "unlock")
        await admin.handle_state_change(
            "lock.front_door", {"state": "unlocked"}, {"state": "locked"}
        )

        event = self.registry.events()[0]
        self.assertEqual(event["source"], "access_manager")
        self.assertNotIn("lock.front_door", self.ha.recent_door_commands)

    async def test_failed_door_command_clears_pending_correlation(self):
        async def fail_service(*_args, **_kwargs):
            raise RuntimeError("service failed")

        self.ha.call_service = fail_service
        with self.assertRaisesRegex(RuntimeError, "service failed"):
            await self.ha.execute_door_action(self.registry.doors()[0], "unlock")
        self.assertNotIn("lock.front_door", self.ha.recent_door_commands)

    async def test_notification_entities_only_include_notify_domain(self):
        self.ha.states.update({
            "notify.example_phone": {
                "state": "2026-07-17T00:00:00+00:00",
                "attributes": {"friendly_name": "Example phone"},
            },
            "sensor.notification_count": {
                "state": "2", "attributes": {"friendly_name": "Notifications"},
            },
        })
        self.assertTrue(self.ha.is_notification_entity(""))
        self.assertTrue(self.ha.is_notification_entity("notify.example_phone"))
        self.assertFalse(self.ha.is_notification_entity("notify.missing"))
        self.assertEqual(self.ha.notification_entities(), [{
            "entity_id": "notify.example_phone",
            "name": "Example phone",
            "state": "2026-07-17T00:00:00+00:00",
        }])

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
    def test_door_activity_schema_and_sensor_are_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            path = Path(directory) / "door-activity-schema.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE doors (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    entity_id TEXT,
                    open_action TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE managed_automations (
                    id TEXT PRIMARY KEY,
                    automation_type TEXT NOT NULL,
                    door_id TEXT NOT NULL,
                    ha_config_id TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(automation_type, door_id)
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    slot INTEGER,
                    confidence INTEGER,
                    detail TEXT
                );
                INSERT INTO doors VALUES (
                    'front_door', 'Front door', 'lock.front_door', 'open',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
                );
                INSERT INTO managed_automations VALUES (
                    'access_manager_door_open_front_door', 'door_open',
                    'front_door', 'access_manager_door_open_front_door', 1,
                    '{"door_sensor_entity":"binary_sensor.front_door_contact"}',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
                );
                """
            )
            connection.commit()
            connection.close()

            registry = APP.Registry(path)
            self.assertEqual(
                registry.doors()[0]["door_sensor_entity"],
                "binary_sensor.front_door_contact",
            )
            event_columns = {
                row[1]
                for row in registry.connection.execute(
                    "PRAGMA table_info(events)"
                ).fetchall()
            }
            self.assertTrue({
                "door_id", "entity_id", "source", "previous_state", "new_state"
            }.issubset(event_columns))
            registry.connection.close()

    def test_pre_release_plaintext_credentials_are_encrypted_and_scrubbed(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            path = Path(directory) / "plaintext-keypad-schema.db"
            raw_secret = "+0A1B2C3"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE keypad_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER NOT NULL,
                    reader_id TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    code_hint TEXT NOT NULL,
                    keypad_action TEXT NOT NULL,
                    normalized_action TEXT NOT NULL,
                    secret_value TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(reader_id, secret_hash)
                );
                INSERT INTO keypad_credentials(
                    person_id, reader_id, secret_hash, code_hint, keypad_action,
                    normalized_action, secret_value, status, created_at, updated_at
                ) VALUES (
                    1, 'old_keypad', 'old-digest', 'Tag masked', 'disarm',
                    'open', '+0A1B2C3', 'active',
                    '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:00+00:00'
                );
                """
            )
            connection.commit()
            connection.close()

            registry = APP.Registry(path)
            row = registry.connection.execute(
                "SELECT secret_value, secret_ciphertext "
                "FROM keypad_credentials WHERE id = 1"
            ).fetchone()
            self.assertIsNone(row["secret_value"])
            self.assertNotEqual(row["secret_ciphertext"], raw_secret)
            self.assertEqual(
                registry.decrypt_keypad_secret(row["secret_ciphertext"]), raw_secret
            )
            registry.connection.close()
            self.assertNotIn(raw_secret.encode(), path.read_bytes())

    def test_existing_keypad_credentials_are_marked_as_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            path = Path(directory) / "legacy-keypad-schema.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE keypad_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER NOT NULL,
                    reader_id TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    code_hint TEXT NOT NULL,
                    keypad_action TEXT NOT NULL,
                    normalized_action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(reader_id, secret_hash)
                );
                INSERT INTO keypad_credentials(
                    person_id, reader_id, secret_hash, code_hint, keypad_action,
                    normalized_action, status, created_at, updated_at
                ) VALUES (
                    1, 'old_keypad', 'old-digest', 'Code ••34', 'disarm',
                    'open', 'active', '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:00+00:00'
                );
                """
            )
            connection.commit()
            connection.close()

            registry = APP.Registry(path)
            columns = {
                row[1]: row for row in registry.connection.execute(
                    "PRAGMA table_info(keypad_credentials)"
                ).fetchall()
            }
            self.assertIn("hash_version", columns)
            row = registry.connection.execute(
                "SELECT hash_version FROM keypad_credentials WHERE id = 1"
            ).fetchone()
            self.assertEqual(row["hash_version"], 1)
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
            raw_secret = "+0A1B2C3"
            registry.add_keypad_credential(
                person_id, "example_keypad", raw_secret
            )
            self.assertNotIn(raw_secret, str(registry.people()))
            disarm_credential = registry.find_keypad_credential(
                "example_keypad", raw_secret, "disarm"
            )
            arm_credential = registry.find_keypad_credential(
                "example_keypad", raw_secret, "arm_all_zones"
            )
            self.assertEqual(disarm_credential["id"], arm_credential["id"])
            self.assertEqual(disarm_credential["hash_version"], 2)
            self.assertEqual(disarm_credential["code_hint"], "Tag •••2C3")
            with self.assertRaisesRegex(ValueError, "already linked"):
                registry.add_keypad_credential(
                    person_id, "example_keypad", raw_secret
                )
            registry.connection.close()

    def test_encrypted_secret_can_be_revealed_without_plaintext_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            path = Path(directory) / "privacy.db"
            registry = APP.Registry(path)
            person_id = registry.create_person("Example Person")
            registry.create_reader(
                "example_keypad", "Example Keypad", "keypad", "", {}
            )
            registry.add_keypad_credential(
                person_id, "example_keypad", "+0A1B2C3"
            )
            hidden = registry.people()[0]["credentials"][0]
            self.assertIsNone(hidden["display_value"])
            self.assertTrue(hidden["revealable"])
            self.assertEqual(
                registry.reveal_keypad_credential(1), "+0A1B2C3"
            )
            stored = registry.connection.execute(
                "SELECT secret_ciphertext FROM keypad_credentials WHERE id = 1"
            ).fetchone()["secret_ciphertext"]
            self.assertNotEqual(stored, "+0A1B2C3")
            self.assertNotIn(
                b"+0A1B2C3", path.read_bytes()
            )
            self.assertIsNotNone(
                registry.find_keypad_credential(
                    "example_keypad", "+0A1B2C3", "disarm"
                )
            )
            registry.set_privacy_mode(False)
            visible = registry.people()[0]["credentials"][0]
            self.assertEqual(visible["display_value"], "+0A1B2C3")
            registry.set_privacy_mode(True)
            self.assertIsNone(
                registry.people()[0]["credentials"][0]["display_value"]
            )
            self.assertTrue((Path(directory) / "credential_encryption.key").is_file())
            registry.connection.close()

    def test_keypad_pin_is_opaque_and_preserves_leading_zeroes(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "pins.db")
            person_id = registry.create_person("Example Person")
            registry.create_reader(
                "example_keypad", "Example Keypad", "keypad", "", {}
            )
            short_id = registry.add_keypad_credential(
                person_id, "example_keypad", "0123"
            )
            long_id = registry.add_keypad_credential(
                person_id, "example_keypad", "00123456"
            )
            self.assertNotEqual(short_id, long_id)
            self.assertIsNotNone(
                registry.find_keypad_credential(
                    "example_keypad", "0123", "disarm"
                )
            )
            self.assertIsNone(
                registry.find_keypad_credential(
                    "example_keypad", "123", "disarm"
                )
            )
            for invalid in ("", "unknown", "unavailable", "x" * 129, "12\n34"):
                with self.assertRaises(ValueError):
                    registry.add_keypad_credential(
                        person_id, "example_keypad", invalid
                    )
            registry.connection.close()

    def test_legacy_action_scoped_keypad_credential_still_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            APP.DATA_DIR = Path(directory)
            registry = APP.Registry(Path(directory) / "legacy-keypad.db")
            person_id = registry.create_person("Example Person")
            registry.create_reader(
                "example_keypad", "Example Keypad", "keypad", "", {}
            )
            digest = registry.legacy_credential_hash(
                "example_keypad", "1234", "disarm"
            )
            timestamp = APP.now_iso()
            registry.connection.execute(
                """
                INSERT INTO keypad_credentials(
                    person_id, reader_id, secret_hash, hash_version, code_hint,
                    keypad_action, normalized_action, status, created_at, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    person_id, "example_keypad", digest, "Code ••34",
                    "disarm", "open", timestamp, timestamp,
                ),
            )
            registry.connection.commit()
            self.assertIsNotNone(
                registry.find_keypad_credential(
                    "example_keypad", "1234", "disarm"
                )
            )
            self.assertIsNone(
                registry.find_keypad_credential(
                    "example_keypad", "1234", "arm_all_zones"
                )
            )
            credential = registry.people()[0]["credentials"][0]
            self.assertTrue(credential["legacy_action_scope"])
            registry.connection.close()


if __name__ == "__main__":
    unittest.main()

import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch


SPEC = importlib.util.spec_from_file_location("access_manager_resilience", Path(__file__).parents[1] / "access_manager/app/main.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class DashboardJobTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ha = APP.HomeAssistant(None)
        self.transport = APP.HomeAssistantIngressTransport(self.ha)

    async def asyncTearDown(self):
        await self.ha.close()

    async def test_repeated_and_concurrent_followers_never_spawn_again(self):
        release, started = asyncio.Event(), asyncio.Event()
        async def process(endpoint, args, on_event):
            started.set()
            await on_event("output", "Synthetic compile output")
            await release.wait()
            return {"success": True, "install_completed": True}
        self.transport._dashboard_process = AsyncMock(side_effect=process)
        job = await self.transport._legacy_dashboard_command("firmware/install", {"configuration": "front.yaml"})
        await started.wait()
        first = asyncio.create_task(self.transport._legacy_dashboard_command("firmware/follow_job", job))
        second_transport = APP.HomeAssistantIngressTransport(self.ha)
        second_transport._dashboard_process = AsyncMock()
        second_transport._websocket_command = AsyncMock()
        second = asyncio.create_task(second_transport.command("firmware/follow_job", job))
        release.set()
        self.assertTrue((await first)["install_completed"])
        self.assertTrue((await second)["install_completed"])
        self.assertTrue((await second_transport.command("firmware/follow_job", job))["install_completed"])
        self.transport._dashboard_process.assert_awaited_once()
        second_transport._dashboard_process.assert_not_called()
        second_transport._websocket_command.assert_not_called()

    async def test_job_listing_preserves_process_failure(self):
        for success in (False, True):
            self.transport._dashboard_process = AsyncMock(return_value={"success": success})
            job = await self.transport._legacy_dashboard_command("firmware/compile", {"configuration": "front.yaml"})
            await self.transport._follow_dashboard_job(job["job_id"])
            jobs = await self.transport._legacy_dashboard_command("firmware/get_jobs")
            listed = next(item for item in jobs if item["job_id"] == job["job_id"])
            self.assertEqual(listed["status"], "completed" if success else "failed")

    async def test_cancelled_observer_does_not_cancel_the_install(self):
        release, started = asyncio.Event(), asyncio.Event()
        async def process(*args):
            started.set()
            await release.wait()
            return {"success": True, "install_completed": True}
        self.transport._dashboard_process = AsyncMock(side_effect=process)
        job = await self.transport._legacy_dashboard_command("firmware/install", {"configuration": "front.yaml"})
        await started.wait()
        observer = asyncio.create_task(self.transport._follow_dashboard_job(job["job_id"]))
        await asyncio.sleep(0)
        observer.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await observer
        self.assertFalse(self.ha.dashboard_jobs[job["job_id"]]["done"])
        release.set()
        self.assertTrue((await self.transport._follow_dashboard_job(job["job_id"]))["success"])
        self.transport._dashboard_process.assert_awaited_once()

    async def test_lost_job_after_restart_is_reported_without_spawning(self):
        self.transport._dashboard_process = AsyncMock()
        for job_id in ("dashboard:run:front.yaml", "dashboard:run:abcdefghijklmnop:front.yaml"):
            with self.assertRaises(APP.DeviceBuilderError) as error:
                await self.transport._follow_dashboard_job(job_id)
            self.assertEqual(error.exception.code, "job_not_found")
        self.transport._dashboard_process.assert_not_called()

    async def test_lost_process_is_terminal_and_cannot_auto_replay(self):
        self.transport._dashboard_process = AsyncMock(side_effect=APP.DeviceBuilderError("Socket lost", "unavailable"))
        job = await self.transport._legacy_dashboard_command("firmware/install", {"configuration": "front.yaml"})
        for _ in range(2):
            with self.assertRaises(APP.DeviceBuilderError) as error:
                await self.transport._follow_dashboard_job(job["job_id"])
            self.assertEqual(error.exception.code, "job_interrupted")
        self.transport._dashboard_process.assert_awaited_once()

    async def test_active_configuration_rejects_a_second_submission(self):
        release = asyncio.Event()
        async def process(*args):
            await release.wait()
            return {"success": True}
        self.transport._dashboard_process = AsyncMock(side_effect=process)
        job = await self.transport._legacy_dashboard_command("firmware/compile", {"configuration": "front.yaml"})
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await self.transport._legacy_dashboard_command("firmware/install", {"configuration": "front.yaml"})
        self.assertEqual(error.exception.code, "job_busy")
        release.set()
        await self.transport._follow_dashboard_job(job["job_id"])

    async def test_ha_close_stops_its_dashboard_workers(self):
        started = asyncio.Event()
        async def process(*args):
            started.set()
            await asyncio.Event().wait()
        self.transport._dashboard_process = AsyncMock(side_effect=process)
        await self.transport._legacy_dashboard_command("firmware/compile", {"configuration": "front.yaml"})
        await started.wait()
        await self.ha.close()
        self.assertEqual(self.ha.dashboard_jobs, {})

    async def test_home_assistant_command_has_a_bounded_wait(self):
        async def never_reply(command):
            await asyncio.Event().wait()
        self.ha._websocket_command_once = never_reply
        timeout = asyncio.timeout(0.01)
        with patch.object(APP.asyncio, "timeout", return_value=timeout):
            with self.assertRaises(TimeoutError):
                await self.ha.websocket_command({"type": "person/list"})

    async def test_supervisor_denial_is_a_handled_builder_error_without_retry(self):
        self.transport.ingress_context = ("admin-user", "esphome", "synthetic_session")
        self.ha.ingress_user_is_admin = AsyncMock(return_value=False)
        self.ha.websocket_command = AsyncMock(side_effect=RuntimeError("Unauthorized"))
        self.transport._legacy_dashboard_command = AsyncMock()
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await self.transport.command("devices/list")
        self.assertEqual(error.exception.code, "unauthorized")
        self.assertEqual(self.transport.status["status"], "unauthorized")
        self.ha.websocket_command.assert_not_awaited()
        self.transport._legacy_dashboard_command.assert_not_called()

    async def test_supervisor_failures_do_not_leak_private_upstream_details(self):
        self.transport.ingress_context = ("admin-user", "esphome", "synthetic_session")
        for failure, code in (
            (RuntimeError("synthetic-private-session-value"), "unauthorized"),
            (TimeoutError("synthetic-private-session-value"), "unauthorized"),
            (APP.ClientError("synthetic-private-session-value"), "unauthorized"),
            (OSError("synthetic-private-session-value"), "unauthorized"),
        ):
            with self.subTest(failure=type(failure).__name__):
                self.ha.ingress_user_is_admin = AsyncMock(side_effect=failure)
                with self.assertRaises(APP.DeviceBuilderError) as error:
                    await self.transport.command("devices/list")
                self.assertEqual(error.exception.code, code)
                self.assertEqual(self.transport.status["status"], code)
                self.assertNotIn("synthetic-private", str(error.exception))
                self.assertTrue(error.exception.__suppress_context__)

    async def test_supervisor_cancellation_is_not_converted_to_a_connection_error(self):
        self.transport.ingress_context = ("admin-user", "esphome", "synthetic_session")
        self.ha.ingress_user_is_admin = AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await self.transport._discover()

    async def test_startup_refresh_handles_authorization_denial(self):
        self.transport.ingress_context = ("admin-user", "esphome", "synthetic_session")
        self.ha.ingress_user_is_admin = AsyncMock(return_value=False)
        self.ha.websocket_command = AsyncMock(side_effect=RuntimeError("Unauthorized"))
        client = APP.DeviceBuilderProtocol(self.transport)
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        admin.registry = SimpleNamespace(
            esphome_connection=Mock(return_value={"mode": "local_ingress"}),
            mark_esphome_connection_error=Mock(),
        )
        admin.device_builder_client = Mock(return_value=client)
        with self.assertLogs(APP.LOGGER, level="WARNING") as captured:
            await admin.refresh_device_builder_cache()
        self.assertEqual(captured.output, [
            "WARNING:fingerprint_admin:Device Builder refresh failed: unauthorized",
        ])
        admin.registry.mark_esphome_connection_error.assert_not_called()

    async def test_legacy_dashboard_denial_updates_connection_status(self):
        self.transport._websocket_command = AsyncMock(side_effect=APP._LegacyDashboardRequired)
        self.transport._legacy_dashboard_command = AsyncMock(
            side_effect=APP.DeviceBuilderError("Denied", "unauthorized"),
        )
        with self.assertRaises(APP.DeviceBuilderError):
            await self.transport.command("devices/list")
        self.assertEqual(self.transport.status["status"], "unauthorized")

    async def test_missing_or_invalid_exit_code_is_never_a_success(self):
        class Socket:
            def __init__(self, code): self.code = code
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
            async def send_json(self, value): pass
            async def messages(self):
                yield SimpleNamespace(type=APP.WSMsgType.TEXT, data=json.dumps({"event": "exit", **self.code}))
            def __aiter__(self): return self.messages()
        class Session:
            def __init__(self, code): self.code = code
            async def __aenter__(self): return self
            async def __aexit__(self, *args): return False
            def ws_connect(self, *args, **kwargs): return Socket(self.code)
        self.transport._dashboard_context = AsyncMock(return_value=("http://supervisor/ingress/synthetic/", {}))
        for code in ({}, {"code": None}, {"code": False}, {"code": "unknown"}):
            with self.subTest(code=code), patch.object(APP, "ClientSession", return_value=Session(code)):
                with self.assertRaises(APP.DeviceBuilderError):
                    await self.transport._dashboard_process("run", {"configuration": "front.yaml"})
        with patch.object(APP, "ClientSession", return_value=Session({"code": 0})):
            result = await self.transport._dashboard_process("run", {"configuration": "front.yaml"})
            self.assertTrue(result["install_completed"])


class FirmwareSubmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(APP, "DATA_DIR", Path(self.tmp.name))
        self.data_patch.start()
        self.registry = APP.Registry(Path(self.tmp.name) / "jobs.db")
        self.admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        self.admin.registry = self.registry
        self.admin.firmware_update_locks = {}
        self.admin.firmware_tasks = set()
        self.admin.start_firmware_follow = Mock()

    async def asyncTearDown(self):
        self.registry.connection.close()
        self.data_patch.stop()
        self.tmp.cleanup()

    def request(self, payload):
        return SimpleNamespace(headers={"X-Fingerprint-Admin": "1"}, json=AsyncMock(return_value=payload), match_info={"reader_id": "front"})

    async def test_build_rejects_duplicate_while_submitting_and_running(self):
        self.admin.esphome_preview_data = AsyncMock(return_value={"configuration": "front.yaml", "collision": None, "exists": False, "yaml": "synthetic"})
        submitted, release = asyncio.Event(), asyncio.Event()
        async def command(name, args):
            if name == "devices/create":
                submitted.set()
                await release.wait()
                return {"ok": True}
            return {"job_id": "remote-job"}
        client = SimpleNamespace(command=AsyncMock(side_effect=command))
        self.admin.device_builder_client = Mock(return_value=client)
        request = self.request({"device_name": "front"})
        first = asyncio.create_task(self.admin.build_esphome_firmware(request))
        await submitted.wait()
        with self.assertRaises(APP.web.HTTPConflict):
            await self.admin.build_esphome_firmware(request)
        release.set()
        self.assertEqual((await first).status, 200)
        with self.assertRaises(APP.web.HTTPConflict):
            await self.admin.build_esphome_firmware(request)
        self.assertEqual([call.args[0] for call in client.command.await_args_list], ["devices/create", "firmware/compile"])

    async def test_managed_update_rejects_an_existing_configuration_job(self):
        self.registry.create_firmware_operation("busy", "front.yaml", True)
        self.admin.canonical_reader_firmware_preflight = AsyncMock(return_value={"configuration": "front.yaml", "config_sha256": "a" * 64, "update_state": "up_to_date"})
        self.admin.device_builder_client = Mock()
        with self.assertRaises(APP.web.HTTPConflict):
            await self.admin.apply_reader_firmware_update(self.request({"expected_config_sha256": "a" * 64}))
        self.admin.device_builder_client.assert_not_called()

    async def test_follow_task_is_deduplicated(self):
        del self.admin.start_firmware_follow
        release = asyncio.Event()
        async def follow(operation):
            await release.wait()
        self.admin.follow_device_builder_operation = AsyncMock(side_effect=follow)
        first = self.admin.start_firmware_follow("same")
        second = self.admin.start_firmware_follow("same")
        self.assertIs(first, second)
        release.set()
        await first
        self.admin.follow_device_builder_operation.assert_awaited_once_with("same")

    async def test_active_job_detection_is_not_limited_to_latest_fifty(self):
        self.registry.create_firmware_operation("active", "front.yaml", False)
        for index in range(55):
            self.registry.create_firmware_operation(str(index), "other.yaml", False)
        self.assertTrue(self.registry.has_active_firmware_operation("front.yaml"))
        self.registry.update_firmware_operation("active", status="completed_verified")
        self.assertFalse(self.registry.has_active_firmware_operation("front.yaml"))

    async def test_conflicting_person_link_does_not_leave_a_partial_identity(self):
        first = self.registry.create_linked_person("First", "person.example", "stable-a")
        with self.assertRaises(ValueError):
            self.registry.create_linked_person("Second", "person.example", "stable-a")
        self.assertIsNone(self.registry.person_by_name("Second"))
        self.assertEqual(self.registry.person(first)["ha_person_id"], "stable-a")
        self.assertEqual(len(self.registry.people()), 1)

    async def test_new_keypad_credentials_require_a_confirmed_person_link(self):
        person = self.registry.create_person("Synthetic")
        self.registry.create_reader("keypad", "Synthetic keypad", "keypad", None, {})
        self.admin.capture_sessions = {}
        for state in ("unlinked", "missing", "unknown"):
            with self.registry.connection:
                self.registry.connection.execute("UPDATE people SET ha_person_entity_id = ?, ha_link_status = ? WHERE id = ?", (None if state == "unlinked" else "person.synthetic", state, person))
            for handler in (self.admin.start_keypad_capture, self.admin.create_keypad_credential):
                with self.assertRaises(APP.web.HTTPConflict):
                    await handler(self.request({"person_id": person, "reader_id": "keypad", "code": "synthetic"}))
        self.assertEqual(self.registry.keypad_credentials(), [])
        self.assertEqual(self.admin.capture_sessions, {})


class DeviceProjectionTests(unittest.TestCase):
    def test_invalid_nested_reader_configuration_is_rejected(self):
        admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        for config in ([], None, {"slot_entity": ["number.synthetic"]}, {"transaction_entity": {"id": "sensor.synthetic"}}):
            with self.subTest(config=config), self.assertRaises(APP.web.HTTPBadRequest):
                admin.validate_reader_config("fingerprint", config)

    def test_legacy_discovery_supports_current_and_original_firmware_names(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(APP, "DATA_DIR", Path(directory)):
            registry = APP.Registry(Path(directory) / "reader.db")
            self.addCleanup(registry.connection.close)
            registry.create_reader("display1", "Synthetic", "fingerprint", None, {"legacy_autodiscovery": True})
            ha = APP.HomeAssistant(registry)
            for index in (0, 1):
                ha.states = {f"{APP.DOMAINS[key]}.display1_{APP.normalized(labels[index if len(labels) > index else 0]).replace(' ', '_')}": {"state": "on", "attributes": {}}
                             for key, labels in APP.LABELS.items()}
                ha.resolve_entities()
                self.assertTrue(ha.reader_ready("display1"))
                for key in ("slot", "enroll", "cancel", "delete", "name_registry", "access_event", "management_event", "device_status"):
                    self.assertIn(ha.reader_entity("display1", key), ha.states)

    def test_nested_runtime_and_legacy_shapes_are_supported_without_leaking_fields(self):
        devices = APP.FingerprintAdmin.public_esphome_devices({"devices": [
            {"configuration": "front.yaml", "runtime_state": {"state": "online", "api_encryption_key": "never-export"}, "state": "offline"},
            {"configuration": "back.yaml", "state": "offline"},
            {"configuration": "bad.yaml", "runtime_state": {"state": {"secret": "never-export"}}},
        ]})
        by_name = {item["configuration"]: item for item in devices}
        self.assertEqual(by_name["front.yaml"]["state"], "online")
        self.assertEqual(by_name["back.yaml"]["state"], "offline")
        self.assertEqual(by_name["bad.yaml"]["state"], "")
        self.assertNotIn("never-export", str(devices))


if __name__ == "__main__":
    unittest.main()

import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiohttp.test_utils import TestClient, TestServer


SPEC = importlib.util.spec_from_file_location(
    "access_manager_security", Path(__file__).parents[1] / "access_manager/app/main.py"
)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


def ha_user(**changes):
    return {
        "id": "admin-user", "is_active": True, "is_owner": False,
        "system_generated": False, "group_ids": ["system-admin"], **changes,
    }


class IngressPeerTests(unittest.TestCase):
    def test_only_the_actual_supervisor_peer_is_trusted(self):
        for peer, expected in (
            (("172.30.32.2", 40000), True),
            (("::ffff:172.30.32.2", 40000, 0, 0), True),
            (("172.30.33.5", 40000), False),
            (("192.168.1.10", 40000), False),
            (("127.0.0.1", 40000), False),
            (("::1", 40000, 0, 0), False),
            (("not-an-ip", 40000), False),
            (None, False),
            ("172.30.32.2", False),
        ):
            with self.subTest(peer=peer):
                request = SimpleNamespace(
                    transport=Mock(get_extra_info=Mock(return_value=peer)),
                    remote="172.30.32.2",
                    headers={"X-Forwarded-For": "172.30.32.2", "X-Remote-User-Id": "admin-user"},
                )
                self.assertEqual(APP.request_from_ingress(request), expected)
        self.assertFalse(APP.request_from_ingress(SimpleNamespace(transport=None)))


class AdminRoleTests(unittest.IsolatedAsyncioTestCase):
    async def test_current_active_human_admin_or_owner_only(self):
        ha = APP.HomeAssistant(None)
        for users, expected in (
            ([ha_user()], True),
            ([ha_user(is_owner=True, group_ids=[])], True),
            ([ha_user(group_ids=["system-users"])], False),
            ([ha_user(is_active=False)], False),
            ([ha_user(system_generated=True)], False),
            ([ha_user(is_active="true")], False),
            ([ha_user(group_ids="system-admin")], False),
            ([ha_user(id="someone-else")], False),
            ([ha_user(), ha_user()], False),
            ([], False),
        ):
            with self.subTest(users=users):
                ha.websocket_command = AsyncMock(return_value=users)
                self.assertEqual(await ha.ingress_user_is_admin("admin-user"), expected)
                ha.websocket_command.assert_awaited_once_with({"type": "config/auth/list"})

    async def test_malformed_upstream_result_fails_closed(self):
        ha = APP.HomeAssistant(None)
        ha.websocket_command = AsyncMock(return_value={"is_admin": True})
        with self.assertRaises(RuntimeError):
            await ha.ingress_user_is_admin("admin-user")

    async def test_revoked_admin_rights_are_not_cached(self):
        ha = APP.HomeAssistant(None)
        ha.websocket_command = AsyncMock(side_effect=[
            [ha_user()], [ha_user(group_ids=["system-users"])],
        ])
        self.assertTrue(await ha.ingress_user_is_admin("admin-user"))
        self.assertFalse(await ha.ingress_user_is_admin("admin-user"))

    async def test_authorization_cancellation_is_propagated(self):
        ha = APP.HomeAssistant(None)
        ha.websocket_command = AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await ha.ingress_user_is_admin("admin-user")


class IngressHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_patch = patch.object(APP, "DATA_DIR", Path(self.tmp.name))
        self.data_patch.start()
        self.admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        self.admin.registry = APP.Registry(Path(self.tmp.name) / "security.db")
        self.admin.ha = APP.HomeAssistant(self.admin.registry)
        self.admin.ha.websocket_command = AsyncMock(return_value=[ha_user()])
        app = self.admin.application()
        # Exercise the real router/middleware without HA connections/background jobs.
        app.on_startup.clear()
        app.on_cleanup.clear()
        self.client = TestClient(TestServer(app))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.admin.registry.connection.close()
        self.data_patch.stop()
        self.tmp.cleanup()

    async def test_direct_requests_cannot_bypass_auth_with_forged_headers(self):
        headers = {
            "X-Fingerprint-Admin": "1", "X-Remote-User-Id": "admin-user",
            "X-Forwarded-For": "172.30.32.2", "X-Real-IP": "172.30.32.2",
            "Forwarded": "for=172.30.32.2", "X-Ingress-Path": "/api/hassio_ingress/fake",
        }
        for method, path in (
            ("GET", "/"), ("GET", "/health"), ("GET", "/api/state"),
            ("GET", "/assets/missing.png"), ("POST", "/api/people"),
            ("PUT", "/api/settings/log-retention"), ("DELETE", "/api/people/1"),
        ):
            with self.subTest(method=method, path=path):
                response = await self.client.request(method, path, headers=headers, json={"days": 7})
                self.assertEqual(response.status, 403)
        self.admin.ha.websocket_command.assert_not_awaited()
        self.assertEqual(self.admin.registry.log_retention_days(), 30)
        self.assertEqual(self.admin.registry.people(), [])

    async def test_ingress_requires_a_single_identity_header(self):
        with patch.object(APP, "request_from_ingress", return_value=True):
            for headers in ({}, {"X-Remote-User-Id": " "}, [
                ("X-Remote-User-Id", "admin-user"), ("X-Remote-User-Id", "other"),
            ]):
                response = await self.client.get("/", headers=headers)
                self.assertEqual(response.status, 403)
        self.admin.ha.websocket_command.assert_not_awaited()

    async def test_admin_can_open_panel_but_writes_require_same_origin_marker(self):
        headers = {"X-Remote-User-Id": "admin-user"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            response = await self.client.get("/", headers=headers)
            self.assertEqual(response.status, 200)
            self.assertIn("no-store", response.headers["Cache-Control"])
            response = await self.client.put("/api/settings/log-retention", headers=headers, json={"days": 7})
            self.assertEqual(response.status, 403)
            self.assertEqual(self.admin.registry.log_retention_days(), 30)
            response = await self.client.put(
                "/api/settings/log-retention", json={"days": 7},
                headers={**headers, "X-Fingerprint-Admin": "1"},
            )
            self.assertEqual(response.status, 200)
            self.assertEqual(self.admin.registry.log_retention_days(), 7)

    async def test_non_admin_cannot_read_or_modify_the_panel(self):
        self.admin.ha.websocket_command.return_value = [ha_user(group_ids=["system-users"])]
        headers = {"X-Remote-User-Id": "admin-user", "X-Fingerprint-Admin": "1"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            for method, path in (("GET", "/api/state"), ("PUT", "/api/settings/log-retention")):
                response = await self.client.request(method, path, headers=headers, json={"days": 7})
                self.assertEqual(response.status, 403)
        self.assertEqual(self.admin.registry.log_retention_days(), 30)

    async def test_ha_failure_or_timeout_denies_access_without_leaking_details(self):
        headers = {"X-Remote-User-Id": "admin-user", "X-Fingerprint-Admin": "1"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            for error in (RuntimeError("sensitive-upstream-value"), TimeoutError()):
                self.admin.ha.websocket_command.side_effect = error
                response = await self.client.put("/api/settings/log-retention", headers=headers, json={"days": 7})
                self.assertEqual(response.status, 503)
                self.assertNotIn("sensitive-upstream-value", await response.text())
        self.assertEqual(self.admin.registry.log_retention_days(), 30)

    async def test_malformed_or_non_object_json_never_reaches_a_mutation(self):
        headers = {"X-Remote-User-Id": "admin-user", "X-Fingerprint-Admin": "1", "Content-Type": "application/json"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            for payload in ('[]', 'null', '42', '"value"', '{"days":'):
                response = await self.client.put("/api/settings/log-retention", headers=headers, data=payload)
                self.assertEqual(response.status, 400)
        self.assertEqual(self.admin.registry.log_retention_days(), 30)

    async def test_invalid_path_ids_and_boolean_values_return_client_errors(self):
        headers = {"X-Remote-User-Id": "admin-user", "X-Fingerprint-Admin": "1"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            for identifier in ("invalid", "-1", "0", "9999999999999999999999999"):
                response = await self.client.delete(f"/api/people/{identifier}", headers=headers)
                self.assertEqual(response.status, 400)
            for field in ("enabled", "install", "confirm_overwrite", "acknowledge"):
                response = await self.client.put("/api/settings/log-retention", headers=headers, json={"days": 7, field: "false"})
                self.assertEqual(response.status, 400)
        self.assertEqual(self.admin.registry.log_retention_days(), 30)
        self.assertEqual(self.admin.registry.people(), [])


if __name__ == "__main__":
    unittest.main()

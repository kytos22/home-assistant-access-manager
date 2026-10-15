import ast
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiohttp.test_utils import TestClient, TestServer
from ruamel.yaml import YAML


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_diagnostic", ROOT / "tools/prepare_ingress_diagnostic.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


def load_diagnostic():
    module = ModuleType("isolated_diagnostic")
    exec(compile(PREPARE.diagnostic_source(PREPARE.SOURCE.read_text()), "isolated_diagnostic", "exec"), module.__dict__)
    return module


class DiagnosticPackageTests(unittest.TestCase):
    def test_endpoint_constants_follow_candidate_without_local_overrides(self):
        source = PREPARE.SOURCE.read_text().replace('HA_WS = "ws://supervisor/core/websocket"', 'HA_WS = "ws://synthetic/core/websocket"')
        generated = PREPARE.diagnostic_source(source)
        self.assertIn("ws://synthetic/core/websocket", generated)
        self.assertNotIn("ws://supervisor/core/websocket", generated)

    def test_extracted_authorization_is_identical_to_candidate(self):
        original = ast.parse(PREPARE.SOURCE.read_text())
        generated = ast.parse(PREPARE.diagnostic_source(PREPARE.SOURCE.read_text()))
        for original_owner, generated_owner, names in (
            (None, None, ["request_from_ingress"]),
            ("HomeAssistant", "CandidateAuthClient", ["websocket_command", "_websocket_command_once", "ingress_user_is_admin"]),
            ("FingerprintAdmin", "CandidateGate", ["require_admin_request", "ingress_authentication"]),
        ):
            for name in names:
                first = ast.parse(PREPARE.definition(original, original_owner, name))
                second = ast.parse(PREPARE.definition(generated, generated_owner, name))
                self.assertEqual(ast.dump(first), ast.dump(second))

    def test_fresh_package_has_no_shared_mounts_or_production_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "diagnostic"
            destination, review = PREPARE.prepare(target)
            config = YAML(typ="safe").load((destination / "config.yaml").read_text())
            self.assertEqual(config["slug"], PREPARE.SLUG)
            self.assertEqual(config["boot"], "manual")
            # Non-admin visibility lets us prove rejection in the app, not just HA's UI.
            self.assertIs(config["panel_admin"], False)
            for key in ("map", "ports", "host_network", "hassio_api", "docker_api", "privileged", "devices", "full_access"):
                self.assertNotIn(key, config)
            self.assertEqual(set(path.name for path in destination.iterdir()), {"config.yaml", "Dockerfile", "diagnostic.py", "review.json"})
            self.assertFalse(review["installed"])
            dockerfile = (destination / "Dockerfile").read_text()
            command = next(line[4:] for line in dockerfile.splitlines() if line.startswith("CMD "))
            self.assertEqual(json.loads(command), ["/usr/bin/with-contenv", "python3", "/app/diagnostic.py"])
            for name, digest in review["files_sha256"].items():
                self.assertEqual(hashlib.sha256((destination / name).read_bytes()).hexdigest(), digest)
            with self.assertRaises(FileExistsError):
                PREPARE.prepare(target)

    def test_runtime_has_no_database_or_full_app_import(self):
        generated = PREPARE.diagnostic_source(PREPARE.SOURCE.read_text())
        tree = ast.parse(generated)
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules.add(node.module)
        self.assertEqual(modules, {"asyncio", "ipaddress", "json", "os", "re", "aiohttp"})
        self.assertNotIn("Registry", generated)
        self.assertNotIn("FingerprintAdmin", generated)
        self.assertNotIn("/data", generated)


class DiagnosticHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_start_only_allocates_a_session_and_close_releases_it(self):
        client = self.module.ReadOnlyAuthClient()
        session = Mock(close=AsyncMock())
        with patch.object(self.module, "TOKEN", "synthetic-token"), patch.object(self.module, "ClientSession", return_value=session) as constructor:
            await client.start()
            constructor.assert_called_once()
            session.ws_connect.assert_not_called()
            self.assertIs(client.session, session)
            await client.close()
            session.close.assert_awaited_once()
        with patch.object(self.module, "TOKEN", ""), patch.object(self.module, "ClientSession") as constructor:
            with self.assertRaises(RuntimeError):
                await self.module.ReadOnlyAuthClient().start()
            constructor.assert_not_called()

    async def asyncSetUp(self):
        self.module = load_diagnostic()
        self.auth = self.module.ReadOnlyAuthClient()
        self.auth._websocket_command_once = AsyncMock(return_value=[{
            "id": "synthetic-admin", "is_active": True, "is_owner": False,
            "system_generated": False, "group_ids": ["system-admin"],
        }])
        self.client = TestClient(TestServer(self.module.make_app(self.auth)))
        await self.client.start_server()
        self.headers = {"X-Remote-User-Id": "synthetic-admin"}

    async def asyncTearDown(self):
        await self.client.close()

    async def test_direct_peer_cannot_spoof_ingress(self):
        response = await self.client.get("/", headers={**self.headers, "X-Forwarded-For": "172.30.32.2", "X-Fingerprint-Admin": "1"})
        self.assertEqual(response.status, 403)
        self.auth._websocket_command_once.assert_not_awaited()

    async def test_admin_gets_only_sanitized_status(self):
        with patch.object(self.module, "request_from_ingress", return_value=True):
            response = await self.client.get("/health", headers=self.headers)
            self.assertEqual(response.status, 200)
            payload = await response.json()
            self.assertEqual(set(payload), {"ok", "result", "read_only", "candidate_sha256"})
            self.assertTrue(payload["read_only"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertNotIn("synthetic-admin", json.dumps(payload))
            response = await self.client.get("/", headers=self.headers)
            self.assertEqual(response.status, 200)
            self.assertIn("Authorized", await response.text())
        for call in self.auth._websocket_command_once.await_args_list:
            self.assertEqual(call.args, ({"type": "config/auth/list"},))

    async def test_revoked_nonadmin_inactive_and_system_accounts_are_denied(self):
        user = self.auth._websocket_command_once.return_value[0]
        with patch.object(self.module, "request_from_ingress", return_value=True):
            for changes in ({"group_ids": ["system-users"]}, {"is_active": False}, {"system_generated": True}):
                self.auth._websocket_command_once.return_value = [{**user, **changes}]
                response = await self.client.get("/", headers=self.headers)
                self.assertEqual(response.status, 403)
            self.auth._websocket_command_once.return_value = [user]
            self.assertEqual((await self.client.get("/", headers=self.headers)).status, 200)
            self.auth._websocket_command_once.return_value = [{**user, "group_ids": []}]
            self.assertEqual((await self.client.get("/", headers=self.headers)).status, 403)

    async def test_identity_headers_and_upstream_fail_closed_without_details(self):
        with patch.object(self.module, "request_from_ingress", return_value=True):
            for headers in ({}, {"X-Remote-User-Id": " "}, [("X-Remote-User-Id", "a"), ("X-Remote-User-Id", "b")]):
                self.assertEqual((await self.client.get("/", headers=headers)).status, 403)
            for result in (RuntimeError("private-value"), TimeoutError()):
                self.auth._websocket_command_once.side_effect = result
                response = await self.client.get("/", headers=self.headers)
                self.assertEqual(response.status, 503)
                self.assertNotIn("private-value", await response.text())
            self.auth._websocket_command_once.side_effect = None
            self.auth._websocket_command_once.return_value = {"invalid": True}
            self.assertEqual((await self.client.get("/", headers=self.headers)).status, 503)

    async def test_write_methods_and_other_commands_are_impossible(self):
        with patch.object(self.module, "request_from_ingress", return_value=True):
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                response = await self.client.request(method, "/health", headers=self.headers, json={"entity_id": "lock.synthetic"})
                self.assertEqual(response.status, 405)
        self.auth._websocket_command_once.assert_not_awaited()
        for command in ({"type": "call_service"}, {"type": "config/auth/list", "extra": True}, {"type": "subscribe_events"}):
            with self.assertRaises(RuntimeError):
                await self.auth.websocket_command(command)
        self.auth._websocket_command_once.assert_not_awaited()

    async def test_real_peer_check_matches_candidate(self):
        for address, expected in (("172.30.32.2", True), ("::ffff:172.30.32.2", True), ("127.0.0.1", False)):
            request = SimpleNamespace(transport=Mock(get_extra_info=Mock(return_value=(address, 1234))))
            self.assertEqual(self.module.request_from_ingress(request), expected)


if __name__ == "__main__":
    unittest.main()

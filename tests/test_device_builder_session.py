"""Offline delegation boundary tests; no real HA, credentials or devices."""
import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiohttp.test_utils import TestClient, TestServer
from multidict import CIMultiDict

SPEC = importlib.util.spec_from_file_location("access_manager_delegation", Path(__file__).parents[1] / "access_manager/app/main.py")
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class DelegationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.admin = APP.FingerprintAdmin.__new__(APP.FingerprintAdmin)
        self.admin.ha = SimpleNamespace(ingress_user_is_admin=AsyncMock(return_value=True))
        self.seen = []
        self.seen_info = []
        self.release = asyncio.Event()
        self.jobs = []

        async def inspect(request):
            context = APP.DEVICE_BUILDER_INGRESS.get()
            self.seen.append(context)
            self.seen_info.append(APP.DEVICE_BUILDER_METADATA.get())
            if request.query.get("job"):
                async def job():
                    await self.release.wait()
                    return APP.DEVICE_BUILDER_INGRESS.get()
                self.jobs.append(asyncio.create_task(job()))
            if request.query.get("fail"):
                raise APP.web.HTTPConflict(text="Synthetic failure")
            return APP.web.json_response({"ok": True, "has_session": context is not None})

        app = APP.web.Application(middlewares=[self.admin.ingress_authentication, self.admin.device_builder_ingress_context])
        app.router.add_get("/api/esphome/devices", inspect)
        app.router.add_get("/health", inspect)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.headers = {"X-Remote-User-Id":"admin-a", "X-Fingerprint-Admin":"1",
                        "X-Device-Builder-User":"admin-a", "X-Device-Builder-Addon":"custom_esphome",
                        "X-Device-Builder-Session":"synthetic_session_a"}
        self.headers["X-Device-Builder-Info"] = json.dumps({"slug":"custom_esphome", "name":"ESPHome Device Builder",
            "repository":"esphome", "state":"started", "ingress":True, "ingress_token":"synthetic_ingress",
            "version":"2026.9.1", "stage":"stable"})

    async def asyncTearDown(self):
        self.release.set()
        if self.jobs:
            await asyncio.gather(*self.jobs)
        await self.client.close()

    async def get(self, headers=None, path="/api/esphome/devices"):
        with patch.object(APP, "request_from_ingress", return_value=True):
            return await self.client.get(path, headers=headers or self.headers)

    async def test_valid_capability_only_reaches_its_request_and_job(self):
        response = await self.get(path="/api/esphome/devices?job=1")
        self.assertEqual(response.status, 200)
        body = await response.text()
        self.assertNotIn("synthetic_session", body)
        self.assertIsNone(APP.DEVICE_BUILDER_INGRESS.get())
        self.assertIsNone(APP.DEVICE_BUILDER_METADATA.get())
        response = await self.get({"X-Remote-User-Id":"admin-b"})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.seen, [("admin-a", "custom_esphome", "synthetic_session_a"), None])
        self.release.set()
        self.assertEqual(await self.jobs[0], self.seen[0])

    async def test_two_users_never_adopt_each_others_capability(self):
        other = {**self.headers, "X-Remote-User-Id":"admin-b", "X-Device-Builder-User":"admin-b",
                 "X-Device-Builder-Session":"synthetic_session_b"}
        with patch.object(APP, "request_from_ingress", return_value=True):
            responses = await asyncio.gather(self.client.get("/api/esphome/devices?job=1", headers=self.headers),
                                             self.client.get("/api/esphome/devices?job=1", headers=other))
        self.assertEqual([r.status for r in responses], [200, 200])
        self.release.set()
        values = await asyncio.gather(*self.jobs)
        self.assertEqual(set(values), {("admin-a", "custom_esphome", "synthetic_session_a"),
                                       ("admin-b", "custom_esphome", "synthetic_session_b")})

    async def test_forged_headers_do_not_bypass_direct_peer_or_non_admin_denial(self):
        response = await self.client.get("/api/esphome/devices", headers=self.headers)
        self.assertEqual(response.status, 403)
        self.admin.ha.ingress_user_is_admin.assert_not_awaited()
        self.admin.ha.ingress_user_is_admin.return_value = False
        response = await self.get()
        self.assertEqual(response.status, 403)
        self.assertEqual(self.seen, [])

    async def test_revoked_admin_and_authorization_outage_are_not_cached(self):
        self.admin.ha.ingress_user_is_admin.side_effect = [True, False, TimeoutError()]
        self.assertEqual((await self.get()).status, 200)
        self.assertEqual((await self.get()).status, 403)
        self.assertEqual((await self.get()).status, 503)
        self.assertEqual(len(self.seen), 1)

    async def test_mismatched_partial_duplicate_and_malformed_headers_fail_closed(self):
        cases = [{**self.headers, "X-Device-Builder-User":"admin-b"},
                 {key:value for key,value in self.headers.items() if key != "X-Device-Builder-Session"},
                 {**self.headers, "X-Device-Builder-Addon":"../../core"},
                 {**self.headers, "X-Device-Builder-Session":"bad;Cookie=1"},
                 list(self.headers.items()) + [("X-Device-Builder-Session", "synthetic_session_b")]]
        for headers in cases:
            with self.subTest(headers=type(headers).__name__):
                response = await self.get(headers)
                self.assertIn(response.status, {400, 403})
                self.assertNotIn("synthetic_session", await response.text())
        self.assertEqual(self.seen, [])

    async def test_session_is_rejected_on_unrelated_routes_and_cleared_after_error(self):
        self.assertEqual((await self.get(path="/health")).status, 400)
        self.assertEqual((await self.get(path="/api/esphome/devices?fail=1")).status, 409)
        self.assertEqual((await self.get({"X-Remote-User-Id":"admin-b"})).status, 200)
        self.assertIsNone(self.seen[-1])
        self.assertIsNone(APP.DEVICE_BUILDER_INGRESS.get())

    async def test_cancellation_restores_previous_context(self):
        request = SimpleNamespace(headers=CIMultiDict(self.headers), path="/api/esphome/devices")
        handler = AsyncMock(side_effect=asyncio.CancelledError)
        with self.assertRaises(asyncio.CancelledError):
            await self.admin.device_builder_ingress_context(request, handler)
        self.assertIsNone(APP.DEVICE_BUILDER_INGRESS.get())
        self.assertIsNone(APP.DEVICE_BUILDER_METADATA.get())

    async def test_metadata_is_bounded_validated_and_not_shared(self):
        good=json.loads(self.headers['X-Device-Builder-Info'])
        for invalid in ('[]','not json','x'*4097,json.dumps({**good,'slug':'other'}),
                        json.dumps({**good,'ingress_token':'bad;Cookie=1'}),
                        json.dumps({**good,'private_options':{'password':'synthetic_private'}})):
            response=await self.get({**self.headers,'X-Device-Builder-Info':invalid})
            self.assertEqual(response.status,400)
            self.assertNotIn('synthetic_private',await response.text())
        self.assertEqual(self.seen,[])
        self.assertEqual((await self.get()).status,200)
        self.assertEqual((await self.get({'X-Remote-User-Id':'admin-b'})).status,200)
        self.assertEqual(self.seen_info,[good,None])


class LocalTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_has_no_capability_and_cannot_query_or_create_a_session(self):
        ha = SimpleNamespace(supervisor_api=AsyncMock())
        transport = APP.HomeAssistantIngressTransport(ha)
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await transport.command("devices/list")
        self.assertEqual(error.exception.code, "session_required")
        ha.supervisor_api.assert_not_awaited()

    async def test_backend_cannot_invoke_admin_supervisor_operations(self):
        ha = APP.HomeAssistant(None)
        ha.websocket_command = AsyncMock()
        for method, endpoint in (("GET", "/addons"), ("POST", "/ingress/session"),
                                 ("POST", "/addons/esphome/start"), ("GET", "/core/info"),
                                 ("GET", "/addons/custom_esphome/info")):
            with self.assertRaises(APP.DeviceBuilderError):
                await ha.supervisor_api(method, endpoint)
        ha.websocket_command.assert_not_awaited()

    async def test_metadata_is_revalidated_and_only_public_status_is_retained(self):
        ha = SimpleNamespace(supervisor_api=AsyncMock(return_value={"name":"ESPHome Device Builder", "state":"started", "ingress":True}))
        ha.ingress_user_is_admin = AsyncMock(return_value=True)
        receipt = APP.DEVICE_BUILDER_INGRESS.set(("admin-a", "custom_esphome", "synthetic_session_a"))
        try:
            transport = APP.HomeAssistantIngressTransport(ha)
        finally:
            APP.DEVICE_BUILDER_INGRESS.reset(receipt)
        transport.addon_info = {"name":"ESPHome Device Builder", "state":"started", "ingress":True}
        self.assertEqual((await transport._discover())["slug"], "custom_esphome")
        self.assertEqual(await transport._session(), "synthetic_session_a")
        ha.supervisor_api.assert_not_awaited()
        self.assertNotIn("synthetic_session", repr(vars(ha)))
        transport.addon_info = {"name":"Different app", "state":"started", "ingress":True}
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await transport._discover()
        self.assertEqual(error.exception.code, "incompatible")

    async def test_dashboard_error_bodies_never_expose_capabilities(self):
        for code in (401, 403, 500):
            error = APP.HomeAssistantIngressTransport._request_error(code, "synthetic_session_a")
            self.assertNotIn("synthetic_session", str(error))

    async def test_upstream_rejects_forged_or_expired_session_without_submitting(self):
        ha = SimpleNamespace(supervisor_api=AsyncMock(return_value={"name":"ESPHome Device Builder", "state":"started",
            "ingress":True, "ingress_entry":"/api/hassio_ingress/synthetic_ingress"}))
        ha.ingress_user_is_admin = AsyncMock(return_value=True)
        transport = APP.HomeAssistantIngressTransport(ha)
        transport.ingress_context = ("admin-a", "custom_esphome", "synthetic_expired_session")
        transport.addon_info = ha.supervisor_api.return_value
        socket = Mock(side_effect=APP.WSServerHandshakeError(None, (), status=401))
        session = SimpleNamespace(ws_connect=socket)
        manager = AsyncMock()
        manager.__aenter__.return_value = session
        transport._legacy_dashboard_command = AsyncMock()
        with patch.object(APP, "ClientSession", return_value=manager):
            with self.assertRaises(APP.DeviceBuilderError) as error:
                await transport.command("devices/list")
        self.assertEqual(error.exception.code, "unauthorized")
        transport._legacy_dashboard_command.assert_not_awaited()
        self.assertNotIn("synthetic_expired", str(error.exception))

    async def test_job_capability_cannot_outlive_current_administrator_rights(self):
        ha = SimpleNamespace(ingress_user_is_admin=AsyncMock(return_value=False), supervisor_api=AsyncMock())
        transport = APP.HomeAssistantIngressTransport(ha)
        transport.ingress_context = ("admin-a", "custom_esphome", "synthetic_session_a")
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await transport.command("devices/list")
        self.assertEqual(error.exception.code, "unauthorized")
        ha.supervisor_api.assert_not_awaited()

    async def test_finished_job_releases_capability_and_does_not_retain_task(self):
        ha = SimpleNamespace(dashboard_jobs={})
        transport = APP.HomeAssistantIngressTransport(ha)
        transport.ingress_context = ("admin-a", "custom_esphome", "synthetic_session_a")
        transport._dashboard_process = AsyncMock(return_value={"success":True})
        receipt = APP.DEVICE_BUILDER_INGRESS.set(transport.ingress_context)
        try:
            job = await transport._legacy_dashboard_command("firmware/compile", {"configuration":"synthetic.yaml"})
        finally:
            APP.DEVICE_BUILDER_INGRESS.reset(receipt)
        await transport._follow_dashboard_job(job["job_id"])
        self.assertIsNone(transport.ingress_context)
        self.assertNotIn("task", ha.dashboard_jobs[job["job_id"]])
        self.assertNotIn("synthetic_session", repr(ha.dashboard_jobs))

    async def test_missing_delegated_metadata_fails_without_any_supervisor_request(self):
        ha=SimpleNamespace(ingress_user_is_admin=AsyncMock(return_value=True),supervisor_api=AsyncMock())
        transport=APP.HomeAssistantIngressTransport(ha)
        transport.ingress_context=("admin-a","custom_esphome","synthetic_session_a")
        with self.assertRaises(APP.DeviceBuilderError) as error:
            await transport.command("devices/list")
        self.assertEqual(error.exception.code,"ingress_unavailable")
        ha.supervisor_api.assert_not_awaited()

    async def test_backend_has_no_frontend_supervisor_command_construction(self):
        source=Path(APP.__file__).read_text()
        self.assertNotIn('"type": "supervisor/api"',source)

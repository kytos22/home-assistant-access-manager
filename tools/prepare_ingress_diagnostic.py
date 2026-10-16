"""Prepare an isolated diagnostic from candidate auth code; never install it."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "access_manager/app/main.py"
SLUG = "access_manager_ingress_diagnostic"


def definition(tree, owner, name):
    nodes = tree.body
    if owner:
        nodes = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == owner).body
    node = next(node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)
    return ast.unparse(node)


def diagnostic_source(source):
    tree = ast.parse(source)
    # Extract, do not import main.py: importing/starting the full app is forbidden.
    peer = definition(tree, None, "request_from_ingress")
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {"INGRESS_PROXY", "HA_WS"}:
                constants[node.targets[0].id] = ast.unparse(node)
    if set(constants) != {"INGRESS_PROXY", "HA_WS"}:
        raise ValueError("Candidate authorization constants are missing")
    client = "\n\n".join(definition(tree, "HomeAssistant", name) for name in (
        "websocket_command", "_websocket_command_once", "ingress_user_is_admin",
    ))
    middleware = "\n\n".join(definition(tree, "FingerprintAdmin", name) for name in (
        "require_admin_request", "ingress_authentication",
    ))
    digest = hashlib.sha256(source.encode()).hexdigest()
    header = '''# Generated from the candidate; contains authorization code only.
import asyncio
import ipaddress
import json
import os
import re
from aiohttp import ClientSession, ClientTimeout, web

TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
'''
    scaffold = '''
class ReadOnlyAuthClient(CandidateAuthClient):
    def __init__(self):
        self.session = None

    async def websocket_command(self, command):
        if command != {"type": "config/auth/list"}:
            raise RuntimeError("Only the authorization lookup is permitted")
        return await super().websocket_command(command)

    async def start(self):
        if not TOKEN:
            raise RuntimeError("Supervisor authorization is unavailable")
        self.session = ClientSession(timeout=ClientTimeout(total=15))

    async def close(self):
        if self.session is not None:
            await self.session.close()


class Diagnostic(CandidateGate):
    def __init__(self, client):
        self.ha = client

    async def status(self, request):
        return web.json_response({"ok": True, "result": "authorized", "read_only": True,
                                  "candidate_sha256": CANDIDATE_SHA256})

    async def index(self, request):
        return web.Response(text=PAGE, content_type="text/html")


@web.middleware
async def read_only_boundary(request, handler):
    try:
        if request.method not in {"GET", "HEAD"}:
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD"])
        response = await handler(request)
    except web.HTTPException as error:
        response = web.json_response({"ok": False, "result": "unavailable" if error.status == 503 else "denied"}, status=error.status)
    except Exception:
        response = web.json_response({"ok": False, "result": "unavailable"}, status=503)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
    return response


PAGE = """<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Manager · Ingress diagnostic</title>
<style>body{font:16px system-ui;background:#0b1722;color:#e2edf5;margin:0;padding:24px}main{max-width:650px;margin:8vh auto;padding:28px;border:1px solid #355264;border-radius:16px;background:#132535}h1{font-size:1.6rem}strong{color:#6fe0bd}p{line-height:1.6}small{color:#a5bdce}</style>
<main><h1>Access Manager · Ingress</h1><p><strong>Acceso autorizado / Authorized</strong></p>
<p>La conexión procede del proxy de Ingress y Home Assistant confirma que esta sesión pertenece a un administrador activo.</p>
<p>The Ingress proxy and current active administrator authorization checks passed.</p>
<p>Solo lectura: sin base de datos, lectores ni puertas.<br>Read only: no database, readers or doors.</p>
<small>Este resultado no valida la migración, el panel completo ni OTA. This does not validate migration, the full panel or OTA.</small></main></html>"""


def make_app(client=None):
    owned = client is None
    client = client if client is not None else ReadOnlyAuthClient()
    diagnostic = Diagnostic(client)
    app = web.Application(client_max_size=1024, middlewares=[read_only_boundary, diagnostic.ingress_authentication])
    app.router.add_get("/", diagnostic.index)
    app.router.add_get("/health", diagnostic.status)
    if owned:
        async def lifetime(app):
            await client.start()
            try:
                yield
            finally:
                await client.close()
        app.cleanup_ctx.append(lifetime)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host="0.0.0.0", port=8099, access_log=None, print=None)
'''
    result = (header + "\n".join(constants.values()) + f"\nCANDIDATE_SHA256 = {digest!r}\n\n" + peer
              + "\n\nclass CandidateAuthClient:\n" + textwrap.indent(client, "    ")
              + "\n\nclass CandidateGate:\n" + textwrap.indent(middleware, "    ")
              + "\n" + textwrap.dedent(scaffold))
    compile(result, "diagnostic.py", "exec")
    return result


def prepare(output=None):
    source = SOURCE.read_text(encoding="utf-8")
    application = diagnostic_source(source)
    # A fresh directory only: never overwrite an installed app or existing data.
    destination = Path(tempfile.mkdtemp(prefix="access-manager-ingress-")) if output is None else Path(output)
    if output is not None:
        destination.mkdir(parents=False, exist_ok=False)
    files = {
        "diagnostic.py": application,
        "config.yaml": '''name: "Access Manager Ingress Diagnostic (temporary)"
version: "0.1.0"
slug: "access_manager_ingress_diagnostic"
description: "Temporary read-only authorization diagnostic, no reader or door functions"
arch: [aarch64, amd64, armv7]
startup: application
boot: manual
init: false
ingress: true
ingress_port: 8099
panel_admin: false
panel_icon: mdi:shield-check
panel_title: "Access diagnostic"
homeassistant_api: true
options: {}
schema: {}
''',
        "Dockerfile": '''FROM ghcr.io/home-assistant/base-python:3.13-alpine3.24
RUN python3 -m pip install --no-cache-dir aiohttp==3.14.1
COPY diagnostic.py /app/diagnostic.py
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["/usr/bin/with-contenv", "python3", "/app/diagnostic.py"]
''',
    }
    for name, content in files.items():
        (destination / name).write_text(content, encoding="utf-8")
    metadata = {
        "candidate_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "files_sha256": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()},
        "installed": False,
        "scope": "Authorization lookup only; no registry, event subscriptions, readers or door actions",
    }
    (destination / "review.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return destination, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New directory only; omit for a unique temporary directory")
    args = parser.parse_args()
    destination, metadata = prepare(args.output)
    print(json.dumps({"prepared_directory": str(destination), **metadata}, indent=2))

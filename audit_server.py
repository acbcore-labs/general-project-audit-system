from __future__ import annotations

import json
import mimetypes
import os
import re
import signal
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from audit_db import AuditDB


UI_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui"))
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB upper bound to prevent OOM DoS (F-22)
ALLOWED_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", re.IGNORECASE)
ALLOWED_HOST_RE = re.compile(r"^(localhost|127\.0\.0\.1)(:\d+)?$", re.IGNORECASE)


def is_allowed_origin(origin: Optional[str]) -> bool:
    """Allow same-machine localhost origins or absent/null local file origins; block external websites (F-01)."""
    if not origin or origin == "null":
        return True
    return bool(ALLOWED_ORIGIN_RE.match(origin.strip()))


def is_allowed_host(host: Optional[str]) -> bool:
    """Validate Host header to prevent DNS rebinding attacks against 127.0.0.1 (RF-02)."""
    if not host:
        return True
    return bool(ALLOWED_HOST_RE.match(host.strip()))


class AuditRequestHandler(BaseHTTPRequestHandler):
    db: AuditDB = None  # type: ignore
    timeout = 30.0  # Prevent Slowloris stalled socket hangs (F-22)

    def log_message(self, format: str, *args: Any) -> None:
        if os.environ.get("AUDIT_DEBUG"):
            super().log_message(format, *args)

    def _apply_cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        else:
            self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8420")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Agent-Id")

    def _check_origin_and_csrf(self, is_mutation: bool = False) -> bool:
        """Enforce localhost Host, Origin, and Sec-Fetch-Site checks against DNS rebinding, exfiltration & CSRF (F-01, F-05, RF-02)."""
        host = self.headers.get("Host")
        if host and not is_allowed_host(host):
            self._send_json(
                {"error": f"Invalid Host header '{host}': DNS rebinding protection blocked request."},
                status=403,
            )
            return False

        origin = self.headers.get("Origin")
        if origin and not is_allowed_origin(origin):
            self._send_json(
                {"error": f"Cross-origin request from '{origin}' is forbidden."},
                status=403,
            )
            return False

        sec_fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_fetch_site == "cross-site":
            self._send_json(
                {"error": "Cross-site requests (Sec-Fetch-Site: cross-site) are forbidden."},
                status=403,
            )
            return False

        if is_mutation:
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                self._send_json(
                    {"error": "Mutating requests require 'Content-Type: application/json'."},
                    status=415,
                )
                return False
        return True

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._apply_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, text: str, content_type: str = "text/plain; charset=utf-8", status: int = 200) -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._apply_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> Dict[str, Any]:
        raw_len = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_len)
        except ValueError:
            raise ValueError("Invalid Content-Length header.")
        if length < 0:
            raise ValueError("Negative Content-Length header.")
        if length > MAX_BODY_BYTES:
            raise OverflowError(f"Request body exceeds maximum allowed size of {MAX_BODY_BYTES} bytes.")
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("JSON request body must be an object.")
        return parsed

    def do_OPTIONS(self) -> None:
        host = self.headers.get("Host")
        origin = self.headers.get("Origin")
        if (host and not is_allowed_host(host)) or (origin and not is_allowed_origin(origin)):
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._apply_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_origin_and_csrf(is_mutation=False):
            return

        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        def q1(key: str, default: Optional[str] = None) -> Optional[str]:
            vals = qs.get(key)
            return vals[0] if vals else default

        try:
            if path == "/api/health":
                self._send_json({"ok": True, "database": os.path.basename(self.db.db_path)})
                return

            if path == "/api/snapshot":
                project_ref = q1("project")
                snap = self.db.get_project_snapshot(project_ref)
                self._send_json(snap)
                return

            if path == "/api/board":
                project_ref = q1("project")
                board = self.db.get_blackboard(project_ref)
                self._send_json(board)
                return

            if path == "/api/sweep":
                project_ref = q1("project")
                res = self.db.run_sweep(project_ref=project_ref, auto_fix=False)
                self._send_json(res)
                return

            if path == "/api/roles":
                pid = self.db.resolve_project_id(q1("project")) if q1("project") else None
                self._send_json(self.db.list_roles(pid))
                return

            if path == "/api/checkpoints":
                pid = self.db.resolve_project_id(q1("project")) if q1("project") else None
                limit = int(q1("limit", "50") or "50")
                self._send_json(
                    {
                        "checkpoints": self.db.list_checkpoints(
                            project_id=pid,
                            agent_id=q1("agent"),
                            task_id=q1("task"),
                            limit=limit,
                        )
                    }
                )
                return

            if path == "/api/projects":
                self._send_json({"projects": self.db.list_projects()})
                return

            if path == "/api/agents":
                pid = self.db.resolve_project_id(q1("project")) if q1("project") else None
                self._send_json({"agents": self.db.list_agents(project_id=pid)})
                return

            if path == "/api/systems":
                pid = self.db.resolve_project_id(q1("project"))
                self._send_json({"systems": self.db.list_systems(pid)})
                return

            if path.startswith("/api/systems/"):
                sys_ref = path[len("/api/systems/") :].strip("/")
                pid = self.db.resolve_project_id(q1("project"))
                self._send_json(self.db.get_system(pid, sys_ref))
                return

            if path == "/api/relations":
                pid = self.db.resolve_project_id(q1("project"))
                self._send_json({"relations": self.db.list_relations(pid, system_ref=q1("system"))})
                return

            if path == "/api/tasks":
                pid = self.db.resolve_project_id(q1("project"))
                self._send_json(
                    {
                        "tasks": self.db.list_tasks(
                            pid,
                            status=q1("status"),
                            agent_id=q1("agent"),
                            system_ref=q1("system"),
                        )
                    }
                )
                return

            if path == "/api/findings":
                pid = self.db.resolve_project_id(q1("project"))
                self._send_json(
                    {
                        "findings": self.db.list_findings(
                            pid,
                            severity=q1("severity"),
                            category=q1("category"),
                            status=q1("status"),
                            system_ref=q1("system"),
                            agent_id=q1("agent"),
                        )
                    }
                )
                return

            if path == "/api/logs":
                pid = self.db.resolve_project_id(q1("project")) if q1("project") else None
                raw_limit = int(q1("limit", "100") or "100")
                limit = max(1, min(raw_limit, 500))  # Clamp limit to prevent LIMIT -1 bypass (RF-15)
                self._send_json({"logs": self.db.list_logs(pid, limit=limit)})
                return

            if path == "/api/export/markdown":
                md = self.db.export_markdown_report(q1("project"))
                self._send_text(md, content_type="text/markdown; charset=utf-8")
                return

            # Static UI serving with strict os.path.commonpath confinement (F-30)
            rel_path = "index.html" if path in ("/", "") else path.lstrip("/")
            full_path = os.path.abspath(os.path.join(UI_DIR, rel_path))
            if os.path.commonpath([UI_DIR, full_path]) != UI_DIR or not os.path.isfile(full_path):
                self._send_json({"error": f"Not found: {path}"}, status=404)
                return

            ctype, _ = mimetypes.guess_type(full_path)
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self._apply_cors_headers()
            self.end_headers()
            self.wfile.write(content)

        except Exception as exc:
            self._send_json(
                {"error": str(exc), "trace": traceback.format_exc() if os.environ.get("AUDIT_DEBUG") else None},
                status=400,
            )

    def do_POST(self) -> None:
        if not self._check_origin_and_csrf(is_mutation=True):
            return

        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
            header_agent = self.headers.get("X-Agent-Id")
            agent_id = body.get("agent_id") or header_agent

            if path == "/api/projects":
                proj = self.db.create_project(
                    name=body["name"],
                    root_path=body.get("root_path", ""),
                    description=body.get("description", ""),
                    details=body.get("details", ""),
                    project_id=body.get("id"),
                    agent_id=agent_id,
                )
                self._send_json(proj, status=201)
                return

            if path == "/api/agents/register":
                pid = (
                    self.db.resolve_project_id(body.get("project_id"))
                    if body.get("project_id") or self.db.has_any_project()
                    else None
                )
                agent = self.db.register_agent(
                    agent_id=body.get("id") or agent_id,
                    name=body.get("name"),
                    role=body.get("role", "general-auditor"),
                    model=body.get("model", ""),
                    capabilities=body.get("capabilities", ""),
                    status=body.get("status", "active"),
                    project_id=pid,
                )
                self._send_json(agent, status=201)
                return

            if path == "/api/agents/heartbeat":
                target_agent = body.get("id") or agent_id
                if not target_agent:
                    raise ValueError("agent_id is required for heartbeat.")
                agent = self.db.heartbeat_agent(
                    agent_id=target_agent,
                    status=body.get("status", "active"),
                    extend_leases_minutes=int(body.get("lease_minutes", 30)),
                )
                self._send_json(agent)
                return

            if path == "/api/systems":
                pid = self.db.resolve_project_id(body.get("project_id"))
                health = int(body["health_score"]) if body.get("health_score") not in (None, "") else None
                sys_obj = self.db.upsert_system(
                    project_id=pid,
                    name=body["name"],
                    parent_ref=body.get("parent_id") or body.get("parent_ref") or None,
                    system_type=body.get("system_type"),
                    path_scope=body.get("path_scope"),
                    description=body.get("description"),
                    details=body.get("details"),
                    status=body.get("status"),
                    health_score=health,
                    agent_id=agent_id,
                    slug=body.get("slug"),
                    system_id=body.get("id"),
                )
                self._send_json(sys_obj, status=201)
                return

            if path == "/api/systems/claim":
                pid = self.db.resolve_project_id(body.get("project_id"))
                if not agent_id:
                    raise ValueError("agent_id is required to claim a system.")
                sys_obj = self.db.claim_system(
                    project_id=pid,
                    system_ref=body["system_ref"],
                    agent_id=agent_id,
                    lease_minutes=int(body.get("lease_minutes", 30)),
                    force=bool(body.get("force", False)),
                )
                self._send_json(sys_obj)
                return

            if path == "/api/systems/release":
                pid = self.db.resolve_project_id(body.get("project_id"))
                health = int(body["health_score"]) if body.get("health_score") not in (None, "") else None
                sys_obj = self.db.release_system(
                    project_id=pid,
                    system_ref=body["system_ref"],
                    agent_id=agent_id,
                    status=body.get("status"),
                    health_score=health,
                    details_append=body.get("details_append"),
                    force=bool(body.get("force", False)),
                )
                self._send_json(sys_obj)
                return

            if path == "/api/relations":
                pid = self.db.resolve_project_id(body.get("project_id"))
                rel = self.db.add_relation(
                    project_id=pid,
                    source_ref=body["source_ref"],
                    target_ref=body["target_ref"],
                    relation_type=body.get("relation_type", "depends_on"),
                    interface_or_protocol=body.get("interface_or_protocol", ""),
                    direction=body.get("direction", "unidirectional"),
                    criticality=body.get("criticality", "medium"),
                    description=body.get("description", ""),
                    details=body.get("details", ""),
                    agent_id=agent_id,
                )
                self._send_json(rel, status=201)
                return

            if path == "/api/tasks":
                pid = self.db.resolve_project_id(body.get("project_id"))
                task = self.db.create_task(
                    project_id=pid,
                    title=body["title"],
                    system_ref=body.get("system_ref") or body.get("system_id") or None,
                    task_type=body.get("task_type", "subsystem_audit"),
                    priority=body.get("priority", "medium"),
                    description=body.get("description", ""),
                    created_by=agent_id,
                    claim_immediately_for=body.get("claim_immediately_for"),
                )
                self._send_json(task, status=201)
                return

            if path == "/api/tasks/claim":
                if not agent_id:
                    raise ValueError("agent_id is required to claim a task.")
                task = self.db.claim_task(
                    task_id=body["task_id"],
                    agent_id=agent_id,
                    lease_minutes=int(body.get("lease_minutes", 30)),
                    force=bool(body.get("force", False)),
                )
                self._send_json(task)
                return

            if path == "/api/tasks/next":
                pid = self.db.resolve_project_id(body.get("project_id"))
                if not agent_id:
                    raise ValueError("agent_id is required to claim next task.")
                task = self.db.claim_next_task(
                    project_id=pid,
                    agent_id=agent_id,
                    task_type=body.get("task_type"),
                    system_ref=body.get("system_ref"),
                    lease_minutes=int(body.get("lease_minutes", 30)),
                )
                self._send_json({"task": task})
                return

            if path == "/api/tasks/block":
                task = self.db.block_task(
                    task_id=body["task_id"],
                    agent_id=agent_id,
                    reason=body.get("reason", "Blocked during review"),
                    force=bool(body.get("force", False)),
                )
                self._send_json(task)
                return

            if path == "/api/tasks/complete":
                health = int(body["system_health_score"]) if body.get("system_health_score") not in (None, "") else None
                task = self.db.complete_task(
                    task_id=body["task_id"],
                    agent_id=agent_id,
                    deliverable_summary=body.get("deliverable_summary", ""),
                    system_status=body.get("system_status"),
                    system_health_score=health,
                    force=bool(body.get("force", False)),
                )
                self._send_json(task)
                return

            if path == "/api/tasks/scaffold":
                pid = self.db.resolve_project_id(body.get("project_id"))
                tasks = self.db.scaffold_system_tasks(
                    project_id=pid,
                    system_ref=body["system_ref"],
                    created_by=agent_id,
                )
                self._send_json({"scaffolded_tasks": tasks}, status=201)
                return

            if path == "/api/resume":
                target_agent = body.get("agent_id") or agent_id
                if not target_agent:
                    raise ValueError("agent_id is required to resume session.")
                pid = self.db.resolve_project_id(body.get("project_id")) if body.get("project_id") else None
                res = self.db.resume_agent(
                    agent_id=target_agent,
                    project_id=pid,
                    extend_leases_minutes=int(body.get("lease_minutes", 30)),
                )
                self._send_json(res)
                return

            if path == "/api/revert":
                target_agent = body.get("agent_id") or agent_id
                if not target_agent:
                    raise ValueError("agent_id is required to revert claims.")
                pid = self.db.resolve_project_id(body.get("project_id")) if body.get("project_id") else None
                rev = self.db.revert_agent(
                    agent_id=target_agent,
                    project_id=pid,
                    reason=body.get("reason", "Aborted by agent"),
                )
                self._send_json(rev)
                return

            if path == "/api/checkpoints":
                target_agent = body.get("agent_id") or agent_id
                if not target_agent:
                    raise ValueError("agent_id is required to save checkpoint.")
                pid = self.db.resolve_project_id(body.get("project_id")) if body.get("project_id") else None
                chk = self.db.save_checkpoint(
                    project_id=pid,
                    agent_id=target_agent,
                    content=body.get("content", ""),
                    title=body.get("title", "Progress Checkpoint"),
                    state_json=body.get("state_json") or {},
                    task_id=body.get("task_id"),
                    system_id=body.get("system_id"),
                    checkpoint_type=body.get("checkpoint_type", "scratchpad"),
                )
                self._send_json(chk, status=201)
                return

            if path == "/api/sweep":
                pid = self.db.resolve_project_id(body.get("project_id")) if body.get("project_id") else None
                auto_fix = bool(body.get("auto_fix", False))
                res = self.db.run_sweep(project_ref=pid, auto_fix=auto_fix, agent_id=agent_id)
                self._send_json(res)
                return

            if path == "/api/findings":
                pid = self.db.resolve_project_id(body.get("project_id"))
                finding = self.db.add_finding(
                    project_id=pid,
                    title=body["title"],
                    severity=body.get("severity", "medium"),
                    category=body.get("category", "architecture"),
                    system_ref=body.get("system_ref") or body.get("system_id") or None,
                    related_system_ref=body.get("related_system_ref") or body.get("related_system_id") or None,
                    task_id=body.get("task_id") or None,
                    agent_id=agent_id,
                    description=body.get("description", ""),
                    details=body.get("details", ""),
                    file_path=body.get("file_path", ""),
                    line_range=body.get("line_range", ""),
                    recommendation=body.get("recommendation", ""),
                    status=body.get("status", "open"),
                )
                self._send_json(finding, status=201)
                return

            if path == "/api/findings/status":
                finding = self.db.update_finding_status(
                    finding_id=body["finding_id"],
                    status=body["status"],
                    agent_id=agent_id,
                    recommendation=body.get("recommendation"),
                )
                self._send_json(finding)
                return

            if path == "/api/seed-demo":
                # Require explicit {'confirm': 'RESET'} if reset_first is True (RF-04)
                reset_first = bool(body.get("reset_first", False))
                if reset_first and body.get("confirm") != "RESET":
                    self._send_json(
                        {"error": "Seeding demo with reset_first=True requires {'confirm': 'RESET'}."},
                        status=400,
                    )
                    return
                snap = self.db.seed_demo_data(reset_first=reset_first)
                self._send_json(snap)
                return

            if path == "/api/reset":
                if body.get("confirm") != "RESET":
                    self._send_json(
                        {"error": "Reset requires explicit confirmation payload {'confirm': 'RESET'}."},
                        status=400,
                    )
                    return
                self.db.reset_database()
                proj = self.db.ensure_default_project()
                self._send_json(self.db.get_project_snapshot(proj["id"]))
                return

            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

        except OverflowError as exc:
            self._send_json({"error": str(exc)}, status=413)
        except Exception as exc:
            self._send_json(
                {"error": str(exc), "trace": traceback.format_exc() if os.environ.get("AUDIT_DEBUG") else None},
                status=400,
            )


def run_server(db: AuditDB, host: str = "127.0.0.1", port: int = 8420) -> None:
    AuditRequestHandler.db = db
    server = ThreadingHTTPServer((host, port), AuditRequestHandler)

    def handle_sigterm(signum: int, frame: Any) -> None:
        server.shutdown()

    try:
        signal.signal(signal.SIGTERM, handle_sigterm)
    except ValueError:
        pass

    print("==================================================================")
    print("  Multi-Agent Project Audit System — Web UI & REST API")
    print(f"  URL:      http://{host}:{port}")
    print(f"  Database: {db.db_path}")
    print("==================================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down audit server...")
    finally:
        server.server_close()

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from email.message import Message

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_cli import build_parser, main as cli_main
from audit_db import AuditDB, utc_now_iso
from audit_server import AuditRequestHandler, is_allowed_origin


class MockRequestHandler(AuditRequestHandler):
    """In-memory harness to test AuditRequestHandler without binding a TCP socket."""

    def __init__(
        self,
        db: AuditDB,
        method: str,
        path: str,
        headers_dict: dict | None = None,
        body_bytes: bytes = b"",
    ) -> None:
        self.db = db
        self.command = method
        self.path = path
        self.request_version = "HTTP/1.1"
        self.headers = Message()
        for k, v in (headers_dict or {}).items():
            self.headers[k] = v
        if body_bytes and "Content-Length" not in self.headers:
            self.headers["Content-Length"] = str(len(body_bytes))
        self.rfile = io.BytesIO(body_bytes)
        self.wfile = io.BytesIO()
        self.status_code = 0
        self.response_headers: dict[str, str] = {}

    def send_response(self, code: int, message: str | None = None) -> None:
        self.status_code = code

    def send_header(self, keyword: str, value: str) -> None:
        self.response_headers[keyword] = value

    def end_headers(self) -> None:
        pass

    def get_json(self) -> dict:
        raw = self.wfile.getvalue().decode("utf-8")
        return json.loads(raw) if raw else {}


class TestAuditOSRemediation(unittest.TestCase):
    def setUp(self) -> None:
        self.db = AuditDB(":memory:")

    # -------------------------------------------------------------------------
    # F-01, F-05, F-21, F-22, F-30, F-31: Server Security & Request Validation
    # -------------------------------------------------------------------------
    def test_f01_cors_blocks_foreign_origins(self) -> None:
        self.assertTrue(is_allowed_origin("http://localhost:8420"))
        self.assertTrue(is_allowed_origin("http://127.0.0.1:8420"))
        self.assertTrue(is_allowed_origin(None))
        self.assertFalse(is_allowed_origin("https://malicious-attacker.com"))

        h = MockRequestHandler(
            self.db,
            "GET",
            "/api/snapshot",
            headers_dict={"Origin": "https://malicious-attacker.com"},
        )
        h.do_GET()
        self.assertEqual(h.status_code, 403)
        self.assertIn("forbidden", h.get_json()["error"].lower())

    def test_f01_and_f05_csrf_and_reset_confirmation(self) -> None:
        self.db.ensure_default_project()
        # 1. HTML Form POST without application/json is rejected with 415 (F-05)
        h_form = MockRequestHandler(
            self.db,
            "POST",
            "/api/reset",
            headers_dict={"Content-Type": "text/plain"},
            body_bytes=b"{}",
        )
        h_form.do_POST()
        self.assertEqual(h_form.status_code, 415)

        # 2. Sec-Fetch-Site: cross-site is rejected with 403 (F-05)
        h_cross = MockRequestHandler(
            self.db,
            "POST",
            "/api/reset",
            headers_dict={
                "Content-Type": "application/json",
                "Sec-Fetch-Site": "cross-site",
            },
            body_bytes=b'{"confirm": "RESET"}',
        )
        h_cross.do_POST()
        self.assertEqual(h_cross.status_code, 403)

        # 3. JSON POST to /api/reset without {"confirm": "RESET"} is rejected with 400 (F-01)
        h_no_confirm = MockRequestHandler(
            self.db,
            "POST",
            "/api/reset",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b"{}",
        )
        h_no_confirm.do_POST()
        self.assertEqual(h_no_confirm.status_code, 400)

        # 4. Valid localhost JSON POST with {"confirm": "RESET"} succeeds
        h_valid = MockRequestHandler(
            self.db,
            "POST",
            "/api/reset",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b'{"confirm": "RESET"}',
        )
        h_valid.do_POST()
        self.assertEqual(h_valid.status_code, 200)

    def test_f21_and_f22_malformed_json_and_oversized_body(self) -> None:
        # Malformed JSON returns 400 instead of crashing thread (F-21)
        h_bad = MockRequestHandler(
            self.db,
            "POST",
            "/api/projects",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b"{invalid-json",
        )
        h_bad.do_POST()
        self.assertEqual(h_bad.status_code, 400)

        # Oversized Content-Length returns 413 Payload Too Large (F-22)
        h_huge = MockRequestHandler(
            self.db,
            "POST",
            "/api/projects",
            headers_dict={
                "Content-Type": "application/json",
                "Content-Length": str(50 * 1024 * 1024),
            },
            body_bytes=b"{}",
        )
        h_huge.do_POST()
        self.assertEqual(h_huge.status_code, 413)

    def test_f30_and_f31_static_traversal_and_health_path_redaction(self) -> None:
        h_health = MockRequestHandler(self.db, "GET", "/api/health")
        h_health.do_GET()
        self.assertEqual(h_health.status_code, 200)
        data = h_health.get_json()
        self.assertNotIn("db_path", data)
        self.assertEqual(data["database"], os.path.basename(self.db.db_path))
        self.assertNotIn("/", data["database"])
        self.assertNotIn("\\", data["database"])
        self.assertTrue(data["ok"])

        h_trav = MockRequestHandler(self.db, "GET", "/../audit_db.py")
        h_trav.do_GET()
        self.assertEqual(h_trav.status_code, 404)

    # -------------------------------------------------------------------------
    # F-02: Active Audit Does Not Mask Open Critical/High Findings
    # -------------------------------------------------------------------------
    def test_f02_critical_finding_not_masked_by_task_completion(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Auth Gateway", slug="auth-gw")
        t = self.db.create_task(p["id"], "Audit Auth", system_ref="auth-gw")
        self.db.claim_task(t["id"], "agent-1")

        # Log critical finding while system is 'in_progress'
        self.db.add_finding(
            p["id"],
            system_ref="auth-gw",
            severity="critical",
            title="Remote Code Execution",
            agent_id="agent-1",
        )
        sys_mid = self.db.get_system(p["id"], "auth-gw")
        self.assertEqual(sys_mid["status"], "needs_attention")

        # Complete task requesting 'reviewed' — system MUST remain 'needs_attention'
        self.db.complete_task(t["id"], "agent-1", deliverable_summary="Audit finished", system_status="reviewed")
        sys_after = self.db.get_system(p["id"], "auth-gw")
        self.assertEqual(sys_after["status"], "needs_attention")

        # Complete task requesting 'healthy' — system MUST remain 'needs_attention'
        t2 = self.db.create_task(p["id"], "Audit Auth 2", system_ref="auth-gw")
        self.db.claim_task(t2["id"], "agent-1")
        self.db.complete_task(t2["id"], "agent-1", deliverable_summary="Finished", system_status="healthy")
        sys_after2 = self.db.get_system(p["id"], "auth-gw")
        self.assertEqual(sys_after2["status"], "needs_attention")

        # upsert_system also cannot overwrite to 'healthy' while critical findings are open
        self.db.upsert_system(p["id"], "Auth Gateway", slug="auth-gw", status="healthy")
        sys_upsert = self.db.get_system(p["id"], "auth-gw")
        self.assertEqual(sys_upsert["status"], "needs_attention")

        # Clean system (no open critical/high findings) cleanly transitions to 'reviewed'
        self.db.upsert_system(p["id"], "Clean Gateway", slug="clean-gw")
        t_clean = self.db.create_task(p["id"], "Audit Clean", system_ref="clean-gw")
        self.db.claim_task(t_clean["id"], "agent-1")
        self.db.complete_task(t_clean["id"], "agent-1", deliverable_summary="All clean")
        sys_clean = self.db.get_system(p["id"], "clean-gw")
        self.assertEqual(sys_clean["status"], "reviewed")

    # -------------------------------------------------------------------------
    # F-03, F-08, F-13, F-14, F-17, F-18, F-20, F-23: Leases & Concurrency
    # -------------------------------------------------------------------------
    def test_f03_claim_next_task_respects_active_system_leases(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Payment Core", slug="payment-core")
        # Agent Alice acquires exclusive 60m lease on payment-core
        self.db.claim_system(p["id"], "payment-core", "agent-alice", lease_minutes=60)
        self.db.create_task(p["id"], "Review Payment Gateway", system_ref="payment-core")

        # Agent Bob asks for next task — should NOT steal Alice's leased system
        claimed_by_bob = self.db.claim_next_task(p["id"], "agent-bob")
        self.assertIsNone(claimed_by_bob)
        sys_obj = self.db.get_system(p["id"], "payment-core")
        self.assertEqual(sys_obj["claimed_by"], "agent-alice")

        # Alice CAN claim the task on her own leased system
        claimed_by_alice = self.db.claim_next_task(p["id"], "agent-alice")
        self.assertIsNotNone(claimed_by_alice)
        self.assertEqual(claimed_by_alice["claimed_by"], "agent-alice")

    def test_f08_claim_task_acquires_expired_system_lease(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Gateway", slug="gw")
        t1 = self.db.create_task(p["id"], "Task 1", system_ref="gw")
        self.db.claim_task(t1["id"], "agent-old", lease_minutes=-10)  # Expired lease

        t2 = self.db.create_task(p["id"], "Task 2", system_ref="gw")
        self.db.claim_task(t2["id"], "agent-new", lease_minutes=30)
        sys_obj = self.db.get_system(p["id"], "gw")
        self.assertEqual(sys_obj["claimed_by"], "agent-new")

    def test_f13_and_f14_and_f20_ownership_checks_and_agent_cleanup(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Core Service", slug="core-svc")
        t = self.db.create_task(p["id"], "Audit Core", system_ref="core-svc")
        self.db.claim_task(t["id"], "agent-owner", lease_minutes=30)

        # Another agent cannot release or complete without force=True (F-13, F-14)
        with self.assertRaises(RuntimeError):
            self.db.release_system(p["id"], "core-svc", agent_id="agent-intruder")
        with self.assertRaises(RuntimeError):
            self.db.complete_task(t["id"], agent_id="agent-intruder", deliverable_summary="Hijack")

        # Owner completes task -> both current_task_id and current_system_id are cleared (F-20)
        self.db.complete_task(t["id"], agent_id="agent-owner", deliverable_summary="Done cleanly")
        agents = {a["id"]: a for a in self.db.list_agents(p["id"])}
        self.assertIsNone(agents["agent-owner"]["current_task_id"])
        self.assertIsNone(agents["agent-owner"]["current_system_id"])

        # Completing an already completed task raises RuntimeError unless forced (F-14)
        with self.assertRaises(RuntimeError):
            self.db.complete_task(t["id"], agent_id="agent-owner", deliverable_summary="Duplicate")

    def test_f17_create_task_with_immediate_claim_locks_system(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], " Billing", slug="billing")
        self.db.create_task(
            p["id"],
            "Audit Billing",
            system_ref="billing",
            claim_immediately_for="agent-1",
        )
        sys_obj = self.db.get_system(p["id"], "billing")
        self.assertEqual(sys_obj["claimed_by"], "agent-1")
        self.assertIsNotNone(sys_obj["lease_until"])

    def test_f18_and_f33_poison_pill_max_attempts_and_block_task(self) -> None:
        p = self.db.ensure_default_project()
        t = self.db.create_task(p["id"], "Poison Task", max_attempts=2)

        # Attempt 1 with expired lease
        self.db.claim_next_task(p["id"], "agent-1", lease_minutes=-5)
        # Attempt 2 with expired lease
        self.db.claim_next_task(p["id"], "agent-2", lease_minutes=-5)
        # Next call to claim_next_task should auto-block the task after 2 attempts
        next_t = self.db.claim_next_task(p["id"], "agent-3")
        self.assertIsNone(next_t)
        tasks = self.db.list_tasks(p["id"], status="blocked")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["id"], t["id"])

        # Explicit block_task also works (F-33)
        t2 = self.db.create_task(p["id"], "Manual Block Task", claim_immediately_for="agent-1")
        blocked = self.db.block_task(t2["id"], agent_id="agent-1", reason="Waiting on schema")
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blocked_reason"], "Waiting on schema")

    def test_f23_heartbeat_offline_releases_locks_and_ignores_expired(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Cache", slug="cache")
        self.db.register_agent("agent-hb", "HB Agent", project_id=p["id"])
        self.db.claim_system(p["id"], "cache", "agent-hb", lease_minutes=-10)  # Already expired

        # Heartbeat should NOT resurrect an expired lease
        self.db.heartbeat_agent("agent-hb", status="active", extend_leases_minutes=30)
        sys_obj = self.db.get_system(p["id"], "cache")
        self.assertLess(sys_obj["lease_until"], utc_now_iso())

        # Claim with valid lease, then send offline heartbeat -> releases claim
        self.db.claim_system(p["id"], "cache", "agent-hb", lease_minutes=30, force=True)
        self.db.heartbeat_agent("agent-hb", status="offline")
        sys_after = self.db.get_system(p["id"], "cache")
        self.assertIsNone(sys_after["claimed_by"])

    # -------------------------------------------------------------------------
    # F-09, F-10, F-12, F-25, F-37, F-38: CLI, Foreign Keys, Project Resolution & Bounds
    # -------------------------------------------------------------------------
    def test_f09_cli_global_flags_work_before_and_after_subcommands(self) -> None:
        parser = build_parser()
        a1 = parser.parse_args(["status", "--json", "--project", "my-proj"])
        self.assertTrue(a1.json)
        self.assertEqual(a1.project, "my-proj")

        a2 = parser.parse_args(["--json", "task", "next", "--agent", "agent-99"])
        self.assertTrue(a2.json)
        self.assertEqual(a2.agent, "agent-99")

        a3 = parser.parse_args(["system", "claim", "edge-gateway", "--agent", "agent-01", "--json"])
        self.assertTrue(a3.json)
        self.assertEqual(a3.agent, "agent-01")

    def test_f10_auto_registers_unregistered_agents_on_relations_and_complete(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "SysA", slug="sys-a")
        self.db.upsert_system(p["id"], "SysB", slug="sys-b")
        rel = self.db.add_relation(p["id"], "sys-a", "sys-b", agent_id="brand-new-agent")
        self.assertEqual(rel["recorded_by"], "brand-new-agent")

        t = self.db.create_task(p["id"], "Task X")
        done = self.db.complete_task(t["id"], agent_id="another-new-agent", deliverable_summary="OK")
        self.assertEqual(done["claimed_by"], "another-new-agent")

    def test_f12_user_initialized_project_not_shadowed_by_default(self) -> None:
        self.db.ensure_default_project()
        custom = self.db.create_project("Enterprise Repo", root_path="/repo")
        resolved = self.db.resolve_project_id(None)
        self.assertEqual(resolved, custom["id"])

    def test_f25_and_f37_and_f38_validation_bounds(self) -> None:
        p = self.db.ensure_default_project()
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "BadScore", health_score=-10)
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "BadScore2", health_score=150)

        self.db.upsert_system(p["id"], "Node1", slug="node-1")
        with self.assertRaises(ValueError):
            self.db.add_relation(p["id"], "node-1", "node-1")

        t = self.db.create_task(p["id"], "Case Priority", priority="CRITICAL")
        self.assertEqual(t["priority"], "critical")

    def test_f07_atomic_snapshot_sync_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = os.path.join(tmpdir, "test_audit.db")
            disk_db = AuditDB(db_path=db_file, auto_sync_snapshot=True)
            snap = disk_db.seed_demo_data(reset_first=True)
            self.assertEqual(len(snap["systems"]), 12)


    def test_rf02_host_header_dns_rebinding_rejected(self) -> None:
        # Rebinding host is rejected with 403
        h_bad_host = MockRequestHandler(
            self.db,
            "GET",
            "/api/health",
            headers_dict={"Host": "attacker.com"},
        )
        h_bad_host.do_GET()
        self.assertEqual(h_bad_host.status_code, 403)
        self.assertIn("invalid host header", h_bad_host.get_json()["error"].lower())

        # Valid localhost hosts succeed
        h_local = MockRequestHandler(
            self.db,
            "GET",
            "/api/health",
            headers_dict={"Host": "localhost:8420"},
        )
        h_local.do_GET()
        self.assertEqual(h_local.status_code, 200)

        h_ip = MockRequestHandler(
            self.db,
            "GET",
            "/api/health",
            headers_dict={"Host": "127.0.0.1:8420"},
        )
        h_ip.do_GET()
        self.assertEqual(h_ip.status_code, 200)

    def test_rf04_seed_demo_protection(self) -> None:
        # 1. reset_first=true without confirm=RESET is rejected with 400
        h_unconfirmed = MockRequestHandler(
            self.db,
            "POST",
            "/api/seed-demo",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b'{"reset_first": true}',
        )
        h_unconfirmed.do_POST()
        self.assertEqual(h_unconfirmed.status_code, 400)
        self.assertIn("requires explicit 'confirm': 'RESET'", h_unconfirmed.get_json()["error"])

        # 2. reset_first=true WITH confirm=RESET succeeds
        h_confirmed = MockRequestHandler(
            self.db,
            "POST",
            "/api/seed-demo",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b'{"reset_first": true, "confirm": "RESET"}',
        )
        h_confirmed.do_POST()
        self.assertEqual(h_confirmed.status_code, 200)
        data = h_confirmed.get_json()
        self.assertEqual(len(data["systems"]), 12)

        # 3. reset_first=false (or omitted) on fresh db succeeds without confirm
        fresh_db = AuditDB(":memory:")
        h_safe = MockRequestHandler(
            fresh_db,
            "POST",
            "/api/seed-demo",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b"{}",
        )
        h_safe.do_POST()
        self.assertEqual(h_safe.status_code, 200)

    def test_rf06_and_rf09_and_rf12_task_block_and_attempt_guards(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Worker Sys", slug="worker-sys")
        t = self.db.create_task(p["id"], "Target Task", system_ref="worker-sys")
        self.db.claim_task(t["id"], "agent-owner", lease_minutes=30)

        # Non-owner cannot block without force=True (RF-06)
        with self.assertRaises(RuntimeError):
            self.db.block_task(t["id"], agent_id="agent-intruder", reason="Sabotage")

        # Non-owner CAN block with force=True (RF-06)
        blocked = self.db.block_task(t["id"], agent_id="agent-intruder", reason="Admin Block", force=True)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIsNone(blocked["claimed_by"])

        # Blocking clears agent pointers and system claim (RF-06)
        agents = {a["id"]: a for a in self.db.list_agents(p["id"])}
        self.assertIsNone(agents["agent-owner"]["current_task_id"])
        sys_obj = self.db.get_system(p["id"], "worker-sys")
        self.assertIsNone(sys_obj["claimed_by"])

        # Completed task CANNOT be blocked even with force=True (RF-06)
        t_comp = self.db.create_task(p["id"], "Completed Task")
        self.db.claim_task(t_comp["id"], "agent-owner")
        self.db.complete_task(t_comp["id"], "agent-owner", deliverable_summary="Done")
        with self.assertRaises(RuntimeError):
            self.db.block_task(t_comp["id"], agent_id="agent-owner", force=True)

        # Task exceeding max_attempts cannot be claimed without force=True (RF-09)
        t_fail = self.db.create_task(p["id"], "Failing Task", max_attempts=1)
        self.db.claim_task(t_fail["id"], "agent-old", lease_minutes=-5)
        with self.assertRaises(RuntimeError):
            self.db.claim_task(t_fail["id"], "agent-new")
        # Force claim succeeds
        forced = self.db.claim_task(t_fail["id"], "agent-new", force=True)
        self.assertEqual(forced["claimed_by"], "agent-new")

        # Claiming an expired task clears previous agent's current_task_id and current_system_id (RF-12)
        agents = {a["id"]: a for a in self.db.list_agents(p["id"])}
        self.assertIsNone(agents["agent-old"]["current_task_id"])

    def test_rf07_and_rf08_system_lease_retention_on_multi_task(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Shared Sys", slug="shared-sys")
        t1 = self.db.create_task(p["id"], "Task 1", system_ref="shared-sys")
        t2 = self.db.create_task(p["id"], "Task 2", system_ref="shared-sys")

        self.db.claim_task(t1["id"], "agent-worker", lease_minutes=30)
        self.db.claim_task(t2["id"], "agent-worker", lease_minutes=30)

        # Agent worker completes task 1 -> system lease MUST NOT be released because task 2 is still active (RF-07)
        self.db.complete_task(t1["id"], "agent-worker", deliverable_summary="T1 done")
        sys_mid = self.db.get_system(p["id"], "shared-sys")
        self.assertEqual(sys_mid["claimed_by"], "agent-worker")

        # Completing task 2 (last task on system) releases the lease (RF-07)
        self.db.complete_task(t2["id"], "agent-worker", deliverable_summary="T2 done")
        sys_final = self.db.get_system(p["id"], "shared-sys")
        self.assertIsNone(sys_final["claimed_by"])

        # Agent completing unassigned task does not release unrelated agent's system lease (RF-08)
        self.db.claim_system(p["id"], "shared-sys", "agent-holder", lease_minutes=30)
        t_global = self.db.create_task(p["id"], "Global Task")
        self.db.claim_task(t_global["id"], "agent-other")
        self.db.complete_task(t_global["id"], "agent-other", deliverable_summary="Global done")
        sys_holder = self.db.get_system(p["id"], "shared-sys")
        self.assertEqual(sys_holder["claimed_by"], "agent-holder")

    def test_rf10_hierarchy_cycle_detection(self) -> None:
        p = self.db.ensure_default_project()
        s1 = self.db.upsert_system(p["id"], "System A", slug="sys-a")
        s2 = self.db.upsert_system(p["id"], "System B", slug="sys-b", parent_ref="sys-a")
        s3 = self.db.upsert_system(p["id"], "System C", slug="sys-c", parent_ref="sys-b")

        # Self-parenting raises ValueError (RF-10)
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "System A", slug="sys-a", parent_ref="sys-a")

        # Transitive cycle raises ValueError (RF-10)
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "System A", slug="sys-a", parent_ref="sys-c")

    def test_rf14_invalid_task_id_finding_validation(self) -> None:
        p = self.db.ensure_default_project()
        # Invalid task_id raises ValueError, not unhandled sqlite3.IntegrityError (RF-14)
        with self.assertRaises(ValueError):
            self.db.add_finding(p["id"], title="Orphan Finding", task_id="non-existent-task-id")

    def test_rf15_logs_endpoint_pagination_clamped(self) -> None:
        p = self.db.ensure_default_project()
        # Negative limit is clamped to at least 1 (RF-15)
        h_neg = MockRequestHandler(self.db, "GET", "/api/logs?limit=-1")
        h_neg.do_GET()
        self.assertEqual(h_neg.status_code, 200)

        # Huge limit is clamped to at most 500 (RF-15)
        h_huge = MockRequestHandler(self.db, "GET", "/api/logs?limit=999999")
        h_huge.do_GET()
        self.assertEqual(h_huge.status_code, 200)

    def test_rf17_audit_export_json_output(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Export Sys", slug="export-sys")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli_main(["export", "--json", "--db", self.db.db_path])
        output = buf.getvalue()
        data = json.loads(output)
        self.assertIn("project", data)
        self.assertIn("systems", data)

    def test_cli_commands_integration(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "cli_test.db")
            # 1. init
            cli_main(["init", "--name", "Integration Project", "--root", tmpdir, "--db", db_path])
            # 2. system add
            cli_main(["system", "add", "--name", "Gateway", "--slug", "gw", "--type", "service", "--db", db_path])
            # 3. agent register
            cli_main(["agent", "register", "--id", "agent-cli", "--name", "CLI Agent", "--role", "general-auditor", "--db", db_path])
            # 4. task add
            cli_main(["task", "add", "--title", "Verify Architecture", "--system", "gw", "--db", db_path])
            # 5. task next
            buf_next = io.StringIO()
            with contextlib.redirect_stdout(buf_next):
                cli_main(["task", "next", "--agent", "agent-cli", "--json", "--db", db_path])
            task_data = json.loads(buf_next.getvalue())
            self.assertIn("id", task_data)
            task_id = task_data["id"]
            # 6. finding add
            cli_main(["finding", "add", "--title", "Auth missing", "--system", "gw", "--agent", "agent-cli", "--severity", "high", "--db", db_path])
            # 7. task block
            cli_main(["task", "block", task_id, "--agent", "agent-cli", "--reason", "Waiting on spec", "--db", db_path])
            # 8. status --json
            buf_status = io.StringIO()
            with contextlib.redirect_stdout(buf_status):
                cli_main(["status", "--json", "--db", db_path])
            status_data = json.loads(buf_status.getvalue())
            self.assertEqual(status_data["total_systems"], 1)
            self.assertEqual(status_data["total_agents"], 1)
            self.assertEqual(status_data["total_findings"], 1)

    def test_identifier_validation(self) -> None:
        p = self.db.ensure_default_project()
        # Slashes and spaces in slugs/IDs are rejected (RF-03)
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "Bad Slug System", slug="bad/slug")
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "Bad Slug System 2", slug="bad slug")
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "Bad Slug System 3", slug="bad$slug")
        with self.assertRaises(ValueError):
            self.db.create_project("Bad ID Project", project_id="bad/id")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from email.message import Message

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_cli import build_parser, run_cli
from audit_db import AuditDB, utc_now_iso
from audit_server import AuditRequestHandler, is_allowed_host, is_allowed_origin


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
    # F-01, F-05, F-21, F-22, F-30, F-31, RF-02, RF-04, RF-11, RF-15: Server Security
    # -------------------------------------------------------------------------
    def test_f01_and_rf02_cors_and_dns_rebinding_protection(self) -> None:
        self.assertTrue(is_allowed_origin("http://localhost:8420"))
        self.assertTrue(is_allowed_origin("http://127.0.0.1:8420"))
        self.assertTrue(is_allowed_origin(None))
        self.assertFalse(is_allowed_origin("https://malicious-attacker.com"))

        self.assertTrue(is_allowed_host("localhost:8420"))
        self.assertTrue(is_allowed_host("127.0.0.1:8420"))
        self.assertFalse(is_allowed_host("rebind.attacker.com:8420"))

        # Foreign Origin blocked (F-01)
        h_origin = MockRequestHandler(
            self.db,
            "GET",
            "/api/snapshot",
            headers_dict={"Origin": "https://malicious-attacker.com"},
        )
        h_origin.do_GET()
        self.assertEqual(h_origin.status_code, 403)
        self.assertNotEqual(h_origin.response_headers.get("Access-Control-Allow-Origin"), "*")

        # Host header DNS rebinding blocked (RF-02)
        h_rebind = MockRequestHandler(
            self.db,
            "GET",
            "/api/snapshot",
            headers_dict={
                "Host": "rebind.attacker.com:8420",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        h_rebind.do_GET()
        self.assertEqual(h_rebind.status_code, 403)
        self.assertIn("rebinding", h_rebind.get_json()["error"].lower())

        # Valid localhost request returns strict localhost CORS header (RF-11)
        h_ok = MockRequestHandler(
            self.db,
            "GET",
            "/api/snapshot",
            headers_dict={"Host": "localhost:8420", "Origin": "http://localhost:8420"},
        )
        h_ok.do_GET()
        self.assertEqual(h_ok.status_code, 200)
        self.assertEqual(
            h_ok.response_headers.get("Access-Control-Allow-Origin"),
            "http://localhost:8420",
        )

    def test_f01_f05_and_rf04_csrf_reset_and_seed_demo_confirmation(self) -> None:
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

        # 4. JSON POST to /api/seed-demo with reset_first=True without confirm is rejected (RF-04)
        h_seed_unconfirmed = MockRequestHandler(
            self.db,
            "POST",
            "/api/seed-demo",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b'{"reset_first": true}',
        )
        h_seed_unconfirmed.do_POST()
        self.assertEqual(h_seed_unconfirmed.status_code, 400)

        # 5. Valid localhost JSON POST with {"confirm": "RESET"} succeeds
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
        h_bad = MockRequestHandler(
            self.db,
            "POST",
            "/api/projects",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=b"{invalid-json",
        )
        h_bad.do_POST()
        self.assertEqual(h_bad.status_code, 400)

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

    def test_f30_f31_and_rf15_static_confinement_health_and_logs_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            disk_db = AuditDB(db_path=os.path.join(tmpdir, "secret_dir", "my_audit.db"))
            h_health = MockRequestHandler(disk_db, "GET", "/api/health")
            h_health.do_GET()
            self.assertEqual(h_health.status_code, 200)
            data = h_health.get_json()
            self.assertNotIn("db_path", data)
            self.assertEqual(data["database"], "my_audit.db")
            self.assertNotIn("/", data["database"])
            self.assertNotIn("\\", data["database"])

        h_trav = MockRequestHandler(self.db, "GET", "/../audit_db.py")
        h_trav.do_GET()
        self.assertEqual(h_trav.status_code, 404)

        # RF-15: Negative limit is clamped to >= 1
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Sys1", slug="sys-1")
        self.db.upsert_system(p["id"], "Sys2", slug="sys-2")
        h_logs = MockRequestHandler(self.db, "GET", "/api/logs?limit=-1")
        h_logs.do_GET()
        self.assertEqual(h_logs.status_code, 200)
        self.assertEqual(len(h_logs.get_json()["logs"]), 1)

    # -------------------------------------------------------------------------
    # F-02 & RF-01: Open Critical/High Vulnerability Masking Prevention
    # -------------------------------------------------------------------------
    def test_f02_and_rf01_critical_finding_never_masked_by_reviewed_or_healthy(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Auth Gateway", slug="auth-gw")
        t = self.db.create_task(p["id"], "Audit Auth", system_ref="auth-gw")
        self.db.claim_task(t["id"], "agent-1")

        self.db.add_finding(
            p["id"],
            system_ref="auth-gw",
            severity="critical",
            title="Remote Code Execution",
            agent_id="agent-1",
        )
        # 1. Attempting to complete task with system_status="reviewed" or "healthy" MUST stay 'needs_attention' (RF-01)
        self.db.complete_task(
            t["id"],
            "agent-1",
            deliverable_summary="Audit finished",
            system_status="healthy",
        )
        self.assertEqual(self.db.get_system(p["id"], "auth-gw")["status"], "needs_attention")

        # 2. Attempting to overwrite via upsert_system(status="healthy") MUST stay 'needs_attention' (RF-01)
        self.db.upsert_system(p["id"], "Auth Gateway", slug="auth-gw", status="healthy")
        self.assertEqual(self.db.get_system(p["id"], "auth-gw")["status"], "needs_attention")

        # 3. Attempting to overwrite via release_system(status="healthy") MUST stay 'needs_attention' (RF-01)
        self.db.claim_system(p["id"], "auth-gw", "agent-1")
        self.db.release_system(p["id"], "auth-gw", agent_id="agent-1", status="healthy")
        self.assertEqual(self.db.get_system(p["id"], "auth-gw")["status"], "needs_attention")

    # -------------------------------------------------------------------------
    # F-03, F-08, RF-05, RF-06, RF-07, RF-08, RF-09, RF-12, RF-16: Concurrency & Leases
    # -------------------------------------------------------------------------
    def test_f03_claim_next_task_respects_active_system_leases(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Payment Core", slug="payment-core")
        self.db.claim_system(p["id"], "payment-core", "agent-alice", lease_minutes=60)
        self.db.create_task(p["id"], "Review Payment Gateway", system_ref="payment-core")

        claimed_by_bob = self.db.claim_next_task(p["id"], "agent-bob")
        self.assertIsNone(claimed_by_bob)
        self.assertEqual(self.db.get_system(p["id"], "payment-core")["claimed_by"], "agent-alice")

        claimed_by_alice = self.db.claim_next_task(p["id"], "agent-alice")
        self.assertIsNotNone(claimed_by_alice)
        self.assertEqual(claimed_by_alice["claimed_by"], "agent-alice")

    def test_f08_and_rf12_expired_lease_reclamation_clears_stale_agent_pointers(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Gateway", slug="gw")
        t1 = self.db.create_task(p["id"], "Task 1", system_ref="gw")
        self.db.claim_task(t1["id"], "agent-old", lease_minutes=-10)  # Expired lease

        # Agent-new reclaims expired task1
        self.db.claim_next_task(p["id"], "agent-new", lease_minutes=30)
        sys_obj = self.db.get_system(p["id"], "gw")
        self.assertEqual(sys_obj["claimed_by"], "agent-new")

        # Verify agent-old no longer has stale current_task_id or current_system_id (RF-12)
        agents = {a["id"]: a for a in self.db.list_agents(p["id"])}
        self.assertIsNone(agents["agent-old"]["current_task_id"])
        self.assertIsNone(agents["agent-old"]["current_system_id"])
        self.assertEqual(agents["agent-new"]["current_task_id"], t1["id"])

    def test_rf05_and_rf06_ownership_checks_when_agent_id_omitted_or_blocked(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Core Service", slug="core-svc")
        t = self.db.create_task(p["id"], "Audit Core", system_ref="core-svc")
        self.db.claim_task(t["id"], "agent-owner", lease_minutes=30)

        # RF-05: Calling complete_task with agent_id=None on a claimed task MUST fail
        with self.assertRaises(RuntimeError):
            self.db.complete_task(t["id"], agent_id=None, deliverable_summary="Anonymous hijack")

        # RF-06: Calling block_task as another agent or anonymous on a claimed task MUST fail
        with self.assertRaises(RuntimeError):
            self.db.block_task(t["id"], agent_id="agent-rival", reason="Sabotage")
        with self.assertRaises(RuntimeError):
            self.db.block_task(t["id"], agent_id=None, reason="Anonymous block")

        # Owner can complete task
        self.db.complete_task(t["id"], agent_id="agent-owner", deliverable_summary="Legit")

        # RF-06: Calling block_task on an already completed task MUST fail unless forced
        with self.assertRaises(RuntimeError):
            self.db.block_task(t["id"], agent_id="agent-owner", reason="Regress completed")

    def test_rf07_and_rf08_multi_task_system_lease_preservation_and_unassigned_completion(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Order Engine", slug="order-eng")
        t1 = self.db.create_task(p["id"], "Task 1", system_ref="order-eng")
        t2 = self.db.create_task(p["id"], "Task 2", system_ref="order-eng")

        # Alice claims both t1 and t2 on order-eng
        self.db.claim_task(t1["id"], "agent-alice", lease_minutes=45)
        self.db.claim_task(t2["id"], "agent-alice", lease_minutes=45)

        # Alice completes t1 -> order-eng MUST remain claimed by Alice because t2 is still claimed (RF-07)
        self.db.complete_task(t1["id"], agent_id="agent-alice", deliverable_summary="Part 1 done")
        sys_mid = self.db.get_system(p["id"], "order-eng")
        self.assertEqual(sys_mid["claimed_by"], "agent-alice")
        alice_mid = {a["id"]: a for a in self.db.list_agents(p["id"])}["agent-alice"]
        self.assertEqual(alice_mid["current_system_id"], sys_mid["id"])

        # RF-08: Completing an unassigned task t3 on order-eng with agent_id=None MUST NOT revoke Alice's system lease
        t3 = self.db.create_task(p["id"], "Unassigned Task 3", system_ref="order-eng")
        self.db.complete_task(t3["id"], agent_id=None, deliverable_summary="Auto-check")
        self.assertEqual(self.db.get_system(p["id"], "order-eng")["claimed_by"], "agent-alice")

        # Now Alice completes t2 -> no remaining tasks, so system lease is released
        self.db.complete_task(t2["id"], agent_id="agent-alice", deliverable_summary="Part 2 done")
        self.assertIsNone(self.db.get_system(p["id"], "order-eng")["claimed_by"])

    def test_rf09_and_rf16_offline_heartbeat_blocks_poison_pills_and_resets_system_status(self) -> None:
        p = self.db.ensure_default_project()
        self.db.upsert_system(p["id"], "Cache", slug="cache")
        self.db.register_agent("agent-hb", "HB Agent", project_id=p["id"])

        # Expired lease is NOT resurrected by active heartbeat (F-23, RF-11)
        self.db.claim_system(p["id"], "cache", "agent-hb", lease_minutes=-10)
        self.db.heartbeat_agent("agent-hb", status="active", extend_leases_minutes=30)
        sys_obj = self.db.get_system(p["id"], "cache")
        self.assertLess(sys_obj["lease_until"], utc_now_iso())

        # RF-09 & RF-16: Task with max_attempts=1 claimed by agent-hb who then goes offline
        t = self.db.create_task(p["id"], "Failing Task", system_ref="cache", max_attempts=1)
        self.db.claim_task(t["id"], "agent-hb", lease_minutes=30, force=True)
        self.assertEqual(self.db.get_system(p["id"], "cache")["status"], "in_progress")

        self.db.heartbeat_agent("agent-hb", status="offline")
        # System lock is released AND orphaned 'in_progress' status is reset to 'unreviewed' (RF-16)
        sys_after = self.db.get_system(p["id"], "cache")
        self.assertIsNone(sys_after["claimed_by"])
        self.assertEqual(sys_after["status"], "unreviewed")

        # Task that hit max_attempts=1 is transitioned to 'blocked', not wedged in 'open' (RF-09)
        blocked_tasks = self.db.list_tasks(p["id"], status="blocked")
        self.assertEqual(len(blocked_tasks), 1)
        self.assertEqual(blocked_tasks[0]["id"], t["id"])

        # Attempting to claim a task that reached max_attempts by ID raises RuntimeError (RF-09)
        with self.assertRaises(RuntimeError):
            self.db.claim_task(t["id"], "agent-2")

    # -------------------------------------------------------------------------
    # RF-03, RF-10, RF-14: Identifier Validation, Transitive Cycles & Task FK Validation
    # -------------------------------------------------------------------------
    def test_rf03_and_rf10_identifier_validation_and_transitive_cycle_prevention(self) -> None:
        p = self.db.ensure_default_project()
        # RF-03: Malicious XSS payloads in agent_id or system slug/id are rejected at DB boundary
        with self.assertRaises(ValueError):
            self.db.register_agent(agent_id="agent');alert(1);//", name="Evil")
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "Sys", slug="sys');alert(1);//")

        # RF-10: Transitive cycle A -> B -> C -> A is rejected with ValueError
        self.db.upsert_system(p["id"], "Node A", slug="node-a")
        self.db.upsert_system(p["id"], "Node B", slug="node-b", parent_ref="node-a")
        self.db.upsert_system(p["id"], "Node C", slug="node-c", parent_ref="node-b")
        with self.assertRaises(ValueError):
            self.db.upsert_system(p["id"], "Node A", slug="node-a", parent_ref="node-c")

    def test_rf14_add_finding_validates_task_id(self) -> None:
        p = self.db.ensure_default_project()
        with self.assertRaises(ValueError):
            self.db.add_finding(
                p["id"],
                title="Orphan task ref",
                task_id="task-nonexistent",
            )

    # -------------------------------------------------------------------------
    # F-09, RF-13, RF-17, RF-19: CLI Execution & Hermetic Snapshot Sync
    # -------------------------------------------------------------------------
    def test_f09_rf13_rf17_rf19_cli_end_to_end_and_hermetic_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = os.path.join(tmpdir, "cli_test.db")
            ui_dir = os.path.join(tmpdir, "ui")
            os.makedirs(ui_dir, exist_ok=True)

            # RF-13: Hermetic snapshot sync writes only to tmpdir/ui/snapshot.js
            disk_db = AuditDB(db_path=db_file, ui_dir=ui_dir)
            snap = disk_db.seed_demo_data(reset_first=True)
            snap_file = disk_db.sync_static_snapshot(snap["project"]["id"])
            self.assertTrue(os.path.isfile(snap_file))

            # Reset and verify RF-19: registering an agent before 'init' does NOT create a zombie default project
            self.assertEqual(run_cli(["reset", "--db", db_file, "--json"]), 0)
            self.assertEqual(
                run_cli(["agent", "register", "--db", db_file, "--id", "agent-01", "--name", "Worker 1", "--json"]),
                0,
            )
            self.assertFalse(disk_db.has_any_project())

            # Now initialize project -> becomes the sole active project
            self.assertEqual(
                run_cli(["init", "--db", db_file, "--name", "CLI Project", "--root", "/repo", "--json"]),
                0,
            )
            self.assertEqual(len(disk_db.list_projects()), 1)
            self.assertEqual(disk_db.list_projects()[0]["name"], "CLI Project")

            # Add systems, relation, task, finding, block, complete via CLI
            self.assertEqual(
                run_cli(["system", "add", "--db", db_file, "--name", "Edge", "--slug", "edge", "--health", "90", "--json"]),
                0,
            )
            self.assertEqual(
                run_cli(["system", "add", "--db", db_file, "--name", "Auth", "--slug", "auth", "--parent", "edge", "--json"]),
                0,
            )
            self.assertEqual(
                run_cli(["relation", "add", "--db", db_file, "--from", "edge", "--to", "auth", "--type", "calls", "--json"]),
                0,
            )
            self.assertEqual(
                run_cli(["task", "add", "--db", db_file, "--title", "Review Auth", "--system", "auth", "--priority", "critical", "--json"]),
                0,
            )

            # RF-17: `audit export --json` outputs valid JSON to stdout even without `--format json`
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_cli(["export", "--db", db_file, "--json"])
            self.assertEqual(rc, 0)
            exported_json = json.loads(buf.getvalue())
            self.assertEqual(exported_json["project"]["name"], "CLI Project")

    def test_multi_agent_coordination_blackboard_and_checkpoints(self) -> None:
        """Verify role taxonomy, role-aware task dispatch, mission blackboard, task scaffolding, and checkpoints."""
        proj = self.db.create_project(name="Mission Board Test", root_path="/test")
        pid = proj["id"]

        # Register specialized agents
        sec_agent = self.db.register_agent(agent_id="sec-01", name="Security Agent", role="security-auditor", project_id=pid)
        arch_agent = self.db.register_agent(agent_id="arch-01", name="Arch Agent", role="arch-mapper", project_id=pid)

        # Verify role roster
        roster = self.db.list_roles(pid)
        self.assertEqual(roster["total_active_agents"], 2)
        self.assertIn("performance-reviewer", roster["vacant_roles"])
        self.assertNotIn("security-auditor", roster["vacant_roles"])

        # Add systems
        sys_obj1 = self.db.upsert_system(project_id=pid, name="Payment Core", slug="payment-core", system_type="service")
        sys_obj2 = self.db.upsert_system(project_id=pid, name="Auth Service", slug="auth-service", system_type="service")

        # Auto-scaffold standard multi-disciplinary audit tasks (5 disciplines including verification)
        scaffolded1 = self.db.scaffold_system_tasks(pid, "payment-core", created_by="arch-01")
        self.assertEqual(len(scaffolded1), 5)
        types = {t["task_type"] for t in scaffolded1}
        self.assertEqual(types, {"architecture_map", "security_review", "performance_review", "integration_trace", "verification"})

        scaffolded2 = self.db.scaffold_system_tasks(pid, "auth-service", created_by="arch-01", include_verification=False)
        self.assertEqual(len(scaffolded2), 4)

        # Role-aware dispatch: security-auditor should claim security_review
        sec_task = self.db.claim_next_task(project_id=pid, agent_id="sec-01")
        self.assertIsNotNone(sec_task)
        self.assertEqual(sec_task["task_type"], "security_review")
        self.assertEqual(sec_task["claimed_by"], "sec-01")

        # Role-aware dispatch: arch-mapper should claim architecture_map on an available system
        arch_task = self.db.claim_next_task(project_id=pid, agent_id="arch-01")
        self.assertIsNotNone(arch_task)
        self.assertEqual(arch_task["task_type"], "architecture_map")
        self.assertEqual(arch_task["claimed_by"], "arch-01")

        # Save checkpoint / scratchpad for sec-01
        chk = self.db.save_checkpoint(
            project_id=pid,
            agent_id="sec-01",
            title="Analyzing payment auth headers",
            content="Found missing signature validation on webhook callbacks.",
            state_json={"step": 2, "verified": False},
        )
        self.assertEqual(chk["agent_id"], "sec-01")
        self.assertEqual(chk["task_id"], sec_task["id"])

        # Fetch latest checkpoint
        latest_chk = self.db.get_agent_checkpoint("sec-01")
        self.assertIsNotNone(latest_chk)
        self.assertEqual(latest_chk["title"], "Analyzing payment auth headers")

        # Resume agent session
        res = self.db.resume_agent("sec-01", project_id=pid)
        self.assertEqual(res["active_task"]["id"], sec_task["id"])
        self.assertEqual(res["latest_checkpoint"]["id"], chk["id"])
        self.assertIn("Continue working on task", res["next_action"])

        # Test mission blackboard
        board = self.db.get_blackboard(pid)
        self.assertEqual(len(board["matrix"]), 2)
        payment_row = next(r for r in board["matrix"] if r["slug"] == "payment-core")
        auth_row = next(r for r in board["matrix"] if r["slug"] == "auth-service")
        self.assertEqual(payment_row["facets"]["sec"]["status"], "in_progress")
        self.assertEqual(payment_row["facets"]["arch"]["status"], "pending")
        self.assertEqual(auth_row["facets"]["arch"]["status"], "in_progress")

        # Revert agent claims cleanly
        rev = self.db.revert_agent("sec-01", project_id=pid, reason="Pause for lunch")
        self.assertEqual(rev["status"], "idle")
        self.assertIn(sec_task["id"], rev["reverted_tasks"])

        # Verify task is reopened
        open_task = self.db.get_project_snapshot(pid)["tasks"]
        sec_reopened = next(t for t in open_task if t["id"] == sec_task["id"])
        self.assertEqual(sec_reopened["status"], "open")
        self.assertIsNone(sec_reopened["claimed_by"])

        # Test HTTP REST endpoints for board, roles, checkpoints, scaffold, resume, revert
        h_board = MockRequestHandler(self.db, "GET", f"/api/board?project={pid}")
        h_board.do_GET()
        self.assertEqual(h_board.status_code, 200)
        self.assertEqual(len(h_board.get_json()["matrix"]), 2)

        h_roles = MockRequestHandler(self.db, "GET", f"/api/roles?project={pid}")
        h_roles.do_GET()
        self.assertEqual(h_roles.status_code, 200)
        self.assertEqual(h_roles.get_json()["total_active_agents"], 1)  # arch-01 is active, sec-01 is idle

        h_chks = MockRequestHandler(self.db, "GET", f"/api/checkpoints?project={pid}&agent=sec-01")
        h_chks.do_GET()
        self.assertEqual(h_chks.status_code, 200)
        self.assertEqual(len(h_chks.get_json()["checkpoints"]), 1)

        h_resume = MockRequestHandler(
            self.db,
            "POST",
            "/api/resume",
            headers_dict={"Content-Type": "application/json"},
            body_bytes=json.dumps({"agent_id": "arch-01", "project_id": pid}).encode("utf-8"),
        )
        h_resume.do_POST()
        self.assertEqual(h_resume.status_code, 200)
        self.assertEqual(h_resume.get_json()["active_task"]["id"], arch_task["id"])

        # Test audit lead / sweep functionality
        sweep_dry = self.db.run_sweep(pid, auto_fix=False)
        self.assertFalse(sweep_dry["auto_fix"])
        self.assertIn("zombies", sweep_dry)
        self.assertIn("unscaffolded", sweep_dry)

        # Test sweep with auto_fix
        sweep_fix = self.db.run_sweep(pid, auto_fix=True)
        self.assertTrue(sweep_fix["auto_fix"])

        # Test REST /api/sweep
        h_sweep = MockRequestHandler(self.db, "GET", f"/api/sweep?project={pid}")
        h_sweep.do_GET()
        self.assertEqual(h_sweep.status_code, 200)
        self.assertIn("zombies", h_sweep.get_json())

    def test_evidence_provenance_and_health_calibration(self) -> None:
        """Verify evidence reconstruction keys (commit_sha, span_hash) and health calibration limits."""
        pid = self.db.resolve_project_id()

        # Check PRAGMA user_version is 2
        with self.db.connect() as conn:
            ver = conn.execute("PRAGMA user_version;").fetchone()[0]
            self.assertEqual(ver, 2)

        # Create healthy system with health score 95
        sys_obj = self.db.upsert_system(
            project_id=pid,
            name="Crypto Vault",
            slug="crypto-vault",
            health_score=95,
            status="reviewed",
        )
        self.assertEqual(sys_obj["health_score"], 95)
        self.assertEqual(sys_obj["status"], "reviewed")

        # Log a critical finding with commit_sha and code_snippet
        finding = self.db.add_finding(
            project_id=pid,
            title="Hardcoded master key in AES derivation",
            severity="critical",
            category="security",
            system_ref="crypto-vault",
            file_path="src/crypto/aes.py",
            line_range="45-60",
            commit_sha="a1b2c3d4e5f67890",
            code_snippet="def derive(): return b'0123456789abcdef'",
            recommendation="Read key from HSM or environment variable.",
        )
        self.assertEqual(finding["commit_sha"], "a1b2c3d4e5f67890")
        self.assertTrue(len(finding["span_hash"]) > 0)

        # Invariant check: system health must be clamped from 95 down to <= 65 and status forced to needs_attention
        updated_sys = self.db.get_system(pid, "crypto-vault")
        self.assertEqual(updated_sys["status"], "needs_attention")
        self.assertLessEqual(updated_sys["health_score"], 65)

        # Invariant check: complete_task attempting to assert health=99 on system with open critical finding is clamped
        task = self.db.create_task(
            project_id=pid,
            title="Inspect key derivation",
            system_ref="crypto-vault",
            claim_immediately_for="agent-01",
        )
        self.db.complete_task(
            task_id=task["id"],
            agent_id="agent-01",
            system_status="healthy",
            system_health_score=99,
        )
        sys_after_task = self.db.get_system(pid, "crypto-vault")
        self.assertEqual(sys_after_task["status"], "needs_attention")
        self.assertLessEqual(sys_after_task["health_score"], 65)

        # Markdown report check: ensure Reconstruction Key is exported
        report = self.db.export_markdown_report(pid)
        self.assertIn("Reconstruction Key", report)
        self.assertIn("commit `a1b2c3d4`", report)

    def test_multi_target_portfolio_and_workbench(self) -> None:
        """Verify multi-target repository portfolio overview and per-project isolated workbenches."""
        # Create two distinct target repository projects
        proj_a = self.db.create_project(
            name="Alpha Microservices",
            root_path="/repos/alpha",
            description="Alpha microservices platform",
            project_id="proj-alpha",
        )
        proj_b = self.db.create_project(
            name="Beta Data Platform",
            root_path="/repos/beta",
            description="Beta analytics and data lakehouse",
            project_id="proj-beta",
        )

        # Populate Alpha with a system and a critical finding
        self.db.upsert_system(
            project_id="proj-alpha",
            name="Auth Gateway",
            slug="auth-gateway",
            health_score=60,
            status="needs_attention",
        )
        self.db.add_finding(
            project_id="proj-alpha",
            title="SQL Injection in auth route",
            severity="critical",
            system_ref="auth-gateway",
        )

        # Populate Beta with two healthy systems and zero findings
        self.db.upsert_system(
            project_id="proj-beta",
            name="Ingestion Pipeline",
            slug="ingestion-pipe",
            health_score=95,
            status="healthy",
        )
        self.db.upsert_system(
            project_id="proj-beta",
            name="ClickHouse Store",
            slug="clickhouse-store",
            health_score=90,
            status="healthy",
        )

        # Verify get_portfolio_summary accurately reflects both targets
        portfolio = self.db.get_portfolio_summary()
        self.assertGreaterEqual(len(portfolio), 2)

        alpha_item = next(item for item in portfolio if item["project"]["id"] == "proj-alpha")
        beta_item = next(item for item in portfolio if item["project"]["id"] == "proj-beta")

        self.assertEqual(alpha_item["metrics"]["total_systems"], 1)
        self.assertEqual(alpha_item["metrics"]["open_findings"], 1)
        self.assertEqual(alpha_item["metrics"]["severity_counts"]["critical"], 1)

        self.assertEqual(beta_item["metrics"]["total_systems"], 2)
        self.assertEqual(beta_item["metrics"]["open_findings"], 0)
        self.assertGreaterEqual(beta_item["metrics"]["avg_health_score"], 90)

        # Test REST /api/portfolio endpoint
        h_port = MockRequestHandler(self.db, "GET", "/api/portfolio")
        h_port.do_GET()
        self.assertEqual(h_port.status_code, 200)
        port_json = h_port.get_json()
        self.assertIn("portfolio", port_json)
        self.assertGreaterEqual(len(port_json["portfolio"]), 2)

        # Test board isolation across target repositories
        board_alpha = self.db.get_blackboard("proj-alpha")
        self.assertEqual(board_alpha["project"]["id"], "proj-alpha")
        self.assertEqual(len(board_alpha["matrix"]), 1)

        board_beta = self.db.get_blackboard("proj-beta")
        self.assertEqual(board_beta["project"]["id"], "proj-beta")
        self.assertEqual(len(board_beta["matrix"]), 2)

    def test_sweep_governor_high_finding_and_lease_cleaner(self) -> None:
        """Verify sweep auto-fix cannot paint high-finding systems healthy, clears agent pointers, and matches span_hash."""
        pid = self.db.resolve_project_id()

        # 1. Create a system with asserted health 90 in progress
        sys_obj = self.db.upsert_system(
            project_id=pid,
            name="Payment Settlement Core",
            slug="payment-settlement-core",
            health_score=90,
            status="in_progress",
        )
        sid = sys_obj["id"]

        # Complete a task so it qualifies for milestone sign-off (has_completed=True, has_pending=False)
        task = self.db.create_task(
            project_id=pid,
            title="Initial audit of settlement",
            system_ref=sid,
            claim_immediately_for="agent-01",
        )
        self.db.complete_task(task_id=task["id"], agent_id="agent-01")

        # 2. Add an open HIGH severity finding on this system with code snippet for span_hash
        f1 = self.db.add_finding(
            project_id=pid,
            title="Unchecked float precision in ledger rounding",
            severity="high",
            category="performance",
            system_ref=sid,
            file_path="src/ledger/round.py",
            line_range="10-25",
            code_snippet="def round_amount(x): return float(x)",
            recommendation="Use decimal.Decimal for all monetary calculations.",
        )
        self.assertTrue(len(f1["span_hash"]) > 0)

        # 3. Setup a zombie task and system claimed by agent-zombie
        zombie_agent = self.db.register_agent(agent_id="agent-zombie", name="Zombie Agent", project_id=pid)
        z_task = self.db.create_task(
            project_id=pid,
            title="Stalled reconciliation task",
            system_ref=sid,
            claim_immediately_for="agent-zombie",
        )
        # Manually expire the lease in the past for both task and system
        past_iso = "2020-01-01T00:00:00.000Z"
        with self.db.connect(immediate=True) as conn:
            conn.execute("UPDATE tasks SET lease_until = ? WHERE id = ?", (past_iso, z_task["id"]))
            conn.execute("UPDATE systems SET lease_until = ? WHERE id = ?", (past_iso, sid))
            conn.execute("UPDATE agents SET current_task_id = ?, current_system_id = ? WHERE id = ?", (z_task["id"], sid, "agent-zombie"))

        # Add a duplicate finding with identical span_hash
        f2 = self.db.add_finding(
            project_id=pid,
            title="Another finding with exact same snippet",
            severity="high",
            category="performance",
            system_ref=sid,
            file_path="src/ledger/different_file.py",
            line_range="100-115",
            code_snippet="def round_amount(x): return float(x)",  # same snippet -> same span_hash
        )
        self.assertEqual(f1["span_hash"], f2["span_hash"])

        # 4. Run sweep with auto_fix=True and agent_id=None
        sweep_res = self.db.run_sweep(pid, auto_fix=True, agent_id=None)

        # Verify duplicate detected via span_hash
        self.assertGreaterEqual(len(sweep_res["duplicates"]), 1)
        dup_entry = next((d for d in sweep_res["duplicates"] if d["span_hash"] == f1["span_hash"]), None)
        self.assertIsNotNone(dup_entry)
        self.assertIn("span_hash", dup_entry["reason"])

        # 5. INVARIANT: System CANNOT be painted healthy! Status MUST be needs_attention, health clamped <= 75
        updated_sys = self.db.get_system(pid, sid)
        self.assertEqual(updated_sys["status"], "needs_attention")
        self.assertLessEqual(updated_sys["health_score"], 75)

        # 6. INVARIANT: Zombie repair must clear agents' current_task_id and current_system_id
        with self.db.connect() as conn:
            z_row = conn.execute("SELECT current_task_id, current_system_id FROM agents WHERE id = ?", ("agent-zombie",)).fetchone()
            self.assertIsNone(z_row["current_task_id"])
            self.assertIsNone(z_row["current_system_id"])

            # 7. INVARIANT: Sweep did NOT auto-insert an 'audit-lead' agent when agent_id was None
            lead_agent = conn.execute("SELECT id FROM agents WHERE id = 'audit-lead'").fetchone()
            self.assertIsNone(lead_agent)


if __name__ == "__main__":
    unittest.main()

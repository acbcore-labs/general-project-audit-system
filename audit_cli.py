#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from audit_db import AuditDB
from audit_server import run_server


def print_output(data: Any, as_json: bool = False, human_lines: Optional[List[str]] = None) -> None:
    if as_json or human_lines is None:
        print(json.dumps(data, indent=2))
    else:
        for line in human_lines:
            print(line)


def build_parser() -> argparse.ArgumentParser:
    # Shared parent parser for subcommands so --db, --project, --agent, --json work in ANY position (F-09)
    sub_global = argparse.ArgumentParser(add_help=False)
    sub_global.add_argument("--db", default=argparse.SUPPRESS, help="Path to SQLite audit database")
    sub_global.add_argument("--project", default=argparse.SUPPRESS, help="Project ID, slug, or name")
    sub_global.add_argument("--agent", default=argparse.SUPPRESS, help="Agent/Worker ID executing this command")
    sub_global.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Output structured JSON")

    parser = argparse.ArgumentParser(
        prog="audit",
        description="Generalized Multi-Agent Codebase & Project Auditing System (SQLite + CLI + Web UI)",
    )
    parser.add_argument("--db", default=None, help="Path to SQLite audit database (default: ./audit.db or $AUDIT_DB_PATH)")
    parser.add_argument("--project", default=None, help="Project ID, slug, or name (defaults to active project)")
    parser.add_argument("--agent", default=os.environ.get("AUDIT_AGENT_ID"), help="Agent/Worker ID executing this command (or set $AUDIT_AGENT_ID)")
    parser.add_argument("--json", action="store_true", default=False, help="Output structured JSON for automated agent consumption")

    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", parents=[sub_global], help="Initialize or create a project to audit")
    p_init.add_argument("--name", required=True, help="Project name")
    p_init.add_argument("--root", default="", help="Root directory path of the codebase/project")
    p_init.add_argument("--desc", default="", help="High-level project description")
    p_init.add_argument("--details", default="", help="Detailed architectural overview")
    p_init.add_argument("--id", default=None, help="Optional custom project ID")

    # status
    subparsers.add_parser("status", parents=[sub_global], help="Show overall audit status, coverage metrics, and workforce summary")

    # board
    subparsers.add_parser("board", parents=[sub_global], help="Show live multi-agent mission blackboard & coverage matrix")

    # resume & revert
    p_resume = subparsers.add_parser("resume", parents=[sub_global], help="Resume an interrupted agent session, extend leases, and restore working context")
    p_resume.add_argument("--lease", type=int, default=30, help="Minutes to extend active leases")

    p_revert = subparsers.add_parser("revert", parents=[sub_global], help="Release all active task/system claims held by an agent and return them to the queue")
    p_revert.add_argument("--reason", default="Aborted by agent", help="Reason for releasing claims")

    # checkpoint
    p_chk = subparsers.add_parser("checkpoint", parents=[sub_global], help="Save, show, or list agent progress checkpoints and scratchpad notes")
    chk_sub = p_chk.add_subparsers(dest="chk_cmd")

    p_chk_save = chk_sub.add_parser("save", parents=[sub_global], help="Save draft notes, progress state, or partial findings")
    p_chk_save.add_argument("--notes", default="", help="Markdown or text notes")
    p_chk_save.add_argument("--title", default="", help="Checkpoint title")
    p_chk_save.add_argument("--data", default=None, help="JSON-serialized state object")
    p_chk_save.add_argument("--task", default=None, help="Task ID (defaults to agent's current task)")
    p_chk_save.add_argument("--system", default=None, help="System slug or ID (defaults to agent's current system)")
    p_chk_save.add_argument("--type", default="scratchpad", choices=["scratchpad", "draft_finding", "progress_state", "artifact"], help="Checkpoint type")

    p_chk_show = chk_sub.add_parser("show", parents=[sub_global], help="Show latest checkpoint for an agent")
    p_chk_show.add_argument("--task", default=None, help="Optional task ID")

    p_chk_list = chk_sub.add_parser("list", parents=[sub_global], help="List checkpoints")
    p_chk_list.add_argument("--task", default=None, help="Optional task ID filter")

    # seed-demo & reset
    subparsers.add_parser("seed-demo", parents=[sub_global], help="Seed database with a realistic multi-system, multi-agent audit demo")
    subparsers.add_parser("reset", parents=[sub_global], help="Clear all audit records and reset the database")

    # serve
    p_serve = subparsers.add_parser("serve", parents=[sub_global], help="Start the local Web UI & HTTP REST API server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8420, help="Port to bind (default: 8420)")

    # export
    p_export = subparsers.add_parser("export", parents=[sub_global], help="Export full audit report as Markdown or JSON")
    p_export.add_argument("--format", choices=["md", "json"], default="md", help="Export format (md or json)")
    p_export.add_argument("--output", default=None, help="Optional file path to write report to")

    # logs
    p_logs = subparsers.add_parser("logs", parents=[sub_global], help="View chronological multi-agent audit trail")
    p_logs.add_argument("--limit", type=int, default=40, help="Max log entries to return")

    # agent commands
    p_agent = subparsers.add_parser("agent", parents=[sub_global], help="Manage agent/worker identities and heartbeats")
    agent_sub = p_agent.add_subparsers(dest="agent_cmd")

    p_agent_reg = agent_sub.add_parser("register", parents=[sub_global], help="Register or update an agent worker identity")
    p_agent_reg.add_argument("--id", default=None, help="Unique agent ID (e.g., agent-sec-01)")
    p_agent_reg.add_argument("--name", required=True, help="Human-friendly agent name")
    p_agent_reg.add_argument("--role", default="general-auditor", help="Agent specialty/role (e.g., architecture-mapper, security-auditor, performance-reviewer)")
    p_agent_reg.add_argument("--model", default="", help="Underlying model or worker runtime")
    p_agent_reg.add_argument("--capabilities", default="", help="Comma-separated capabilities or focus areas")

    p_agent_hb = agent_sub.add_parser("heartbeat", parents=[sub_global], help="Send agent heartbeat and extend active task/system leases")
    p_agent_hb.add_argument("--id", default=None, help="Agent ID")
    p_agent_hb.add_argument("--status", default="active", choices=["active", "idle", "offline"], help="Agent status")
    p_agent_hb.add_argument("--lease", type=int, default=30, help="Minutes to extend active leases")

    agent_sub.add_parser("list", parents=[sub_global], help="List all registered agents and their current claims")
    agent_sub.add_parser("roster", parents=[sub_global], help="Show canonical role matrix, active staffing, and vacant specialties")

    # system commands
    p_sys = subparsers.add_parser("system", parents=[sub_global], help="Map and inspect systems and hierarchical subsystems")
    sys_sub = p_sys.add_subparsers(dest="sys_cmd")

    p_sys_add = sys_sub.add_parser("add", parents=[sub_global], help="Add or update a system or subsystem")
    p_sys_add.add_argument("--name", required=True, help="System or subsystem name")
    p_sys_add.add_argument("--slug", default=None, help="Optional unique slug (auto-generated from name if omitted)")
    p_sys_add.add_argument("--parent", default=None, help="Parent system ID, slug, or name (makes this a subsystem)")
    p_sys_add.add_argument("--type", default=None, choices=["system", "subsystem", "service", "module", "pipeline", "datastore", "external"], help="Component type")
    p_sys_add.add_argument("--path", default=None, help="File or directory path glob in the codebase (e.g., services/auth/**)")
    p_sys_add.add_argument("--desc", default=None, help="Concise description of purpose")
    p_sys_add.add_argument("--details", default=None, help="Detailed architectural notes, invariants, tech stack, and behavior")
    p_sys_add.add_argument("--status", default=None, choices=["unreviewed", "in_progress", "reviewed", "needs_attention", "healthy"], help="Audit status")
    p_sys_add.add_argument("--health", type=int, default=None, help="Health score from 0 to 100")

    sys_sub.add_parser("list", parents=[sub_global], help="List all systems and subsystems in a flat table")
    sys_sub.add_parser("tree", parents=[sub_global], help="Display hierarchical tree of systems and their subsystems")

    p_sys_show = sys_sub.add_parser("show", parents=[sub_global], help="Show complete dossier for a system/subsystem (relations, findings, tasks)")
    p_sys_show.add_argument("system_ref", help="System ID, slug, or name")

    p_sys_claim = sys_sub.add_parser("claim", parents=[sub_global], help="Claim/lock a system or subsystem for an agent")
    p_sys_claim.add_argument("system_ref", help="System ID, slug, or name")
    p_sys_claim.add_argument("--lease", type=int, default=30, help="Lease lock duration in minutes")
    p_sys_claim.add_argument("--force", action="store_true", help="Override an existing active claim")

    p_sys_rel = sys_sub.add_parser("release", parents=[sub_global], help="Release claim on a system and optionally update its status/health")
    p_sys_rel.add_argument("system_ref", help="System ID, slug, or name")
    p_sys_rel.add_argument("--status", default=None, choices=["unreviewed", "in_progress", "reviewed", "needs_attention", "healthy"])
    p_sys_rel.add_argument("--health", type=int, default=None, help="Updated health score (0-100)")
    p_sys_rel.add_argument("--notes", default=None, help="Timestamped audit note to append to system details")
    p_sys_rel.add_argument("--force", action="store_true", help="Force release even if claimed by another agent")

    # relation commands
    p_rel = subparsers.add_parser("relation", parents=[sub_global], help="Document how systems and subsystems work with other systems")
    rel_sub = p_rel.add_subparsers(dest="rel_cmd")

    p_rel_add = rel_sub.add_parser("add", parents=[sub_global], help="Record an interaction or dependency between two systems/subsystems")
    p_rel_add.add_argument("--from", dest="source_ref", required=True, help="Source system/subsystem ID, slug, or name")
    p_rel_add.add_argument("--to", dest="target_ref", required=True, help="Target system/subsystem ID, slug, or name")
    p_rel_add.add_argument("--type", default="depends_on", help="Relation type (depends_on, calls, publishes_to, consumes_from, reads_writes, authenticates_via, orchestrates, syncs_with)")
    p_rel_add.add_argument("--protocol", default="", help="Interface, protocol, topic, or contract (e.g., gRPC, REST, Kafka, SQL)")
    p_rel_add.add_argument("--direction", default="unidirectional", choices=["unidirectional", "bidirectional"])
    p_rel_add.add_argument("--criticality", default="medium", choices=["critical", "high", "medium", "low"])
    p_rel_add.add_argument("--desc", default="", help="Summary of how these systems work together")
    p_rel_add.add_argument("--details", default="", help="Technical details (payloads, SLAs, failure modes, coupling)")

    p_rel_list = rel_sub.add_parser("list", parents=[sub_global], help="List cross-system relations")
    p_rel_list.add_argument("--system", default=None, help="Filter to relations involving a specific system/subsystem")

    # task commands
    p_task = subparsers.add_parser("task", parents=[sub_global], help="Coordinate multi-agent audit tasks and job queue")
    task_sub = p_task.add_subparsers(dest="task_cmd")

    p_task_add = task_sub.add_parser("add", parents=[sub_global], help="Create a new audit task")
    p_task_add.add_argument("--title", required=True, help="Task title")
    p_task_add.add_argument("--system", default=None, help="Target system/subsystem ID, slug, or name")
    p_task_add.add_argument("--type", default="subsystem_audit", choices=["architecture_map", "subsystem_audit", "integration_trace", "security_review", "performance_review", "bug_hunt", "verification"])
    p_task_add.add_argument("--priority", default="medium", choices=["critical", "high", "medium", "low"])
    p_task_add.add_argument("--desc", default="", help="Detailed instructions or scope for the task")
    p_task_add.add_argument("--claim", action="store_true", help="Immediately claim this task for --agent")

    p_task_next = task_sub.add_parser("next", parents=[sub_global], help="Atomically claim the highest-priority open task for an agent")
    p_task_next.add_argument("--type", default=None, help="Optional filter by task_type")
    p_task_next.add_argument("--system", default=None, help="Optional filter by system/subsystem")
    p_task_next.add_argument("--lease", type=int, default=30, help="Lease duration in minutes")

    p_task_claim = task_sub.add_parser("claim", parents=[sub_global], help="Claim a specific task by ID")
    p_task_claim.add_argument("task_id", help="Task ID")
    p_task_claim.add_argument("--lease", type=int, default=30, help="Lease duration in minutes")
    p_task_claim.add_argument("--force", action="store_true", help="Force claim even if currently leased")

    p_task_block = task_sub.add_parser("block", parents=[sub_global], help="Mark a task as blocked and release its lease")
    p_task_block.add_argument("task_id", help="Task ID")
    p_task_block.add_argument("--reason", default="Blocked during review", help="Reason why the task is blocked")
    p_task_block.add_argument("--force", action="store_true", help="Force block even if claimed by another agent or completed")

    p_task_done = task_sub.add_parser("complete", parents=[sub_global], help="Mark a task completed and record deliverable summary")
    p_task_done.add_argument("task_id", help="Task ID")
    p_task_done.add_argument("--summary", required=True, help="Summary of what was audited and discovered")
    p_task_done.add_argument("--system-status", default=None, choices=["unreviewed", "in_progress", "reviewed", "needs_attention", "healthy"])
    p_task_done.add_argument("--health", type=int, default=None, help="Optional updated health score for the target system")
    p_task_done.add_argument("--force", action="store_true", help="Force completion even if claimed by another agent or already completed")

    p_task_list = task_sub.add_parser("list", parents=[sub_global], help="List audit tasks")
    p_task_list.add_argument("--status", default=None, choices=["open", "claimed", "completed", "blocked"])
    p_task_list.add_argument("--system", default=None, help="Filter by system/subsystem")
    p_task_list.add_argument("--claimed-by", default=None, help="Filter by assigned agent ID")

    p_task_scaffold = task_sub.add_parser("scaffold", parents=[sub_global], help="Auto-scaffold standard multi-disciplinary audit tasks for a system/subsystem")
    p_task_scaffold.add_argument("--system", required=True, help="Target system/subsystem ID, slug, or name")

    # finding commands
    p_find = subparsers.add_parser("finding", parents=[sub_global], help="Log and manage audit findings, bugs, and architectural risks")
    find_sub = p_find.add_subparsers(dest="find_cmd")

    p_find_add = find_sub.add_parser("add", parents=[sub_global], help="Log a new audit finding")
    p_find_add.add_argument("--title", required=True, help="Concise finding title")
    p_find_add.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low", "info"])
    p_find_add.add_argument("--category", default="architecture", choices=["architecture", "security", "integration", "performance", "reliability", "maintainability", "bug", "documentation"])
    p_find_add.add_argument("--system", default=None, help="Primary affected system/subsystem")
    p_find_add.add_argument("--related-system", default=None, help="Optional secondary system if cross-system issue")
    p_find_add.add_argument("--task", default=None, help="Optional task ID under which this was found")
    p_find_add.add_argument("--file", default="", help="File path in codebase")
    p_find_add.add_argument("--lines", default="", help="Line range (e.g., 120-165)")
    p_find_add.add_argument("--desc", default="", help="Summary description of the issue")
    p_find_add.add_argument("--details", default="", help="Deep technical explanation, reproduction, or root cause")
    p_find_add.add_argument("--recommendation", default="", help="Concrete remediation steps")

    p_find_upd = find_sub.add_parser("update", parents=[sub_global], help="Update finding status or recommendation")
    p_find_upd.add_argument("finding_id", help="Finding ID")
    p_find_upd.add_argument("--status", required=True, choices=["open", "confirmed", "mitigated", "resolved", "wont_fix"])
    p_find_upd.add_argument("--recommendation", default=None, help="Updated recommendation")

    p_find_list = find_sub.add_parser("list", parents=[sub_global], help="List audit findings")
    p_find_list.add_argument("--severity", default=None, choices=["critical", "high", "medium", "low", "info"])
    p_find_list.add_argument("--category", default=None)
    p_find_list.add_argument("--status", default=None)
    p_find_list.add_argument("--system", default=None)

    return parser


def run_cli(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    try:
        db = AuditDB(db_path=args.db)

        if args.command == "serve":
            db.ensure_default_project()
            run_server(db, host=args.host, port=args.port)
            return 0

        if args.command == "init":
            proj = db.create_project(
                name=args.name,
                root_path=args.root,
                description=args.desc,
                details=args.details,
                project_id=args.id,
                agent_id=args.agent,
            )
            db.sync_static_snapshot(proj["id"])
            print_output(
                proj,
                args.json,
                [
                    f"Initialized Project: {proj['name']} ({proj['id']})",
                    f"  Slug:      {proj['slug']}",
                    f"  Root Path: {proj['root_path'] or '(not set)'}",
                    f"  Database:  {db.db_path}",
                ],
            )
            return 0

        if args.command == "seed-demo":
            snap = db.seed_demo_data(reset_first=True)
            db.sync_static_snapshot(snap["project"]["id"])
            m = snap["metrics"]
            print_output(
                snap,
                args.json,
                [
                    f"Seeded Demo Project: {snap['project']['name']} ({snap['project']['id']})",
                    f"  Systems:    {m['total_systems']} systems + {m['total_subsystems']} subsystems ({m['total_relations']} cross-system relations)",
                    f"  Workforce:  {m['total_agents']} specialized agents registered",
                    f"  Tasks:      {sum(m['task_counts'].values())} total ({m['task_counts']['completed']} completed, {m['task_counts']['claimed']} claimed, {m['task_counts']['open']} open)",
                    f"  Findings:   {m['total_findings']} logged ({m['severity_counts']['critical']} critical, {m['severity_counts']['high']} high)",
                ],
            )
            return 0

        if args.command == "reset":
            db.reset_database()
            print_output({"ok": True}, args.json, ["Database reset cleanly."])
            return 0

        if args.command == "status":
            snap = db.get_project_snapshot(args.project)
            p = snap["project"]
            m = snap["metrics"]
            sc = m["severity_counts"]
            tc = m["task_counts"]
            lines = [
                f"=== Project Audit Status: {p['name']} ({p['id']}) ===",
                f"Root Path:   {p.get('root_path') or '(not set)'}",
                f"Updated At:  {p['updated_at']}",
                f"Coverage:    {m['reviewed_components']}/{m['total_components']} components reviewed ({m['total_systems']} systems, {m['total_subsystems']} subsystems)",
                f"Relations:   {m['total_relations']} cross-system interactions documented",
                f"Avg Health:  {m['avg_health_score'] if m['avg_health_score'] is not None else 'N/A'}/100",
                f"Workforce:   {m['active_agents']} active / {m['total_agents']} total agents",
                f"Tasks:       {tc['open']} open | {tc['claimed']} claimed | {tc['completed']} completed | {tc['blocked']} blocked",
                f"Findings:    {m['open_findings']} open / {m['total_findings']} total "
                f"[CRIT: {sc['critical']}, HIGH: {sc['high']}, MED: {sc['medium']}, LOW: {sc['low']}, INFO: {sc['info']}]",
            ]
            print_output(snap["metrics"], args.json, lines)
            return 0

        if args.command == "board":
            b = db.get_blackboard(args.project)
            p = b["project"]
            r = b["roster"]
            m = b["matrix"]
            lines = [
                f"=== AUDIT MISSION BLACKBOARD: {p['name']} ({p['id']}) ===",
                f"Workforce: {r['total_active_agents']} active agent(s) | Vacant roles: {', '.join(r['vacant_roles']) or 'None (Fully Staffed)'}",
                "",
                "SYSTEM / SUBSYSTEM                      HEALTH   ARCH   SEC    PERF   INTEG  VERIFY  CLAIM / AGENT",
                "─" * 96,
            ]
            symbol_map = {
                "completed": "✅",
                "in_progress": "⏳",
                "blocked": "❌",
                "pending": "📋",
                "documented": "🔗",
                "unassigned": "—",
            }
            for row in m:
                pfx = " └── " if row.get("parent_id") else ""
                name_disp = f"{pfx}{row['name']} ({row['slug']})"[:38].ljust(38)
                health_disp = f"{row['health_score']}/100" if row["health_score"] is not None else " unscored"
                health_disp = health_disp.center(8)
                f = row["facets"]
                arch_s = symbol_map.get(f["arch"]["status"], "—").center(6)
                sec_s = symbol_map.get(f["sec"]["status"], "—").center(6)
                perf_s = symbol_map.get(f["perf"]["status"], "—").center(6)
                integ_s = symbol_map.get(f["integ"]["status"], "—").center(6)
                ver_s = symbol_map.get(f["verify"]["status"], "—").center(6)
                claim_str = f"@{row['claimed_by']}" if row.get("claimed_by") else "[Unclaimed]"
                if row.get("critical_findings_count", 0) > 0:
                    claim_str += f" ({row['critical_findings_count']} CRIT finding!)"
                lines.append(f"{name_disp} {health_disp} {arch_s} {sec_s} {perf_s} {integ_s} {ver_s}  {claim_str}")

            lines.append("─" * 96)
            lines.append("Legend: ✅ Completed | ⏳ In-Progress | 📋 Pending/Claimable | ❌ Blocked | 🔗 Documented | — Unassigned")
            if b["recommendations"]:
                lines.append("\nRecommended Next Actions:")
                for rec in b["recommendations"]:
                    lines.append(f"  * {rec}")
            print_output(b, args.json, lines)
            return 0

        if args.command == "resume":
            aid = args.agent
            if not aid:
                raise ValueError("Specify agent ID via --agent or $AUDIT_AGENT_ID to resume session.")
            pid = db.resolve_project_id(args.project) if args.project else None
            res = db.resume_agent(agent_id=aid, project_id=pid, extend_leases_minutes=args.lease)
            lines = [
                f"=== Resumed Session for Agent: {res['agent']['name']} ({aid}) ===",
                f"Role:         {res['agent']['role']} (status: {res['agent']['status']})",
                f"Lease:        Extended active leases by {res['lease_extended_minutes']} minutes",
            ]
            if res.get("active_task"):
                t = res["active_task"]
                lines.append(f"Active Task:  [{t['id']}] {t['title']} (Priority: {t['priority']}, System: {t.get('system_slug') or 'Project'})")
                lines.append(f"  Lease Until: {t.get('lease_until')}")
            else:
                lines.append("Active Task:  (none claimed)")

            if res.get("active_system"):
                s = res["active_system"]
                lines.append(f"Active System: {s['name']} ({s['slug']}) — Lease Until: {s.get('lease_until')}")

            if res.get("latest_checkpoint"):
                c = res["latest_checkpoint"]
                lines.append(f"Latest Checkpoint: '{c.get('title')}' ({c['created_at']})")
                if c.get("content"):
                    lines.append(f"  Notes: {c['content']}")

            lines.append(f"\nNext Action: {res['next_action']}")
            print_output(res, args.json, lines)
            return 0

        if args.command == "revert":
            aid = args.agent
            if not aid:
                raise ValueError("Specify agent ID via --agent or $AUDIT_AGENT_ID to revert claims.")
            pid = db.resolve_project_id(args.project) if args.project else None
            rev = db.revert_agent(agent_id=aid, project_id=pid, reason=args.reason)
            lines = [
                f"Reverted Claims for Agent '{aid}':",
                f"  Reverted Tasks:   {', '.join(rev['reverted_tasks']) or 'None'}",
                f"  Reverted Systems: {', '.join(rev['reverted_systems']) or 'None'}",
                f"  Reason:           {rev['reason']}",
                f"  Agent Status:     {rev['status']}",
            ]
            print_output(rev, args.json, lines)
            return 0

        if args.command == "checkpoint":
            pid = db.resolve_project_id(args.project) if args.project else None
            if args.chk_cmd == "save":
                aid = args.agent
                if not aid:
                    raise ValueError("Specify agent ID via --agent or $AUDIT_AGENT_ID to save checkpoint.")
                data_dict = json.loads(args.data) if getattr(args, "data", None) else {}
                chk = db.save_checkpoint(
                    project_id=pid,
                    agent_id=aid,
                    content=args.notes or "",
                    title=args.title or "Progress Checkpoint",
                    state_json=data_dict,
                    task_id=args.task,
                    system_id=args.system,
                    checkpoint_type=args.type,
                )
                print_output(
                    chk,
                    args.json,
                    [
                        f"Saved Checkpoint {chk['id']} for Agent '{aid}':",
                        f"  Title:      {chk['title']}",
                        f"  Type:       {chk['checkpoint_type']}",
                        f"  Task/Sys:   {chk.get('task_id') or '-'} / {chk.get('system_id') or '-'}",
                        f"  Created At: {chk['created_at']}",
                    ],
                )
                return 0

            if args.chk_cmd == "show":
                aid = args.agent
                if not aid:
                    raise ValueError("Specify agent ID via --agent or $AUDIT_AGENT_ID to show checkpoint.")
                chk = db.get_agent_checkpoint(agent_id=aid, task_id=args.task)
                if not chk:
                    print_output({"checkpoint": None}, args.json, ["No checkpoint found."])
                else:
                    lines = [
                        f"=== Checkpoint: {chk['title']} ({chk['id']}) ===",
                        f"Agent:       {chk['agent_id']}",
                        f"Created At:  {chk['created_at']}",
                        f"Type:        {chk['checkpoint_type']}",
                        f"Task:        {chk.get('task_id') or '-'}",
                        f"System:      {chk.get('system_id') or '-'}",
                        f"Notes/Draft: {chk.get('content') or '-'}",
                    ]
                    if chk.get("state_json") and chk["state_json"] != "{}":
                        lines.append(f"State JSON:  {chk['state_json']}")
                    print_output(chk, args.json, lines)
                return 0

            if args.chk_cmd == "list":
                chks = db.list_checkpoints(project_id=pid, agent_id=args.agent, task_id=args.task)
                lines = [
                    f"- [{c['created_at']}] {c['id']} (@{c['agent_id']}) [{c['checkpoint_type']}]: {c['title']} | task:{c.get('task_id') or '-'}"
                    for c in chks
                ]
                print_output(chks, args.json, lines or ["No checkpoints recorded."])
                return 0

        if args.command == "export":
            # Honor both --format json and global --json flag when exporting to stdout (RF-17)
            use_json_format = args.format == "json" or (args.json and not args.output)
            if use_json_format:
                snap = db.get_project_snapshot(args.project)
                out_str = json.dumps(snap, indent=2)
            else:
                out_str = db.export_markdown_report(args.project)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out_str)
                print_output(
                    {"ok": True, "output": os.path.abspath(args.output)},
                    args.json,
                    [f"Exported report to {os.path.abspath(args.output)}"],
                )
            else:
                print(out_str)
            return 0

        if args.command == "logs":
            pid = db.resolve_project_id(args.project) if args.project else None
            logs = db.list_logs(pid, limit=args.limit)
            lines = [
                f"[{l['created_at']}] ({l.get('agent_id') or 'system'}) {l['action']}: {l['summary']}"
                for l in logs
            ]
            print_output(logs, args.json, lines or ["No audit logs recorded yet."])
            return 0

        # AGENT SUBCOMMANDS
        if args.command == "agent":
            if args.agent_cmd == "register":
                # Do not auto-create a zombie default project if agent register runs before 'audit init' (RF-19)
                pid = (
                    db.resolve_project_id(args.project)
                    if args.project or db.has_any_project()
                    else None
                )
                aid = args.id or args.agent
                agent = db.register_agent(
                    agent_id=aid,
                    name=args.name,
                    role=args.role,
                    model=args.model,
                    capabilities=args.capabilities,
                    project_id=pid,
                )
                if pid:
                    db.sync_static_snapshot(pid)
                print_output(
                    agent,
                    args.json,
                    [
                        f"Registered Agent: {agent['name']} (ID: {agent['id']})",
                        f"  Role:         {agent['role']}",
                        f"  Model:        {agent['model'] or 'unspecified'}",
                        f"  Capabilities: {agent['capabilities'] or 'general'}",
                        f"  Heartbeat:    {agent['last_heartbeat']}",
                    ],
                )
                return 0

            if args.agent_cmd == "heartbeat":
                aid = args.id or args.agent
                if not aid:
                    raise ValueError("Specify agent ID via --id, --agent, or $AUDIT_AGENT_ID")
                agent = db.heartbeat_agent(aid, status=args.status, extend_leases_minutes=args.lease)
                print_output(
                    agent,
                    args.json,
                    [f"Heartbeat recorded for agent '{agent['id']}' at {agent['last_heartbeat']} (status: {agent['status']})"],
                )
                return 0

            if args.agent_cmd == "list":
                pid = db.resolve_project_id(args.project) if args.project else None
                agents = db.list_agents(project_id=pid)
                lines = []
                for a in agents:
                    claim_info = []
                    if a.get("current_system_slug"):
                        claim_info.append(f"system:{a['current_system_slug']}")
                    if a.get("current_task_title"):
                        claim_info.append(f"task:'{a['current_task_title']}'")
                    active_str = f" | Working on: {', '.join(claim_info)}" if claim_info else ""
                    lines.append(
                        f"- {a['id']} ({a['name']}) [{a['role']}] — status: {a['status']} | "
                        f"tasks done: {a.get('completed_tasks_count', 0)} | findings: {a.get('findings_count', 0)} | "
                        f"last seen: {a['last_heartbeat']}{active_str}"
                    )
                print_output(agents, args.json, lines or ["No agents registered."])
                return 0

            if args.agent_cmd == "roster":
                pid = db.resolve_project_id(args.project) if args.project else None
                r = db.list_roles(pid)
                lines = [
                    "=== Multi-Agent Workforce Roster & Role Matrix ===",
                    f"Active Agents: {r['total_active_agents']} | Vacant Canonical Roles: {len(r['vacant_roles'])}",
                    "",
                ]
                for role in r["roles"]:
                    vac_str = "[VACANT]" if role["is_vacant"] else f"[{role['active_agents']} active]"
                    agent_names = ", ".join(f"@{a['id']}" for a in role["agents"] if a["status"] == "active") or "None"
                    task_types_str = ", ".join(role["task_types"]) or "any"
                    lines.append(f"- {role['role']} — {role['title']} {vac_str}")
                    lines.append(f"  Description: {role['description']}")
                    lines.append(f"  Target Tasks: {task_types_str}")
                    lines.append(f"  Active Staff: {agent_names}")
                    lines.append("")
                print_output(r, args.json, lines)
                return 0

        # SYSTEM SUBCOMMANDS
        if args.command == "system":
            pid = db.resolve_project_id(args.project)
            if args.sys_cmd == "add":
                sys_obj = db.upsert_system(
                    project_id=pid,
                    name=args.name,
                    slug=args.slug,
                    parent_ref=args.parent,
                    system_type=args.type,
                    path_scope=args.path,
                    description=args.desc,
                    details=args.details,
                    status=args.status,
                    health_score=args.health,
                    agent_id=args.agent,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    sys_obj,
                    args.json,
                    [
                        f"Saved {sys_obj['system_type'].upper()}: {sys_obj['name']} (slug: {sys_obj['slug']}, id: {sys_obj['id']})",
                        f"  Parent:  {sys_obj['parent']['name'] if sys_obj.get('parent') else '(top-level system)'}",
                        f"  Scope:   {sys_obj['path_scope'] or '(not set)'}",
                        f"  Status:  {sys_obj['status']} | Health: {sys_obj['health_score'] if sys_obj['health_score'] is not None else 'N/A'}",
                        f"  Updated: {sys_obj['updated_at']}",
                    ],
                )
                return 0

            if args.sys_cmd == "list":
                systems = db.list_systems(pid)
                lines = []
                for s in systems:
                    parent_tag = f" (under {s['parent_slug']})" if s.get("parent_slug") else ""
                    claim_tag = f" [CLAIMED BY {s['claimed_by']}]" if s.get("claimed_by") else ""
                    health_tag = f"{s['health_score']}/100" if s["health_score"] is not None else "unscored"
                    lines.append(
                        f"- [{s['system_type'].upper()}] {s['name']} ({s['slug']}){parent_tag} | "
                        f"status: {s['status']} | health: {health_tag} | "
                        f"rels: {s['outbound_count']} out / {s['inbound_count']} in | "
                        f"open findings: {s['open_findings_count']}{claim_tag}"
                    )
                print_output(systems, args.json, lines or ["No systems mapped yet."])
                return 0

            if args.sys_cmd == "tree":
                systems = db.list_systems(pid)
                by_parent: Dict[Optional[str], List[Dict[str, Any]]] = {}
                for s in systems:
                    by_parent.setdefault(s["parent_id"], []).append(s)
                lines = []
                visited_tree = set()

                def walk(node: Dict[str, Any], prefix: str = "", is_last: bool = True) -> None:
                    if node["id"] in visited_tree:
                        return
                    visited_tree.add(node["id"])
                    branch = "└── " if is_last else "├── "
                    health = f"{node['health_score']}/100" if node["health_score"] is not None else "unscored"
                    claim = f" @{node['claimed_by']}" if node.get("claimed_by") else ""
                    lines.append(
                        f"{prefix}{branch}{node['name']} ({node['slug']}) [{node['system_type']} | {node['status']} | {health}]{claim}"
                    )
                    children = by_parent.get(node["id"], [])
                    for idx, child in enumerate(children):
                        ext = "    " if is_last else "│   "
                        walk(child, prefix + ext, idx == len(children) - 1)

                roots = by_parent.get(None, [])
                for i, r in enumerate(roots):
                    walk(r, "", i == len(roots) - 1)
                print_output(systems, args.json, lines or ["No systems mapped yet."])
                return 0

            if args.sys_cmd == "show":
                s = db.get_system(pid, args.system_ref)
                lines = [
                    f"=== {s['name']} ({s['slug']}) [{s['system_type'].upper()}] ===",
                    f"ID:           {s['id']}",
                    f"Parent:       {s['parent']['name'] + ' (' + s['parent']['slug'] + ')' if s.get('parent') else 'None (Top-Level System)'}",
                    f"Path Scope:   {s['path_scope'] or '(not set)'}",
                    f"Status:       {s['status']} | Health Score: {s['health_score'] if s['health_score'] is not None else 'N/A'}/100",
                    f"Claimed By:   {s['claimed_by'] or 'Unclaimed'} (Lease until: {s['lease_until'] or '-'})",
                    f"Last Audited: {s['last_audited_at'] or '-'} by {s['last_audited_by'] or '-'}",
                    f"Timestamps:   Created {s['created_at']} | Updated {s['updated_at']}",
                    f"Description:  {s['description'] or '-'}",
                    f"Details:      {s['details'] or '-'}",
                    "",
                    f"Subsystems ({len(s['subsystems'])}):",
                ]
                for sub in s["subsystems"]:
                    lines.append(f"  - {sub['name']} ({sub['slug']}) [{sub['status']}]")
                lines.append(f"\nOutbound Relations — Works With ({len(s['outbound_relations'])}):")
                for r in s["outbound_relations"]:
                    lines.append(f"  -> [{r['relation_type']}] {r['target_name']} ({r['target_slug']}) via {r['interface_or_protocol'] or 'direct'}: {r['description']}")
                lines.append(f"\nInbound Relations — Used By ({len(s['inbound_relations'])}):")
                for r in s["inbound_relations"]:
                    lines.append(f"  <- [{r['relation_type']}] {r['source_name']} ({r['source_slug']}) via {r['interface_or_protocol'] or 'direct'}: {r['description']}")
                lines.append(f"\nFindings ({len(s['findings'])}):")
                for f in s["findings"]:
                    lines.append(f"  - [{f['severity'].upper()}] {f['title']} ({f['status']}) by {f.get('agent_id') or 'unknown'}")
                print_output(s, args.json, lines)
                return 0

            if args.sys_cmd == "claim":
                if not args.agent:
                    raise ValueError("Provide agent ID via --agent or $AUDIT_AGENT_ID")
                s = db.claim_system(pid, args.system_ref, args.agent, lease_minutes=args.lease, force=args.force)
                db.sync_static_snapshot(pid)
                print_output(
                    s,
                    args.json,
                    [f"Agent '{args.agent}' claimed {s['system_type']} '{s['name']}' ({s['slug']}) until {s['lease_until']}"],
                )
                return 0

            if args.sys_cmd == "release":
                s = db.release_system(
                    pid,
                    args.system_ref,
                    agent_id=args.agent,
                    status=args.status,
                    health_score=args.health,
                    details_append=args.notes,
                    force=args.force,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    s,
                    args.json,
                    [f"Released '{s['name']}' ({s['slug']}) — status: {s['status']}, health: {s['health_score']}"],
                )
                return 0

        # RELATION SUBCOMMANDS
        if args.command == "relation":
            pid = db.resolve_project_id(args.project)
            if args.rel_cmd == "add":
                rel = db.add_relation(
                    project_id=pid,
                    source_ref=args.source_ref,
                    target_ref=args.target_ref,
                    relation_type=args.type,
                    interface_or_protocol=args.protocol,
                    direction=args.direction,
                    criticality=args.criticality,
                    description=args.desc,
                    details=args.details,
                    agent_id=args.agent,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    rel,
                    args.json,
                    [
                        f"Recorded Relation ({rel['id']}): {rel['source_name']} --[{rel['relation_type']}]--> {rel['target_name']}",
                        f"  Protocol:    {rel['interface_or_protocol'] or 'direct'} ({rel['direction']}, criticality: {rel['criticality']})",
                        f"  Description: {rel['description']}",
                    ],
                )
                return 0

            if args.rel_cmd == "list":
                rels = db.list_relations(pid, system_ref=args.system)
                lines = [
                    f"- {r['source_name']} ({r['source_slug']}) --[{r['relation_type']}]--> {r['target_name']} ({r['target_slug']}) "
                    f"| protocol: {r['interface_or_protocol'] or 'direct'} | criticality: {r['criticality']} | {r['description']}"
                    for r in rels
                ]
                print_output(rels, args.json, lines or ["No cross-system relations recorded."])
                return 0

        # TASK SUBCOMMANDS
        if args.command == "task":
            pid = db.resolve_project_id(args.project)
            if args.task_cmd == "add":
                claim_for = args.agent if args.claim else None
                t = db.create_task(
                    project_id=pid,
                    title=args.title,
                    system_ref=args.system,
                    task_type=args.type,
                    priority=args.priority,
                    description=args.desc,
                    created_by=args.agent,
                    claim_immediately_for=claim_for,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    t,
                    args.json,
                    [
                        f"Created Task {t['id']}: {t['title']}",
                        f"  Priority: {t['priority']} | Type: {t['task_type']} | Status: {t['status']}",
                        f"  System:   {t.get('system_name') or 'Project-wide'}",
                        f"  Claimed:  {t.get('claimed_by') or 'Unclaimed'}",
                    ],
                )
                return 0

            if args.task_cmd == "next":
                if not args.agent:
                    raise ValueError("Provide agent ID via --agent or $AUDIT_AGENT_ID to claim next task.")
                t = db.claim_next_task(
                    project_id=pid,
                    agent_id=args.agent,
                    task_type=args.type,
                    system_ref=args.system,
                    lease_minutes=args.lease,
                )
                db.sync_static_snapshot(pid)
                if not t:
                    print_output({"task": None}, args.json, ["No open tasks matching criteria in queue."])
                else:
                    print_output(
                        t,
                        args.json,
                        [
                            f"Claimed Next Task {t['id']} for agent '{args.agent}':",
                            f"  Title:       {t['title']}",
                            f"  Priority:    {t['priority']} | Type: {t['task_type']}",
                            f"  System:      {t.get('system_name') or 'Project-wide'} ({t.get('system_slug') or '-'})",
                            f"  Lease Until: {t['lease_until']}",
                            f"  Description: {t['description'] or '-'}",
                        ],
                    )
                return 0

            if args.task_cmd == "claim":
                if not args.agent:
                    raise ValueError("Provide agent ID via --agent or $AUDIT_AGENT_ID")
                t = db.claim_task(args.task_id, args.agent, lease_minutes=args.lease, force=args.force)
                db.sync_static_snapshot(pid)
                print_output(
                    t,
                    args.json,
                    [f"Agent '{args.agent}' claimed task {t['id']} ('{t['title']}') until {t['lease_until']}"],
                )
                return 0

            if args.task_cmd == "block":
                t = db.block_task(args.task_id, agent_id=args.agent, reason=args.reason, force=args.force)
                db.sync_static_snapshot(pid)
                print_output(
                    t,
                    args.json,
                    [
                        f"Blocked Task {t['id']}: {t['title']}",
                        f"  Reason: {t.get('blocked_reason') or args.reason}",
                    ],
                )
                return 0

            if args.task_cmd == "complete":
                t = db.complete_task(
                    task_id=args.task_id,
                    agent_id=args.agent,
                    deliverable_summary=args.summary,
                    system_status=args.system_status,
                    system_health_score=args.health,
                    force=args.force,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    t,
                    args.json,
                    [
                        f"Completed Task {t['id']}: {t['title']}",
                        f"  Completed At: {t['completed_at']} by {t.get('claimed_by') or args.agent or 'agent'}",
                        f"  Summary:      {t['deliverable_summary']}",
                    ],
                )
                return 0

            if args.task_cmd == "list":
                tasks = db.list_tasks(
                    pid,
                    status=args.status,
                    agent_id=args.claimed_by,
                    system_ref=args.system,
                )
                lines = [
                    f"- [{t['status'].upper()}] {t['id']} ({t['priority']} / {t['task_type']}): {t['title']} "
                    f"| system: {t.get('system_slug') or 'project'} | agent: {t.get('claimed_by') or '-'}"
                    for t in tasks
                ]
                print_output(tasks, args.json, lines or ["No tasks found."])
                return 0

            if args.task_cmd == "scaffold":
                created = db.scaffold_system_tasks(
                    project_id=pid,
                    system_ref=args.system,
                    created_by=args.agent,
                )
                db.sync_static_snapshot(pid)
                lines = [
                    f"Scaffolded {len(created)} standard audit tasks for system '{args.system}':",
                ]
                for t in created:
                    lines.append(f"  + [{t['task_type']}] {t['title']} ({t['priority']}) [ID: {t['id']}]")
                if not created:
                    lines.append("  (All standard audit task types already exist for this system.)")
                print_output(created, args.json, lines)
                return 0

        # FINDING SUBCOMMANDS
        if args.command == "finding":
            pid = db.resolve_project_id(args.project)
            if args.find_cmd == "add":
                f = db.add_finding(
                    project_id=pid,
                    title=args.title,
                    severity=args.severity,
                    category=args.category,
                    system_ref=args.system,
                    related_system_ref=args.related_system,
                    task_id=args.task,
                    agent_id=args.agent,
                    description=args.desc,
                    details=args.details,
                    file_path=args.file,
                    line_range=args.lines,
                    recommendation=args.recommendation,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    f,
                    args.json,
                    [
                        f"Logged Finding {f['id']} [{f['severity'].upper()} / {f['category']}]: {f['title']}",
                        f"  System:   {f.get('system_name') or 'Project-wide'}",
                        f"  Location: {f['file_path'] or '-'}{':' + f['line_range'] if f.get('line_range') else ''}",
                        f"  Agent:    {f.get('agent_id') or 'unspecified'} at {f['created_at']}",
                    ],
                )
                return 0

            if args.find_cmd == "update":
                f = db.update_finding_status(
                    finding_id=args.finding_id,
                    status=args.status,
                    agent_id=args.agent,
                    recommendation=args.recommendation,
                )
                db.sync_static_snapshot(pid)
                print_output(
                    f,
                    args.json,
                    [f"Updated Finding {f['id']} status -> {f['status']} (at {f['updated_at']})"],
                )
                return 0

            if args.find_cmd == "list":
                findings = db.list_findings(
                    pid,
                    severity=args.severity,
                    category=args.category,
                    status=args.status,
                    system_ref=args.system,
                )
                lines = [
                    f"- [{f['severity'].upper()}] {f['id']} ({f['category']} | {f['status']}): {f['title']} "
                    f"| system: {f.get('system_slug') or 'project'} | by: {f.get('agent_id') or '-'}"
                    for f in findings
                ]
                print_output(findings, args.json, lines or ["No findings logged."])
                return 0

        parser.print_help()
        return 0

    except Exception as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()

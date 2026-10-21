# Adversarial Review Final Adjudication Report: AuditOS Regression Audit (Run 20261021-144559)

## 1. Executive Summary & Verdict

- **Overall Grade**: **D+ (Substandard / Severe Concurrency Invariant & Security Regressions)**
- **Critical Stats**:
  - Previous Verified Findings Audited: 38
  - Truly Watertight Remediations: 23 / 38 (60.5%)
  - Regressed / Incomplete / Bypassed Remediations: 15 / 38 (39.5%)
  - Verified Regression Findings: 19 (1 CRITICAL, 10 HIGH, 5 MEDIUM, 3 LOW)
  - Refuted Findings: 1 (F-39 Origin: null exfiltration in modern browsers)
  - Automated Test Coverage: 16 unit tests; Line coverage: `audit_db.py` 45.7%, `audit_server.py` 28.3%, `audit_cli.py` 20.6% (0% CLI command execution coverage)
  - Hollow / Tautological Assertions in Test Suite: 4 confirmed
- **Executive Verdict**: **DO NOT SHIP / FIX FIRST**
- **5-Line Rationale**:
  1. **Core Vulnerability Masking Regressed (CRITICAL)**: The fix for F-02 is bypassed by passing `--system-status healthy` or invoking `upsert_system()`/`release_system()`, turning dashboard metrics green despite unresolved Critical/High RCE vulnerabilities.
  2. **Security Controls Leaking (HIGH)**: `audit_server.py` lacks HTTP `Host` header validation (permitting full REST API exfiltration via DNS rebinding), HTML entity escaping is completely undone by HTML5 entity decoding in inline event handlers (Stored XSS), and `POST /api/seed-demo` wipes the database without confirmation.
  3. **Multi-Agent Invariant Breakdown (HIGH)**: Omitting `agent_id` bypasses task completion ownership checks, unassigned task completion revokes unrelated agents' active system leases, and completing a task prematurely clears system claims while an agent holds other tasks.
  4. **Task Queue Starvation & Concurrency Wedges (HIGH)**: Offline heartbeat resets poison pill tasks to `'open'`, permanently starving workers; newly added `block_task()` lacks caller ownership checks, regresses completed tasks, and orphans agent pointers and system leases.
  5. **Hollow Test Suite Masking Failures (HIGH)**: The 16-test suite contains assertion tautologies (checking leases against `"2099-01-01"`, checking `"db_path"` instead of `"database"`), zero CLI execution coverage, and 86% HTTP endpoint omission.

---

## 2. Verified Regression Findings Ranked by Severity & Confidence

### CRITICAL SEVERITY

#### RF-01 | CRITICAL | conf:HIGH | Open Critical/High Vulnerability Masking via `system_status="healthy"` and Direct Status Overwrites Defeats F-02 Remediation
- **Where**: [audit_db.py:903-935](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L903-L935), [audit_db.py:751-775](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L751-L775), [audit_db.py:968-985](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L968-L985), [audit_db.py:1740-1767](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1740-L1767), [audit_cli.py:167](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_cli.py#L167)
- **Angles Agreed**: `spec-reality` (F-39), `failure-modes` (F-02), `test-quality` (F-02), `skeptic/failure-modes` (M-01), `skeptic/spec-reality` (F-39). Confirmed CRITICAL by review-judge.
- **Problem**: Finding F-02 was designed to prevent systems with unresolved Critical and High vulnerabilities from being marked safe or reviewed. In `_compute_post_audit_system_status()`, lines 921-924 check:
  ```python
  if open_crit_high > 0 and requested_status in (None, "reviewed"):
      return "needs_attention"
  if requested_status:
      return requested_status
  ```
  `VALID_SYSTEM_STATUSES` includes `"healthy"`, and `audit_cli.py:167` explicitly offers `--system-status healthy`. When an agent or operator passes `system_status="healthy"` (via `audit task complete --status healthy`, `audit system release --status healthy`, or REST API `POST /api/tasks/complete`), `"healthy"` is NOT in `(None, "reviewed")`. Line 921 evaluates to `False`, line 923 executes, and `"healthy"` is returned. The parent system's status in `systems` is set to `"healthy"`, masking open Critical vulnerabilities and turning the UI dashboard green.
  Furthermore, `upsert_system()` (lines 760-775) directly overwrites `status = ?` without calling `_compute_post_audit_system_status()` at all, allowing arbitrary status changes on compromised systems.
- **Concrete Scenario / Repro**:
  ```python
  from audit_db import AuditDB
  db = AuditDB(":memory:")
  p = db.create_project("Alpha")
  s = db.upsert_system(p["id"], "Auth Gateway", slug="auth-gw")
  t = db.create_task(p["id"], "Audit Auth", system_ref="auth-gw", claim_immediately_for="agent-1")
  db.add_finding(p["id"], title="Remote Code Execution", severity="critical", system_ref="auth-gw", agent_id="agent-1")
  # System is currently 'needs_attention' with 1 open critical finding
  db.complete_task(t["id"], agent_id="agent-1", deliverable_summary="Reviewed", system_status="healthy")
  sys_after = db.get_system(p["id"], "auth-gw")
  assert sys_after["status"] == "needs_attention"  # FAILS: sys_after["status"] is 'healthy'!
  ```
- **Actionable Remediation**:
  1. In `audit_db.py:921`, update the condition to block any clean/benign status transition when open Critical or High findings exist:
     ```python
     if open_crit_high > 0 and requested_status in (None, "reviewed", "healthy", "unreviewed"):
         return "needs_attention"
     ```
  2. In `upsert_system()` ([audit_db.py:760](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L760)), invoke `_compute_post_audit_system_status(conn, sid, existing["status"], status)` if `status` is provided.

---

### HIGH SEVERITY

#### RF-02 | HIGH | conf:HIGH | Missing `Host` Header Validation Enables Full REST API Exfiltration via DNS Rebinding
- **Where**: [audit_server.py:47-74](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L47-L74), [audit_server.py:125-148](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L125-L148)
- **Angles Agreed**: `security` (F-40), `skeptic/security` (F-40). Confirmed HIGH by review-judge.
- **Problem**: `audit_server.py` performs no inspection or validation of the HTTP `Host` header. An attacker who controls a domain (e.g., `rebind.attacker.com:8420`) with a short DNS TTL points it to their server, waits for the victim developer to visit, and then rebinds the domain to `127.0.0.1`.
  Because the browser considers requests to `rebind.attacker.com:8420` to be same-origin:
  1. The browser omits the `Origin` header on standard GET requests.
  2. The browser attaches `Sec-Fetch-Site: same-origin`.
  3. The browser attaches `Host: rebind.attacker.com:8420`.
  In `_check_origin_and_csrf(is_mutation=False)`, `origin` is `None` (bypassing `is_allowed_origin`) and `sec_fetch_site` is `"same-origin"` (bypassing the cross-site check). The server returns `200 OK` with the complete database snapshot (`GET /api/snapshot`), and the browser allows attacker JavaScript to read and exfiltrate all audit findings and architectural details.
- **Concrete Scenario / Repro**:
  ```bash
  curl -i http://127.0.0.1:8420/api/snapshot \
    -H "Host: rebind.attacker.com:8420" \
    -H "Sec-Fetch-Site: same-origin"
  ```
  Returns `HTTP/1.0 200 OK` with the full audit snapshot despite the hostile `Host` header.
- **Actionable Remediation**:
  In `_check_origin_and_csrf()` ([audit_server.py:47](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L47)), inspect the `Host` header. Reject requests where `Host` does not match `^(localhost|127\.0\.0\.1)(:\d+)?$` with HTTP 403 Forbidden.

---

#### RF-03 | HIGH | conf:HIGH | Ineffective Stored XSS Remediation: HTML Entity Decoding in Inline Event Attributes Enables Arbitrary JavaScript Execution
- **Where**: [ui/app.js:12-21](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L12-L21), [ui/app.js:238](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L238), [ui/app.js:312](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L312), [ui/app.js:415-421](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L415-L421), [ui/app.js:762](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L762), [ui/app.js:823-825](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L823-L825), [ui/app.js:872-878](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L872-L878), [ui/app.js:1039](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L1039), [audit_db.py:529-535](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L529-L535)
- **Angles Agreed**: `security` (F-41), `skeptic/security` (F-41). Confirmed HIGH by review-judge.
- **Problem**: The fix for F-06 modified `esc()` to replace `'` with `&#39;` and `\` with `&#92;`. However, all interactive elements in `ui/app.js` interpolate entity-escaped IDs directly into inline JavaScript event handlers (e.g., `onclick="selectSystem('${esc(sys.id)}')"` or `onclick="setActiveAgent('${esc(a.id)}')"`).
  Under HTML5 Section 13.2.5.38, browser HTML parsers decode all HTML character entities (`&#39;` -> `'`, `&quot;` -> `"`, `&amp;` -> `&`) inside attribute values *before* passing the string to the JavaScript engine for execution.
  Because entity IDs (`agent.id`, `system.id`, `task.id`, `finding.id`) accept unvalidated strings, an attacker or agent who registers an agent or creates a system with an apostrophe breaks out of the JavaScript string literal and executes arbitrary code upon user interaction.
- **Concrete Scenario / Repro**:
  1. Register an agent with an injection payload:
     ```bash
     curl -X POST http://127.0.0.1:8420/api/agents/register \
       -H "Content-Type: application/json" \
       -d '{"id": "agent\x27);alert(document.domain);//", "name": "Security Worker"}'
     ```
  2. Open the AuditOS dashboard at `http://127.0.0.1:8420/` and navigate to Tab 3 ("Multi-Agent Workforce & Tasks").
  3. Click "Act as @agent');alert(document.domain);//".
  4. The browser parses `onclick="setActiveAgent('agent&#39;);alert(document.domain);//')"` -> decodes `&#39;` to `'` -> compiles and executes `setActiveAgent('agent');alert(document.domain);//')`, firing `alert(document.domain)`.
- **Actionable Remediation**:
  1. Do not interpolate dynamic values into inline `onclick="..."` attributes. Use HTML5 `data-*` attributes (e.g. `<button class="btn-agent" data-agent-id="${esc(a.id)}">`) and attach delegated event listeners with `addEventListener` that read `event.target.dataset.agentId`.
  2. In `audit_db.py`, enforce an alphanumeric identifier regex `^[a-zA-Z0-9_-]+$` on `agent_id`, `system_id`, and `task_id`.

---

#### RF-04 | HIGH | conf:HIGH | Unauthenticated Database Purge via `POST /api/seed-demo` Bypasses Reset Confirmation Defense
- **Where**: [audit_server.py:449-453](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L449-L453), [audit_db.py:2297-2303](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L2297-L2303)
- **Angles Agreed**: `security` (F-42), `skeptic/security` (F-42). Confirmed HIGH by review-judge.
- **Problem**: Finding F-01 added a confirmation payload check `if body.get("confirm") != "RESET":` to `POST /api/reset` to prevent unauthenticated database destruction. However, `POST /api/seed-demo` calls `self.db.seed_demo_data(reset_first=bool(body.get("reset_first", True)))`. Because `reset_first` defaults to `True`, an unauthenticated client or agent can send `POST /api/seed-demo` with an empty JSON object `{}`, which directly invokes `self.reset_database()`. This permanently deletes all existing projects, systems, audit findings, tasks, and audit logs without requiring `{"confirm": "RESET"}` or any authentication.
- **Concrete Scenario / Repro**:
  ```bash
  curl -i -X POST http://127.0.0.1:8420/api/seed-demo \
    -H "Content-Type: application/json" \
    -d '{}'
  ```
  Returns `HTTP/1.0 200 OK`. All active audit projects, systems, and findings are permanently wiped and replaced with demo data.
- **Actionable Remediation**:
  In `audit_server.py:450`, default `reset_first` to `False`. If `reset_first` is `True`, require `body.get("confirm") == "RESET"`:
  ```python
  if path == "/api/seed-demo":
      reset_first = bool(body.get("reset_first", False))
      if reset_first and body.get("confirm") != "RESET":
          self._send_json({"error": "Resetting existing data requires 'confirm': 'RESET'."}, status=400)
          return
  ```

---

#### RF-05 | HIGH | conf:HIGH | Task Completion Ownership Bypass When `agent_id` Is Omitted Bypasses F-14 Claim Protection
- **Where**: [audit_db.py:1701-1708](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1701-L1708), [audit_server.py:249-250](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L249-L250)
- **Angles Agreed**: `failure-modes` (F-01), `skeptic/failure-modes` (F-01). Confirmed HIGH by review-judge.
- **Problem**: In `complete_task()`, the claim ownership check is implemented as:
  ```python
  holder = t["claimed_by"]
  if holder and agent_id and agent_id != holder and not force:
      raise RuntimeError(
          f"Task '{task_id}' is claimed by '{holder}', not '{agent_id}' (pass force=True to override)."
      )
  effective_agent = agent_id or holder
  ```
  Because the condition specifies `and agent_id`, whenever `agent_id` is `None` (which occurs when CLI `./audit task complete <id>` is called without `--agent`, or `POST /api/tasks/complete` is called without `agent_id` or `X-Agent-Id`), the conditional expression evaluates to `None` (falsy) and is completely bypassed. `effective_agent` falls back to `holder`. An unauthorized caller or competing agent can complete any agent's in-flight task, overwrite its deliverable summary, clobber completion timestamps, and forge audit log actions attributed to `holder` without `force=True`.
- **Concrete Scenario / Repro**:
  1. Agent Alice claims a task: `t = db.claim_task(task_id, "agent-alice")`.
  2. An attacker or anonymous caller invokes `db.complete_task(task_id, agent_id=None, deliverable_summary="Compromised deliverable")`.
  3. The call succeeds with HTTP 200 / exit code 0.
  4. Task `t` is marked `completed`, deliverable summary is replaced with `"Compromised deliverable"`, and `audit_logs` records `action="task.completed"`, `agent_id="agent-alice"`, falsely attributing the forged deliverable to Alice.
- **Actionable Remediation**:
  In `complete_task()`, reject callers who do not match `holder` unless `force=True`:
  ```python
  if holder and not force and agent_id != holder:
      raise RuntimeError(
          f"Task '{task_id}' is claimed by '{holder}', not '{agent_id or 'anonymous'}' (pass force=True to override)."
      )
  ```

---

#### RF-06 | HIGH | conf:HIGH | `block_task()` Lacks Caller Ownership Verification, Mutates Completed Tasks, and Orphans System Locks
- **Where**: [audit_db.py:1630-1670](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1630-L1670), [audit_server.py:396-403](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L396-L403), [audit_cli.py:160-163](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_cli.py#L160-L163)
- **Angles Agreed**: `spec-reality` (F-40), `failure-modes` (F-05), `skeptic/spec-reality` (F-40), `skeptic/failure-modes` (F-05). Confirmed HIGH by review-judge.
- **Problem**: Finding F-33 added `block_task()` and `/api/tasks/block`. Unlike `complete_task()` and `release_system()`, `block_task()` implements zero caller ownership validation:
  1. Any caller can block another agent's active in-flight task without `force=True`.
  2. Line 1641 sets `effective_agent = agent_id or t["claimed_by"]`. If Agent B blocks Agent A's task, `effective_agent` is Agent B. Line 1657 executes `UPDATE agents ... WHERE id = Agent B AND current_task_id = task_id`, which updates 0 rows for Agent A. Agent A is left permanently desynchronized with `current_task_id = task_id`.
  3. Line 1665 executes `UPDATE systems ... WHERE id = system_id AND claimed_by = Agent B`. Since the system was claimed by Agent A, 0 rows update, leaving the system locked until lease expiration while the task is blocked.
  4. `block_task()` does not check `if t["status"] == "completed"`, allowing completed tasks to be regressed into `blocked`, corrupting completed deliverables and project metrics.
- **Concrete Scenario / Repro**:
  ```python
  # Alice claims task-1 on system auth-gw
  db.claim_task(t1["id"], "agent-alice")
  # Bob blocks Alice's task
  db.block_task(t1["id"], agent_id="agent-bob", reason="Blocked by rival")
  # Check Alice's state
  alice = [a for a in db.list_agents(p["id"]) if a["id"] == "agent-alice"][0]
  assert alice["current_task_id"] is None  # FAILS: alice["current_task_id"] is still t1["id"]!
  sys_obj = db.get_system(p["id"], "auth-gw")
  assert sys_obj["claimed_by"] is None  # FAILS: sys_obj["claimed_by"] is still 'agent-alice'!
  ```
- **Actionable Remediation**:
  In `block_task()`, enforce ownership and completed-status guards:
  ```python
  if t["status"] == "completed" and not force:
      raise RuntimeError(f"Task '{task_id}' is already completed (pass force=True to override).")
  holder = t["claimed_by"]
  if holder and not force and agent_id != holder:
      raise RuntimeError(f"Task '{task_id}' is claimed by '{holder}', not '{agent_id}' (pass force=True to override).")
  # Clear holder's pointers regardless of caller identity
  if holder:
      conn.execute("UPDATE agents SET current_task_id = NULL WHERE id = ? AND current_task_id = ?", (holder, task_id))
      if t["system_id"]:
          conn.execute("UPDATE systems SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL, updated_at = ? WHERE id = ? AND claimed_by = ?", (now, t["system_id"], holder))
  ```

---

#### RF-07 | HIGH | conf:HIGH | Premature System Claim and Agent Association Revocation When Agent Holds Additional Claimed Tasks
- **Where**: [audit_db.py:1726-1735](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1726-L1735), [audit_db.py:1743-1767](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1743-L1767)
- **Angles Agreed**: `failure-modes` (F-03), `skeptic/failure-modes` (F-03). Confirmed HIGH by review-judge.
- **Problem**: When an agent completes a task associated with a system, lines 1746-1748 unconditionally clear the system lease (`claimed_by = NULL`, `lease_until = NULL`), and line 1730 clears the agent's `current_system_id = NULL`. This query never checks whether `effective_agent` still has *other active tasks* (`status = 'claimed'`) on that system. If an agent is assigned multiple tasks for a system, completing the first task prematurely releases the system lock. A parallel agent can immediately acquire the system via `claim_system()` or `claim_next_task()`, causing two agents to audit the same system concurrently and breaking the exclusive system lease invariant.
- **Concrete Scenario / Repro**:
  1. System `sys-1` has two tasks: `t1` and `t2`.
  2. Agent Alice claims both `t1` and `t2` on `sys-1`. `sys-1.claimed_by` is `'agent-alice'`.
  3. Alice completes `t1`: `db.complete_task(t1["id"], "agent-alice")`.
  4. System `sys-1.claimed_by` is now `NULL`, and Alice's `current_system_id` is set to `NULL`, despite `t2` remaining claimed by Alice on `sys-1`.
  5. Agent Bob calls `db.claim_system(p["id"], "sys-1", "agent-bob")`. The claim succeeds.
  6. Alice and Bob now simultaneously audit `sys-1`.
- **Actionable Remediation**:
  In `complete_task()`, only release `systems.claimed_by` and `agents.current_system_id` if the agent has no remaining claimed tasks on that system:
  ```python
  remaining_active = conn.execute(
      "SELECT COUNT(*) AS cnt FROM tasks WHERE system_id = ? AND claimed_by = ? AND status = 'claimed' AND id != ?",
      (t["system_id"], effective_agent, task_id)
  ).fetchone()["cnt"]
  if remaining_active == 0:
      # Clear systems.claimed_by, lease_until, and agents.current_system_id
  ```

---

#### RF-08 | HIGH | conf:HIGH | Completion of Unassigned Tasks Forcibly Revokes Unrelated Agents' Active System Claims
- **Where**: [audit_db.py:1746-1766](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1746-L1766)
- **Angles Agreed**: `spec-reality` (F-41), `skeptic/spec-reality` (F-41). Confirmed HIGH by review-judge.
- **Problem**: In `complete_task()`, lines 1746-1748 execute:
  ```sql
  UPDATE systems
  SET claimed_by = CASE WHEN claimed_by = ? OR ? IS NULL THEN NULL ELSE claimed_by END,
      claimed_at = CASE WHEN claimed_by = ? OR ? IS NULL THEN NULL ELSE claimed_at END,
      lease_until = CASE WHEN claimed_by = ? OR ? IS NULL THEN NULL ELSE lease_until END
  WHERE id = ?
  ```
  When completing a task where `agent_id` is `None` and `t["claimed_by"]` is `None` (an unassigned task completed without `--agent`), `effective_agent` is `None`. In SQLite, `? IS NULL` evaluates to `NULL IS NULL`, which is `TRUE`. The CASE statement evaluates to `THEN NULL`, unconditionally clearing `claimed_by`, `claimed_at`, and `lease_until` on the target system even if an unrelated agent currently holds an exclusive active lease on that system.
- **Concrete Scenario / Repro**:
  1. Agent Alice acquires a 60-minute exclusive lock on system `billing`:
     `./audit system claim billing --agent agent-alice --lease 60`
  2. An unassigned task `task-2` on `billing` is completed without providing `--agent`:
     `./audit task complete task-2 --summary "Auto-verified"`
  3. `effective_agent` is `None`, so `? IS NULL` is `True`.
  4. Alice's system lease on `billing` is wiped to `NULL`.
  5. Alice's agent record still shows `current_system_id = 'billing'`, causing state desynchronization.
- **Actionable Remediation**:
  In `audit_db.py:1746-1748`, only release the system claim if the system is actually held by the completing agent:
  ```sql
  SET claimed_by = CASE WHEN ? IS NOT NULL AND claimed_by = ? THEN NULL ELSE claimed_by END,
      claimed_at = CASE WHEN ? IS NOT NULL AND claimed_by = ? THEN NULL ELSE claimed_at END,
      lease_until = CASE WHEN ? IS NOT NULL AND claimed_by = ? THEN NULL ELSE lease_until END
  ```

---

#### RF-09 | HIGH | conf:HIGH | Task Queue Starvation: Offline Heartbeat Reset Permanently Wedges Poison-Pill Tasks in `'open'`
- **Where**: [audit_db.py:586-593](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L586-L593), [audit_db.py:1532-1546](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1532-L1546), [audit_db.py:1566-1574](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1566-L1574), [audit_db.py:1445-1460](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1445-L1460)
- **Angles Agreed**: `failure-modes` (F-04), `skeptic/failure-modes` (F-04). Confirmed HIGH by review-judge.
- **Problem**: When an agent process reports `status="offline"`, `heartbeat_agent()` resets its claimed tasks back to `status = 'open'` with `claimed_by = NULL` and `lease_until = NULL`, retaining `attempt_count`. If `attempt_count >= max_attempts`:
  1. In `claim_next_task()`, line 1532 only auto-blocks tasks matching `WHERE status = 'claimed' AND lease_until IS NOT NULL AND lease_until < ?`. Because the task is now `'open'` and `lease_until IS NULL`, it is never transitioned to `'blocked'`.
  2. In candidate selection (line 1567), `claim_next_task()` requires `AND t.attempt_count < t.max_attempts`. Because `attempt_count >= max_attempts`, it is never selected.
  The task is permanently stuck in `status = 'open'`. It is never blocked and cannot be claimed by any worker, silently wedging the task queue.
  Furthermore, `claim_task()` (by ID) omits checking `attempt_count < max_attempts`, allowing poison pill tasks to be claimed manually repeatedly without dead-letter blocking.
- **Concrete Scenario / Repro**:
  ```python
  p = db.ensure_default_project()
  t = db.create_task(p["id"], "Failing Task", max_attempts=1)
  db.claim_next_task(p["id"], "agent-1") # attempt_count becomes 1
  db.heartbeat_agent("agent-1", status="offline") # status reset to 'open', attempt_count remains 1
  # Next worker attempts to claim next task
  next_task = db.claim_next_task(p["id"], "agent-2")
  assert next_task is None
  # Task is neither claimed nor blocked; it is stuck in 'open' forever
  assert len(db.list_tasks(p["id"], status="open")) == 1
  assert len(db.list_tasks(p["id"], status="blocked")) == 0 # FAILS to be transitioned to blocked
  ```
- **Actionable Remediation**:
  In `claim_next_task()`, update the auto-block query to also block open tasks that have reached `max_attempts`:
  ```sql
  UPDATE tasks
  SET status = 'blocked',
      blocked_reason = 'Exceeded max_attempts (' || max_attempts || ')',
      lease_until = NULL,
      updated_at = ?
  WHERE project_id = ?
    AND status IN ('open', 'claimed')
    AND attempt_count >= max_attempts
    AND (status = 'open' OR (lease_until IS NOT NULL AND lease_until < ?))
  ```
  In `claim_task()`, raise `RuntimeError` if `attempt_count >= max_attempts` unless `force=True`.

---

#### RF-10 | HIGH | conf:HIGH | Unchecked Transitive System Hierarchy Cycles Cause Server `RecursionError` and Web UI `RangeError` Crashes
- **Where**: [audit_db.py:753-755](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L753-L755), [audit_db.py:2222-2224](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L2222-L2224), [ui/app.js:257](file:///Users/kaizenpro/Desktop/general-project-audit-system/ui/app.js#L257)
- **Angles Agreed**: `skeptic/security` (F-43 Missed), review-judge verification. Confirmed HIGH.
- **Problem**: `upsert_system()` only checks for immediate self-parenting (`if parent_id == sid: raise ValueError("A system cannot be its own parent.")`). It does not perform transitive ancestor cycle detection. A caller can set System A's parent to B, and B's parent to A (or A -> B -> C -> A).
  When a cycle exists:
  1. Calling `GET /api/export/markdown` causes `render_sys` in `audit_db.py:2223` to recurse infinitely until crashing with `RecursionError: maximum recursion depth exceeded`.
  2. Opening the Web UI causes `renderNode` in `ui/app.js:257` to recurse infinitely until crashing with `RangeError: Maximum call stack size exceeded`, rendering the entire dashboard completely blank.
- **Concrete Scenario / Repro**:
  ```python
  p = db.ensure_default_project()
  s1 = db.upsert_system(p["id"], "Node 1", slug="node-1")
  s2 = db.upsert_system(p["id"], "Node 2", slug="node-2", parent_ref="node-1")
  # Update Node 1 to make Node 2 its parent
  db.upsert_system(p["id"], "Node 1", slug="node-1", parent_ref="node-2")
  # Exporting report or loading UI crashes with infinite recursion
  db.export_markdown_report(p["id"]) # Crashes with RecursionError!
  ```
- **Actionable Remediation**:
  1. In `upsert_system()`, before updating `parent_id`, traverse upwards from `new_parent` to the root. If `sid` is encountered in the ancestor chain, raise `ValueError("Hierarchy cycle detected: system cannot be an ancestor of itself.")`.
  2. In `export_markdown_report` (`render_sys`) and `ui/app.js` (`renderNode`), maintain a `visited = set()` to break circular rendering gracefully.

---

#### RF-11 | HIGH | conf:HIGH | Hollow Tests, Tautological Assertions, and Wrong-Key Validations Mask Critical Regressions
- **Where**: [tests/test_auditos.py:161](file:///Users/kaizenpro/Desktop/general-project-audit-system/tests/test_auditos.py#L161), [tests/test_auditos.py:288-291](file:///Users/kaizenpro/Desktop/general-project-audit-system/tests/test_auditos.py#L288-L291), [tests/test_auditos.py:171-192](file:///Users/kaizenpro/Desktop/general-project-audit-system/tests/test_auditos.py#L171-L192), [tests/test_auditos.py:19-56](file:///Users/kaizenpro/Desktop/general-project-audit-system/tests/test_auditos.py#L19-L56)
- **Angles Agreed**: `test-quality` (F-01, F-02, F-04), `skeptic/test-quality` (F-01, F-02, F-04, M-01). Confirmed HIGH by review-judge.
- **Problem**: Hostility analysis and mutation testing revealed critical assertion tautologies:
  1. **Wrong key checked for path disclosure (F-31)**: `test_f30_and_f31` asserts `self.assertNotIn("db_path", data)`. However, `audit_server.py:140` returns `"database"`, NOT `"db_path"`. Mutating the server to return the raw absolute path (`self.db.db_path`) under key `"database"` passes the test!
  2. **Tautological lease resurrection assertion (F-23)**: `test_f23` asserts `self.assertLess(sys_obj["lease_until"], "2099-01-01")`. In string ordering, any timestamp in 2026 is strictly less than `"2099-01-01"`. Mutating `heartbeat_agent` to resurrect expired leases passes 100% of tests.
  3. **Passthrough status survival (F-02)**: `test_f02` system status is already `'needs_attention'`. Mutating `_compute_post_audit_system_status` to `return current_status` passes tests.
  4. **Unasserted CORS headers**: `MockRequestHandler` records `response_headers`, but no test inspects them. Deleting `_apply_cors_headers` or setting wildcard `*` passes tests.
- **Actionable Remediation**:
  1. In `test_f30_and_f31`, assert `self.assertNotIn("/", data["database"])` and `self.assertNotIn("\\", data["database"])`.
  2. In `test_f23`, assert `sys_obj["lease_until"] < utc_now_iso()`.
  3. In `test_f02`, test explicit transitions: `complete_task(..., system_status="reviewed")` must force `'needs_attention'`.
  4. Assert `response_headers.get("Access-Control-Allow-Origin")` across HTTP tests.

---

### MEDIUM SEVERITY

#### RF-12 | MEDIUM | conf:HIGH | Expired Lease Reclamation in `claim_next_task` and `claim_task` Leaves Stale Pointers in Agent Roster
- **Where**: [audit_db.py:1469-1476](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1469-L1476), [audit_db.py:1595-1603](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1595-L1603), [audit_db.py:633-650](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L633-L650)
- **Angles Agreed**: `failure-modes` (F-06), `skeptic/failure-modes` (F-06). Confirmed MEDIUM by review-judge.
- **Problem**: When an agent's lease expires on a task and system, another agent re-claims the task via `claim_next_task()` or `claim_task()`. While `tasks.claimed_by` and `systems.claimed_by` are reassigned to the new agent, neither method clears `current_task_id` or `current_system_id` on the previous agent record in `agents`. In `list_agents()` and the Web UI, both the old and new agents are displayed as simultaneously working on the exact same task.
- **Actionable Remediation**:
  In `claim_next_task()` and `claim_task()`, before assigning to the new agent, clear `current_task_id` and `current_system_id` on any previous agent:
  ```python
  conn.execute("UPDATE agents SET current_task_id = NULL WHERE current_task_id = ? AND id != ?", (tid, agent_id))
  ```

---

#### RF-13 | MEDIUM | conf:HIGH | Synchronous Disk Snapshot Sync on Every Mutation Causes I/O Saturation and Multi-Project File Clobbering
- **Where**: [audit_db.py:277-278](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L277-L278), [audit_db.py:306-333](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L306-L333), [tests/test_auditos.py:347-352](file:///Users/kaizenpro/Desktop/general-project-audit-system/tests/test_auditos.py#L347-L352)
- **Angles Agreed**: `failure-modes` (F-07), `test-quality` (F-03), `skeptic/failure-modes` (F-07), `skeptic/test-quality` (F-03). Confirmed MEDIUM by review-judge.
- **Problem**: `AuditDB.connect(immediate=True)` triggers `self.sync_static_snapshot()` on every single write transaction. Every agent heartbeat, relation addition, finding creation, and task claim executes 8 sequential queries, serializes JSON, and calls physical `os.fsync(f.fileno())`. Under multi-agent concurrency, this saturates disk I/O. Furthermore, `sync_static_snapshot()` defaults `project_ref=None`, causing multi-project environments to overwrite `ui/snapshot.js` with whichever project wrote last. In addition, `test_f07` mutates the host repository's `ui/snapshot.js` during test runs.
- **Actionable Remediation**:
  Decouple `sync_static_snapshot()` from `connect(immediate=True)`. Only sync `ui/snapshot.js` on explicit CLI export/seed commands or via a background thread with debounce, and pass the explicit `project_id`. Parameterize `AuditDB` to accept a custom `ui_dir` for hermetic test execution.

---

#### RF-14 | MEDIUM | conf:HIGH | Unvalidated `task_id` in `add_finding()` Aborts Transactions with Raw `sqlite3.IntegrityError`
- **Where**: [audit_db.py:1860-1896](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1860-L1896), [audit_cli.py:710-715](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_cli.py#L710-L715)
- **Angles Agreed**: `spec-reality` (F-42), `skeptic/spec-reality` (F-42). Confirmed MEDIUM by review-judge.
- **Problem**: `findings` enforces `FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL`. In `add_finding()`, `system_ref` is validated via `_resolve_system_in_conn` and raises a clean `ValueError`. However, `task_id` is passed directly into SQL `INSERT` without checking if the task exists. Passing a non-existent task ID aborts the transaction with `sqlite3.IntegrityError: FOREIGN KEY constraint failed`, crashing CLI commands with a raw database exception rather than domain error `ValueError: Task '...' not found.`
- **Actionable Remediation**:
  In `add_finding()`, if `task_id` is provided, verify `SELECT id FROM tasks WHERE id = ? AND project_id = ?`. If not found, raise `ValueError(f"Task '{task_id}' not found.")`.

---

#### RF-15 | MEDIUM | conf:HIGH | Unbounded or Negative `limit` in `GET /api/logs` Bypasses Pagination Controls via SQLite `LIMIT -1`
- **Where**: [audit_server.py:206](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L206), [audit_db.py:1666](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L1666)
- **Angles Agreed**: `skeptic/security` (F-44 Missed). Confirmed MEDIUM by review-judge.
- **Problem**: In `audit_server.py:206`, `limit` is parsed as `int(q1("limit", "100") or "100")` without bounds validation. In SQLite, `LIMIT -1` returns all records without limit. An external caller can send `GET /api/logs?limit=-1` to dump hundreds of thousands of audit records in a single payload, bypassing pagination and causing memory exhaustion.
- **Actionable Remediation**:
  Enforce strict bounds: `limit = max(1, min(int(raw_limit), 500))`.

---

#### RF-16 | MEDIUM | conf:HIGH | Agent Offline Heartbeat Releases System Claim but Leaves Orphaned `systems.status = 'in_progress'`
- **Where**: [audit_db.py:586-620](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L586-L620)
- **Angles Agreed**: `skeptic/failure-modes` (M-02 Missed). Confirmed MEDIUM by review-judge.
- **Problem**: When an agent reports `status="offline"`, `heartbeat_agent()` releases system claims (`UPDATE systems SET claimed_by = NULL, claimed_at = NULL, lease_until = NULL WHERE claimed_by = ?`). However, it never resets `systems.status`. Systems that were in active audit remain permanently stuck in `status = 'in_progress'` with no agent auditing them.
- **Actionable Remediation**:
  In `heartbeat_agent()` when releasing system locks, if no other active tasks are claimed on that system, reset `systems.status` back to `'unreviewed'` (or `'needs_attention'` if open critical/high findings exist).

---

### LOW SEVERITY

#### RF-17 | LOW | conf:HIGH | CLI `--json` Contract Violation in `audit export` Emits Markdown Output
- **Where**: [audit_cli.py:287-300](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_cli.py#L287-L300), [AGENT_GUIDE.md:10](file:///Users/kaizenpro/Desktop/general-project-audit-system/AGENT_GUIDE.md#L10)
- **Angles Agreed**: `spec-reality` (F-43), `skeptic/spec-reality` (F-43). Confirmed LOW by review-judge.
- **Problem**: `AGENT_GUIDE.md` principle #2 states that "Every `./audit` command supports `--json`". However, `audit export` defines an independent `--format` flag defaulting to `"md"`. When an automated agent calls `./audit export --json` without `--output`, line 288 checks `if args.format == "json":` (which is False), generating and printing raw Markdown to stdout and breaking agent JSON parsers.
- **Actionable Remediation**:
  In `audit_cli.py:288`, check `if args.format == "json" or args.json:`.

---

#### RF-18 | LOW | conf:HIGH | Non-Atomic Project Resolution in `get_project_snapshot` Triggers Unhandled `TypeError`
- **Where**: [audit_db.py:2091-2094](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_db.py#L2091-L2094), [audit_server.py:233-236](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_server.py#L233-L236)
- **Angles Agreed**: `failure-modes` (F-08), `skeptic/failure-modes` (F-08). Confirmed LOW by review-judge.
- **Problem**: In `get_project_snapshot()`, line 2091 resolves `project_id = self.resolve_project_id(project_ref)` outside the connection transaction. Then line 2092 opens `with self.connect() as conn:`, and line 2093 executes `project = dict(conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone())`. If the database is reset or the project is deleted between lines 2091 and 2093, `fetchone()` returns `None`, and `dict(None)` raises an unhandled `TypeError: 'NoneType' object is not iterable` rather than a clean `ValueError` or HTTP 404.
- **Actionable Remediation**:
  Execute `resolve_project_id` inside the connection and check `if not row: raise ValueError(f"Project '{project_id}' not found.")`.

---

#### RF-19 | LOW | conf:HIGH | `AGENT_GUIDE.md` Onboarding Sequences Agent Registration Before `init`, Creating Zombie Default Project
- **Where**: [AGENT_GUIDE.md:21-45](file:///Users/kaizenpro/Desktop/general-project-audit-system/AGENT_GUIDE.md#L21-L45), [audit_cli.py:315](file:///Users/kaizenpro/Desktop/general-project-audit-system/audit_cli.py#L315)
- **Angles Agreed**: `spec-reality` (F-44), `skeptic/spec-reality` (F-44). Confirmed LOW by review-judge.
- **Problem**: `AGENT_GUIDE.md` Step 1 instructs agents to run `./audit agent register` before running `./audit init` in Step 2. On a fresh database, `agent register` calls `resolve_project_id(None)`, which auto-creates `Default Project Audit` (`default-project-audit`) and registers the agent to it. When the agent runs Step 2 (`./audit init --name "My Codebase"`), a second project is created, but the agent remains registered under the unwanted default project.
- **Actionable Remediation**:
  In `AGENT_GUIDE.md`, swap Step 1 and Step 2 so that `./audit init` precedes `./audit agent register`.

---

## 3. Verification Status of Previous 38 Findings

| ID | Title | Status | Regression & Verification Analysis |
|:---|:---|:---|:---|
| **F-01** | Wildcard CORS & Remote Wipe | **REGRESSED / INCOMPLETE** | CORS restricted, but `POST /api/seed-demo` wipes without confirmation (RF-04) and missing `Host` validation allows DNS rebinding exfiltration (RF-02). |
| **F-02** | Masking Critical Findings | **REGRESSED / BYPASSED** | `_compute_post_audit_system_status()` is bypassed by `--system-status healthy`, `upsert_system`, and `release_system` (RF-01). |
| **F-03** | `claim_next_task` Stealing Claims | **REGRESSED / PARTIAL** | Unassigned task completion wipes active system claims (RF-08); task completion prematurely releases system lock when agent holds other tasks (RF-07). |
| **F-04** | Total Absence of Automated Test Suite | **PARTIALLY REMEDIATED** | 16 tests added in `tests/test_auditos.py`, but hollow assertions, tautologies, and 0% CLI execution coverage mask critical regressions (RF-11). |
| **F-05** | Missing Content-Type CSRF | **REGRESSED / INCOMPLETE** | Enforced `application/json`, but DNS rebinding bypasses origin checks, and unauthenticated `seed-demo` wipes with `{}`. |
| **F-06** | Stored XSS in Web UI | **INEFFECTIVE / REGRESSED** | `&#39;` is decoded by HTML parser in inline `onclick` attributes before JavaScript executes, re-enabling Stored XSS (RF-03). |
| **F-07** | Non-Atomic snapshot.js Overwrite | **REGRESSED / PARTIAL** | Atomic tempfile rename added, but synchronous execution on every write causes I/O saturation and multi-project clobbering (RF-13). |
| **F-08** | System Lease Deadlock via COALESCE | **WATERTIGHT** | Replaced with explicit expiration logic in `claim_task`. |
| **F-09** | Root CLI Flags After Subcommands | **REGRESSED / PARTIAL** | `sub_global` added, but `./audit export --json` ignores `--json` and emits Markdown (RF-17). |
| **F-10** | Missing Agent Auto-Registration | **REGRESSED / PARTIAL** | Auto-registration added on `add_relation`/`complete_task`, but unvalidated `task_id` in `add_finding` crashes with raw `sqlite3.IntegrityError` (RF-14). |
| **F-11** | Step-by-Step Playbook Crash | **WATERTIGHT (Code) / MINOR DOC** | Dependency crash fixed; onboarding step ordering causes zombie project (RF-19). |
| **F-12** | Silent Default to Oldest Project | **WATERTIGHT** | `resolve_project_id` now picks the most recently updated project. |
| **F-13** | Unchecked System Release | **REGRESSED / PARTIAL** | `release_system` has ownership checks, but newly added `block_task()` completely lacks ownership checks and orphans locks (RF-06). |
| **F-14** | Non-Idempotent Task Completion | **REGRESSED / BYPASSED** | Added ownership checks, but `holder and agent_id` condition completely bypasses check when `agent_id` is None (RF-05). |
| **F-15** | Missing Agent Authentication | **PARTIALLY REMEDIATED** | Pass-through `agent_id` parameter added, but token auth omitted and easily bypassed. |
| **F-16** | Disjoint Queries in Snapshot | **WATERTIGHT** | Wrapped in single transaction connection. |
| **F-17** | `create_task` Immediate Claim | **WATERTIGHT** | System lease locked atomically during task creation. |
| **F-18** | Poison-Pill Infinite Reclaim Loop | **REGRESSED / PARTIAL** | `max_attempts` added, but offline tasks with exceeded attempts are starved permanently in `'open'` (RF-09). |
| **F-19** | Rollback on Acquisition Failure | **WATERTIGHT** | Handled correctly via context manager. |
| **F-20** | Leaked `current_system_id` | **REGRESSED / PARTIAL** | Cleared on completion, but prematurely cleared when agent holds other tasks (RF-07). |
| **F-21** | Unhandled JSON Decode Exceptions | **WATERTIGHT** | Catches `json.JSONDecodeError` and returns 400. |
| **F-22** | Unbounded Request Body / Timeout | **WATERTIGHT** | 10MB limit and 30s socket timeout enforced. |
| **F-23** | Heartbeat Resurrects Expired Leases | **WATERTIGHT (Code) / HOLLOW TEST**| Code correctly filters `lease_until >= ?`, but unit test tautologically asserted `< 2099` (RF-11). |
| **F-24** | Cross-Project Data Bleeding | **WATERTIGHT** | Scoped queries by `project_id`. |
| **F-25** | Unvalidated Health Score Bounds | **WATERTIGHT** | Validates 0-100 integer range. |
| **F-26** | Schema DDL on Every CLI Invocation | **WATERTIGHT** | DDL executed only on init and write operations. |
| **F-27** | 32-Bit Sliced UUID Collisions | **WATERTIGHT** | Full 128-bit hex UUIDs used. |
| **F-28** | Packaging Metadata & Portable Shell | **WATERTIGHT** | `pyproject.toml`, `audit`, and `audit.bat` verified. |
| **F-29** | Committed DB Artifacts & gitignore | **WATERTIGHT** | `.gitignore` verified. |
| **F-30** | Static File Traversal Prefix Mismatch| **WATERTIGHT** | `os.path.commonpath` confinement verified. |
| **F-31** | Absolute Path Disclosure in `/api/health`| **WATERTIGHT (Code) / HOLLOW TEST**| `os.path.basename` used; test verified wrong key (RF-11). |
| **F-32** | Unhandled CLI Crash in DB Init | **WATERTIGHT** | Clean domain exception handling. |
| **F-33** | Documented Task Status `blocked` | **REGRESSED / INSECURE** | Added `block_task()` but introduced claim desynchronization and ownership bypass (RF-06). |
| **F-34** | Missing SIGTERM Trap in Server | **WATERTIGHT** | Clean SIGTERM and SIGINT handler. |
| **F-35** | Hardcoded Author Path | **WATERTIGHT** | Cleaned up. |
| **F-36** | Missing Open-Source License | **WATERTIGHT** | MIT License added. |
| **F-37** | Unnormalized Task Priority Case | **WATERTIGHT** | Lowercased and validated. |
| **F-38** | Self-Referential Relations Geometry | **WATERTIGHT** | Self-referential relations rejected. |

**Summary**: 23 Watertight (60.5%), 15 Regressed / Incomplete / Bypassed (39.5%).

---

## 4. Test Quality & Coverage Audit

### Code Coverage Matrix
- `audit_db.py`: 1262 / 2759 lines executed (**45.7%** coverage; 54.3% unexecuted).
- `audit_server.py`: 141 / 499 lines executed (**28.3%** coverage; 71.7% unexecuted).
- `audit_cli.py`: 148 / 719 lines executed (**20.6%** coverage; `main()` has 0 / 509 lines executed — **0% CLI execution coverage**).
- `ui/`: 0 tests.

### Mutation Testing & Hollow Assertion Results
1. **Wrong Key Tested in Path Disclosure (F-31)**: In `test_f30_and_f31`, line 161 asserts `self.assertNotIn("db_path", data)`. The server returns `"database"`. Mutating `audit_server.py:140` to return `self.db.db_path` (leaking full filesystem paths) passes tests 100%.
2. **Lease Resurrection Tautology (F-23)**: In `test_f23`, line 290 asserts `self.assertLess(sys_obj["lease_until"], "2099-01-01")`. In string comparison, any 2026 timestamp is strictly less than `"2099-01-01"`. Mutating `heartbeat_agent` to resurrect expired leases passes tests 100%.
3. **Passthrough Status Mutation (F-02)**: In `test_f02`, `sys_row["status"]` is already `'needs_attention'`. Mutating `_compute_post_audit_system_status` to `return current_status` passes tests 100%.
4. **Mock Request Handler Header Blind Spot**: `MockRequestHandler` records `response_headers`, but no test inspects them. Deleting `_apply_cors_headers` or setting `*` passes all tests.
5. **Non-Hermetic Snapshot Test (F-07)**: In `test_f07`, `sync_static_snapshot()` mutates the repository's root `ui/snapshot.js` during test execution, and the test only asserts the in-memory return dictionary without inspecting the file on disk. Deleting `sync_static_snapshot` passes tests.
6. **Zero CLI Execution Coverage**: In `audit_cli.py`, inserting `sys.exit(1)` at the start of `main()` passes all 16 tests because `main()` is never invoked.

### Endpoint Coverage Blind Spots
- **GET Endpoints (12 total)**: Only `/api/health` and `/api/snapshot` (with forbidden origin) are called in tests. 10 GET endpoints have zero test coverage.
- **POST Endpoints (16 total)**: Only `/api/reset` and `/api/projects` (with malformed/oversized payloads) are called in tests. 14 POST endpoints have zero test coverage.
- **Protocol Fidelity**: No test executes against a live TCP socket, threading server, or real socket timeout.

---

## 5. Systemic Agent-Coded-Project Patterns (with Counts)

Across the audited codebase and test suite, **15 concrete instances of systemic agent-generated anti-patterns** were verified:

1. **Hollow Assertions & Tautologies (Count: 4)**:
   - Comparing lease timestamps against year 2099 (`test_f23`).
   - Asserting against non-existent key `"db_path"` instead of `"database"` (`test_f30_and_f31`).
   - Asserting in-memory dictionary count instead of inspecting physical snapshot file on disk (`test_f07`).
   - Mocking request handler response headers without asserting their values (`MockRequestHandler`).
2. **Context-Blind Escaping / Incomplete Security Fixes (Count: 3)**:
   - Applying HTML entity escaping to strings interpolated into inline JavaScript event handlers (`ui/app.js`).
   - Implementing Origin and Sec-Fetch-Site validation while completely omitting HTTP `Host` header validation (`audit_server.py`).
   - Adding confirmation payload to `/api/reset` while leaving `/api/seed-demo` defaulting to unconfirmed database wipe (`audit_server.py`).
3. **Logic Disjunction Bypasses (Count: 3)**:
   - Condition `if holder and agent_id and agent_id != holder`: omitting `agent_id` completely bypasses ownership checks (`audit_db.py:1702`).
   - Condition `if open_crit_high > 0 and requested_status in (None, "reviewed")`: passing `"healthy"` completely bypasses vulnerability protection (`audit_db.py:921`).
   - SQL `CASE WHEN claimed_by = ? OR ? IS NULL THEN NULL`: passing `None` wipes active system claims of unrelated agents (`audit_db.py:1746`).
4. **Desynchronization on Partial State Updates (Count: 4)**:
   - `block_task()` clearing task/system claims using caller's ID instead of claimant's ID (`audit_db.py:1657`).
   - `complete_task()` unconditionally clearing system claims while an agent holds other active tasks on the system (`audit_db.py:1746`).
   - `heartbeat_agent(status="offline")` releasing system claims while leaving system status stuck in `'in_progress'` without an active worker (`audit_db.py:590`).
   - `claim_task()` / `claim_next_task()` reassigning task claims without clearing `current_task_id` on the previous agent (`audit_db.py:1470`).
5. **Non-Hermetic Test Side-Effects (Count: 1)**:
   - Test suite executing writes to the host repository's `ui/snapshot.js` during test runs (`tests/test_auditos.py:347`).

---

## 6. Tiered Remediation Roadmap for Regression Findings

### Tier 1: Immediate Critical & High Blockers (Security & Multi-Agent Invariants)
1. **Fix F-02 Status Masking (RF-01)**:
   - Update `_compute_post_audit_system_status()` in `audit_db.py` to block status transitions to `(None, "reviewed", "healthy", "unreviewed")` when open Critical/High findings exist.
   - Guard `upsert_system()` to compute status through `_compute_post_audit_system_status()`.
2. **Implement Host Header Validation (RF-02)**:
   - In `audit_server.py:_check_origin_and_csrf()`, validate `self.headers.get("Host")` against `^(localhost|127\.0\.0\.1)(:\d+)?$`. Return 403 on mismatch.
3. **Eliminate Inline Event Handler XSS (RF-03)**:
   - Refactor `ui/app.js` to remove inline `onclick="...('${esc(id)}')"` calls. Use `data-agent-id`, `data-system-id`, and attach event listeners via `addEventListener`.
   - Add regex validation `^[a-zA-Z0-9_-]+$` to all ID parameters in `audit_db.py`.
4. **Require Reset Confirmation on Demo Seed (RF-04)**:
   - In `audit_server.py:450`, default `reset_first=False`. If `reset_first=True`, require `body.get("confirm") == "RESET"`.
5. **Fix Task Completion Ownership Verification (RF-05)**:
   - In `audit_db.py:complete_task()`, enforce `if holder and not force and agent_id != holder: raise RuntimeError(...)`.
6. **Fix `block_task()` Ownership & Desynchronization (RF-06)**:
   - Add ownership checks (`agent_id == holder or force`) and completed-task checks (`status != 'completed' or force`).
   - Ensure cleanups target `holder` rather than `agent_id`.
7. **Fix System Lease Release on Multi-Task Agents (RF-07)**:
   - In `complete_task()`, check if `effective_agent` holds other active tasks on the system before clearing `systems.claimed_by` and `agents.current_system_id`.
8. **Fix Unassigned Task Claim Wipe (RF-08)**:
   - In `complete_task()`, update SQL `CASE WHEN ? IS NOT NULL AND claimed_by = ? THEN NULL ELSE claimed_by END`.
9. **Fix Offline Poison-Pill Starvation (RF-09)**:
   - In `claim_next_task()`, include open tasks with `attempt_count >= max_attempts` in the auto-block query.
   - In `claim_task()`, reject claims if `attempt_count >= max_attempts` unless `force=True`.
10. **Add Transitive Cycle Detection (RF-10)**:
    - In `upsert_system()`, traverse ancestor chain to prevent cycles. Add cycle guards to `renderNode` in `ui/app.js` and `render_sys` in `audit_db.py`.

### Tier 2: Medium Integrity & Performance Remediations
11. **Clear Stale Agent Pointers on Lease Re-Claim (RF-12)**:
    - In `claim_next_task()` and `claim_task()`, clear `current_task_id` on previous holder upon expired lease claim.
12. **Decouple Static Snapshot Sync from Write Transactions (RF-13)**:
    - Remove `sync_static_snapshot()` from `connect(immediate=True)`. Run via explicit CLI or debounced background thread. Parameterize `ui_dir` for tests.
13. **Validate `task_id` in `add_finding()` (RF-14)**:
    - Check task existence and raise `ValueError` before inserting into `findings`.
14. **Clamp `limit` in `GET /api/logs` (RF-15)**:
    - Enforce `limit = max(1, min(int(raw_limit), 500))`.
15. **Reset Orphaned System Status on Offline Heartbeat (RF-16)**:
    - Reset `systems.status` from `'in_progress'` to `'unreviewed'` when agent goes offline without remaining active tasks.

### Tier 3: Test Quality Overhaul
16. **Fix Tautological and Hollow Test Assertions (RF-11)**:
    - Fix `test_f30_and_f31` to assert `"database"` does not contain path separators.
    - Fix `test_f23` to assert `sys_obj["lease_until"] < utc_now_iso()`.
    - Fix `test_f02` to test explicit override transitions.
    - Add assertions for `response_headers` across all HTTP tests.
17. **Add CLI Subcommand Execution Tests**:
    - Add integration tests for `audit_cli.main()` covering `init`, `status`, `task next`, `system claim`, and `export`.
18. **Parameterize HTTP Endpoint Testing**:
    - Add test matrix verifying CSRF headers and Content-Type enforcement across all 16 POST endpoints.

### Tier 4: Polish & Ergonomics
19. **Fix `./audit export --json` Output (RF-17)**: Check `if args.format == "json" or args.json:`.
20. **Fix Onboarding Step Sequence (RF-19)**: Reorder Step 1 and Step 2 in `AGENT_GUIDE.md`.
21. **Make `get_project_snapshot` Atomic (RF-18)**: Resolve `project_id` inside connection transaction.

---

## 7. Appendix: Refuted Findings & Disagreements

### Refuted Findings
- **F-39 (Security Finding: Origin: null enables CORS exfiltration & CSRF in modern browsers)**:
  - **Verdict**: **REFUTED** (Downgraded to LOW defense-in-depth hygiene).
  - **Rationale**: The reviewer claimed that trusting `Origin: null` allows external websites to exfiltrate snapshots or execute CSRF via sandboxed `<iframe sandbox="allow-scripts">`.
  - Under the W3C Fetch Metadata specification, all modern evergreen browsers (Chrome 76+, Firefox 90+, Safari 16.4+) automatically attach `Sec-Fetch-Site: cross-site` to any cross-origin request initiated by external websites or sandboxed iframes.
  - In `audit_server.py:57-63`:
    ```python
    sec_fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
    if sec_fetch_site == "cross-site":
        self._send_json({"error": "Cross-site requests (Sec-Fetch-Site: cross-site) are forbidden."}, status=403)
        return False
    ```
  - While preflight `OPTIONS` succeeds, the subsequent `GET /api/snapshot` or `POST /api/reset` is immediately blocked with HTTP 403 Forbidden. The reviewer's curl command reproduced an exfiltration only because curl does not send Fetch Metadata headers. Trusting `"null"` is a defense-in-depth hygiene issue for legacy WebViews (Safari < 16.4), but not an exploitable HIGH vulnerability in modern browsers.

### Model Disagreements Needing a Human Decision
1. **Localhost Threat Model & Ephemeral Bearer Tokens**:
   - *Conflict*: The Security angle argued that local unauthenticated HTTP services remain vulnerable to local port-scanning, DNS rebinding, and malicious local applications unless protected by an ephemeral local bearer token (`~/.audit_token`). The Skeptic noted that DNS rebinding is completely eliminated by HTTP `Host` header validation, and token authentication adds friction for multi-agent CLI wrappers.
   - *Recommendation for Human Decision*: Implement HTTP `Host` header validation immediately in this release (zero ergonomics cost, eliminates DNS rebinding). Evaluate adding an opt-in or default local token (`--token` / `~/.audit_token`) for multi-tenant environments in v1.1.
2. **Static Snapshot Synchronization Model**:
   - *Conflict*: Failure-Modes and Test-Quality identified severe write amplification and host repository mutation caused by `sync_static_snapshot()` running synchronously on every write transaction (`AuditDB.connect(immediate=True)`). Decoupling it entirely breaks offline static file inspection in `ui/` unless an explicit export command is executed.
   - *Recommendation for Human Decision*: Decouple synchronous snapshot generation from SQLite transactions. Introduce a debounced background sync worker (e.g. at most once every 5 seconds on write) and provide an explicit CLI command `./audit export --static-ui` for deterministic generation. Parameterize `AuditDB(ui_dir=...)` so tests run hermetically in temporary directories.
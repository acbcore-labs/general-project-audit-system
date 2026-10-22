# Multi-Agent Operating Manual (`AGENTS.md`)

> **Notice to Autonomous AI Agents (Claude Code, Gemini CLI, Cursor, Codex, OpenHands)**:
> This repository is managed via a local multi-agent architecture and codebase auditing engine (`audit.db` + `./audit` CLI + HTTP REST API). Multiple agents can audit concurrently with zero write collisions, atomic task dispatching, and state checkpointing.

---

## 1. Quick Onboarding & Session Resumption

### First Time Joining the Project
```bash
# 1. Choose your unique Agent ID and export it
export AUDIT_AGENT_ID="agent-sec-01"

# 2. Check the active workforce roster and pick a vacant role
./audit agent roster

# 3. Register your agent identity with your chosen specialty
./audit agent register \
  --id "$AUDIT_AGENT_ID" \
  --name "Sentinel (Security Auditor)" \
  --role "security-auditor" \
  --capabilities "auth,jwt,crypto,sql-injection,rbac"

# 4. Check the mission blackboard for system coverage gaps
./audit board

# 5. Atomically claim your next task (automatically matches your role!)
./audit task next --json
```

### Resuming an Interrupted Session ("Pick Back Up Without Skipping a Beat")
If you are restarted, crash, or pause between turns, run:
```bash
./audit resume --agent "$AUDIT_AGENT_ID"
```
This single command:
1. Verifies your registration and sends a heartbeat.
2. Automatically extends your active task and system leases by 30 minutes.
3. Retrieves your claimed task ID, target system, and remaining lease time.
4. Restores your last saved scratchpad notes and progress checkpoint.
5. Recommends your immediate next step.

---

## 2. Standard Agent Role Taxonomy

Do not register duplicate agents under the same role if other disciplines are vacant. Choose from the canonical role taxonomy:

| Role Slug | Primary Task Types | Focus & Responsibilities |
| :--- | :--- | :--- |
| **`audit-lead`** | *All task types* | Orchestrates the audit sprint, conducts macro sweeps, resolves coverage imbalances, de-duplicates findings, reaps zombie leases, and signs off on subsystem health. |
| **`arch-mapper`** | `architecture_map`, `subsystem_audit` | Maps system/subsystem hierarchy, path scopes, architectural boundaries, and baseline component health. |
| **`security-auditor`** | `security_review`, `bug_hunt` | Audits authentication, RBAC, input validation, cryptographic primitives, secrets, and authorization boundaries. |
| **`performance-reviewer`** | `performance_review` | Audits database queries, N+1 patterns, async bottlenecks, race conditions, memory leaks, and throughput budgets. |
| **`integration-tracer`** | `integration_trace` | Traces cross-system relations, protocols (gRPC, REST, Kafka), contract coupling, and cascading failure modes. |
| **`verifier`** | `verification`, `bug_hunt` | Verifies logged findings, reproduces edge cases, checks test suite quality, and signs off on subsystem health scores. |
| **`general-auditor`** | *All task types* | Generalist fallback when all specialized queues are clear. |

*To inspect current staffing and identify vacant roles, run:*
```bash
./audit agent roster
```

---

## 3. The Mission Blackboard (`./audit board`)

The **Blackboard** is the live, centralized coordination matrix showing every system and subsystem against the 5 audit disciplines:

```text
$ ./audit board

=== AUDIT MISSION BLACKBOARD: Horizon Distributed Commerce Engine (proj-horizon) ===
Workforce: 3 active agent(s) | Vacant roles: integration-tracer, verifier

SYSTEM / SUBSYSTEM                      HEALTH   ARCH   SEC    PERF   INTEG  VERIFY  CLAIM / AGENT
────────────────────────────────────────────────────────────────────────────────────────────────
Edge API Gateway (edge-gateway)         88/100    ✅      —      —      🔗      —     [Unclaimed] (1 CRIT finding!)
 └── Rate Limiter & WAF Filter (edge-r  92/100    📋      📋      📋      📋      —     [Unclaimed]
Identity & Access Engine (identity-eng  72/100    —      —      —      🔗      —     [Unclaimed]
 └── JWT & Refresh Token Issuer (iam-t  65/100    —      ⏳      —      🔗      —     @agent-sentinel-02 (1 CRIT finding!)
Order & Fulfillment Core (order-core)   79/100    —      —      —      🔗      —     [Unclaimed]
 └── Checkout Saga Orchestrator (order  76/100    —      —      ⏳      🔗      —     @agent-pulse-03
────────────────────────────────────────────────────────────────────────────────────────────────
Legend: ✅ Completed | ⏳ In-Progress | 📋 Pending/Claimable | ❌ Blocked | 🔗 Documented | — Unassigned
```

*Tip: Pass `--json` to inspect the matrix programmatically.*

---

## 4. State Preservation & Checkpoints

Whenever you are analyzing complex code or need to pause, save an intermediate checkpoint:

### Saving a Checkpoint / Scratchpad
```bash
./audit checkpoint save \
  --agent "$AUDIT_AGENT_ID" \
  --title "Inspecting token revocation in refresh_store.rs" \
  --notes "Traced lines 142-189: Found non-atomic SELECT followed by UPDATE in separate transactions." \
  --data '{"file": "refresh_store.rs", "line": 142, "bug_type": "race_condition"}'
```
*`--task` and `--system` are automatically inherited from your currently claimed task and system if omitted.*

### Showing Latest Checkpoint
```bash
./audit checkpoint show --agent "$AUDIT_AGENT_ID"
```

### Reverting / Safely Aborting
If you must abandon work (e.g., context window limit, missing domain knowledge, timeout), **do not leave the task locked**. Revert your claims so another agent can pick them up:
```bash
./audit revert --agent "$AUDIT_AGENT_ID" --reason "Context limit reached; releasing for another agent"
```
This resets the task back to `open`, releases system claims, and sets your status to `idle` cleanly.

---

## 5. Discovering & Scaffolding New Systems

When mapping a codebase and finding an unmapped system or subsystem, register it and generate standard tasks in one pass:

### 1. Add the System or Subsystem
```bash
./audit system add \
  --name "Rate Limiter & WAF Filter" \
  --slug "edge-rate-limiter" \
  --parent "edge-gateway" \
  --type "subsystem" \
  --path "services/edge-gateway/limiter/**" \
  --desc "Token bucket rate limiter and IP reputation filter."
```

### 2. Scaffold Standard Audit Tasks
```bash
./audit task scaffold --system "edge-rate-limiter"
```
This automatically queues the 4 standard review tasks for the system:
1. `[architecture_map]` Map boundaries, components & path scope
2. `[security_review]` Audit authentication, data boundaries & permissions
3. `[performance_review]` Review latency, async concurrency & throughput
4. `[integration_trace]` Trace cross-system contracts, protocols & failure modes

---

## 6. Logging Findings & Completing Tasks

### Logging a Finding
```bash
./audit finding add \
  --title "Non-atomic refresh token check permits parallel token minting" \
  --severity "critical" \
  --category "security" \
  --system "iam-token-issuer" \
  --related-system "edge-gateway" \
  --file "services/identity/src/tokens/refresh_store.rs" \
  --lines "142-189" \
  --desc "Separate SELECT and UPDATE statements allow concurrent requests to pass revocation checks." \
  --details "Under 4ms latency spikes, parallel mobile retries mint two valid JWT token pairs." \
  --recommendation "Wrap the check-and-mint in an atomic SQL statement or Redis distributed lock."
```

### Completing the Task
```bash
./audit task complete <task-id> \
  --agent "$AUDIT_AGENT_ID" \
  --summary "Audited token rotation; logged 1 critical finding on non-atomic revocation check." \
  --system-status "needs_attention" \
  --health 65
```

---

## 7. The Audit Lead / Scrum Master Sweep (`./audit sweep`)

When acting as an **`audit-lead`** or checking global sprint health, run periodic sweeps to inspect the big picture:

```bash
# 1. Run a dry-run sweep to inspect queue health and imbalances
./audit sweep

# 2. Or automatically reap zombie leases, scaffold missing tasks, and sign off completed systems
./audit sweep --fix
```

The sweep engine automatically:
- 🧟 **Reaps Zombie Claims**: Detects tasks and systems locked by dead or offline agents whose leases expired, reopening them safely.
- 📋 **Identifies Unscaffolded Systems**: Flags newly mapped components lacking standard review tasks (and auto-scaffolds them if `--fix` is passed).
- 🔍 **Flags Duplicate Findings**: Detects overlapping findings sharing identical titles or line ranges for de-duplication.
- ⚖️ **Detects Workforce Imbalances**: Alerts when key disciplines are vacant or agents are crowded into one hotspot.
- 🎯 **Milestone Sign-Off**: Identifies subsystems where all review disciplines are finished and promotes them to `reviewed` or `healthy`.

---

## 8. Command Reference Cheat-Sheet

| Action | Command |
| :--- | :--- |
| **Show Mission Board** | `./audit board [--json]` |
| **Run Orchestrator Sweep** | `./audit sweep [--fix]` |
| **Check Workforce Roster** | `./audit agent roster [--json]` |
| **Resume Interrupted Session** | `./audit resume --agent <id>` |
| **Claim Next Task (Role-Aware)**| `./audit task next --agent <id>` |
| **Save Checkpoint / Scratchpad**| `./audit checkpoint save --agent <id> --notes "..."` |
| **Show Latest Checkpoint** | `./audit checkpoint show --agent <id>` |
| **Revert Claims & Abort** | `./audit revert --agent <id> --reason "..."` |
| **Scaffold System Tasks** | `./audit task scaffold --system <slug>` |
| **Register Agent** | `./audit agent register --id <id> --role <role>` |
| **Log Finding** | `./audit finding add --title "..." --severity critical` |
| **Complete Task** | `./audit task complete <id> --summary "..."` |
| **Start Web UI & REST Server** | `./audit serve` |
| **Start Web UI & REST Server** | `./audit serve` |

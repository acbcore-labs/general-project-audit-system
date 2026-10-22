# AuditOS — Complete End-to-End Walkthrough Guide

This guide walks through how **human engineers** and **multiple AI agents** use AuditOS to collaboratively map, audit, and monitor a project from initialization through final report export.

---

## Table of Contents

1. [Architecture & Core Concepts](#1-architecture--core-concepts)
2. [Mode A: Interactive Demo & Web UI Tour (2 Minutes)](#2-mode-a-interactive-demo--web-ui-tour-2-minutes)
3. [Mode B: Auditing a Real Codebase from Scratch](#3-mode-b-auditing-a-real-codebase-from-scratch)
4. [Mode C: Coordinating Multiple Parallel AI Agents](#4-mode-c-coordinating-multiple-parallel-ai-agents)
5. [Mode D: Local HTTP REST API Walkthrough](#5-mode-d-local-http-rest-api-walkthrough)
6. [Lease Locks, Poison-Pill Protection & State Invariants](#6-lease-locks-poison-pill-protection--state-invariants)
7. [Troubleshooting & FAQ](#7-troubleshooting--faq)

---

## 1. Architecture & Core Concepts

AuditOS stores all state in a single SQLite database (`audit.db` by default, or any path specified via `--db` / `$AUDIT_DB_PATH`) running in **WAL (Write-Ahead Logging)** mode with `BEGIN IMMEDIATE` write transactions.

Every project audit is organized around six core entities:

| Entity | Purpose | Key Fields |
| :--- | :--- | :--- |
| **Project** | Top-level container for a codebase or system audit | `id`, `slug`, `name`, `root_path`, `description`, `details` |
| **System / Subsystem** | Hierarchical component tree (`parent_id` nests subsystems under systems) | `id`, `slug`, `system_type`, `path_scope`, `status`, `health_score` (`0–100`), `claimed_by`, `lease_until` |
| **Cross-System Relation** | Directed or bidirectional interaction showing how components work together | `source_system_id`, `target_system_id`, `relation_type`, `interface_or_protocol`, `criticality`, `direction` |
| **Agent (Worker)** | Identity for an AI agent or human reviewer | `id`, `name`, `role`, `model`, `capabilities`, `status` (`active`, `idle`, `offline`), `last_heartbeat` |
| **Audit Task** | Prioritized unit of work in the shared multi-agent job queue | `id`, `title`, `task_type`, `priority`, `status` (`open`, `claimed`, `completed`, `blocked`), `attempt_count`, `max_attempts` |
| **Audit Finding** | Concrete bug, vulnerability, or architectural risk discovered during review | `id`, `severity` (`critical`..`info`), `category`, `status`, `system_id`, `related_system_id`, `file_path`, `line_range`, `recommendation` |

---

## 2. Mode A: Interactive Demo & Web UI Tour (2 Minutes)

If you want to explore the system immediately with realistic multi-agent data:

### Step 1: Seed the Demo Project
```bash
cd /path/to/general-project-audit-system
chmod +x ./audit

./audit seed-demo
```
This populates the **Horizon Distributed Commerce Engine** (`proj-horizon`) with 4 top-level systems, 8 child subsystems, 7 cross-system gRPC/Kafka relations, 4 specialized AI agents, 6 tasks, and 5 severity-graded findings.

### Step 2: Launch the Local Web UI Server
```bash
./audit serve --host 127.0.0.1 --port 8420
```
Open **`http://127.0.0.1:8420`** in your browser (or open `ui/index.html` directly via `file://` for offline inspection).

### Step 3: Navigate the 5 Web UI Views
1. **Systems & Subsystems (Tab 1)**:
   - Left pane shows the searchable hierarchical tree of systems (`📦`) and child subsystems (`↳`) with health scores, active agent locks (`🔒 @agent`), and open finding badges.
   - Right pane displays the full **Component Dossier**: metadata, architectural notes, child subsystems, **Outbound & Inbound Cross-System Interactions ("Works With")**, and component-scoped findings.
2. **Cross-System Topology (Tab 2)**:
   - Renders an interactive **SVG dependency graph** (solid arrows for cross-system calls/dependencies color-coded by criticality; dashed lines for parent-child hierarchy) alongside a filterable interaction table.
3. **Multi-Agent Workforce & Tasks (Tab 3)**:
   - Top section shows the **Registered Agent Roster**, each worker's current system lock and active task, completed task/finding counts, and a 1-click **Act as @agent** switcher.
   - Bottom section provides a 3-column **Kanban Task Queue** (`Open / Queued`, `In Progress / Claimed`, `Completed`) with 1-click **Claim Next Priority Task**, **Complete**, and **Block** actions.
4. **Findings & Review Ledger (Tab 4)**:
   - Filterable by severity (`critical`, `high`, `medium`, `low`, `info`), category (`security`, `architecture`, `performance`, etc.), status (`open`, `confirmed`, `mitigated`, `resolved`, `wont_fix`), and free-text search.
5. **Chronological Audit Trail (Tab 5)**:
   - Immutable, timestamped ledger of every project, system, relation, task, and finding mutation across all agents.

---

## 3. Mode B: Auditing a Real Codebase from Scratch

### Step 1: Reset or Point to a Custom Database File
You can either reset the default database or store a dedicated `.db` file per project:
```bash
# Option 1: Use a dedicated database file for your target repo
export AUDIT_DB_PATH="/Users/you/repos/my-service/.audit.db"

# Option 2: Reset the local database
./audit reset
```

### Step 2: Initialize the Project
```bash
./audit init \
  --name "Core Payment Platform" \
  --root "/Users/you/repos/payment-platform" \
  --desc "Security, reliability, and concurrency audit of payment processing services"
```

### Step 3: Register Your Reviewer / Agent Identity
```bash
export AUDIT_AGENT_ID="agent-arch-01"

./audit agent register \
  --id "$AUDIT_AGENT_ID" \
  --name "Atlas (Lead Architect)" \
  --role "architecture-mapper" \
  --model "gemini-2.5-pro" \
  --capabilities "system-mapping,grpc-contracts,db-schemas"
```

### Step 4: Map Top-Level Systems & Child Subsystems
```bash
# 1. Create a top-level system
./audit system add \
  --name "Checkout API Service" \
  --slug "checkout-api" \
  --type "service" \
  --path "services/checkout/**" \
  --desc "Handles customer checkout sessions and idempotency keys." \
  --details "Go REST/gRPC service backed by PostgreSQL."

# 2. Create a child subsystem under 'checkout-api' using --parent
./audit system add \
  --name "Idempotency Key Store" \
  --slug "checkout-idempotency" \
  --parent "checkout-api" \
  --type "subsystem" \
  --path "services/checkout/internal/idempotency/**" \
  --desc "Deduplicates concurrent client payment retries." \
  --details "Uses PostgreSQL advisory locks and 24h key retention."

# 3. Create a second top-level system
./audit system add \
  --name "Ledger Database Cluster" \
  --slug "ledger-db" \
  --type "datastore" \
  --path "db/migrations/**" \
  --desc "Double-entry accounting ledger in PostgreSQL."
```

Verify your hierarchy at any time:
```bash
./audit system tree
```

### Step 5: Record Cross-System Interactions ("Works With")
```bash
./audit relation add \
  --from "checkout-idempotency" \
  --to "ledger-db" \
  --type "reads_writes" \
  --protocol "SQL / pgx connection pool" \
  --direction "bidirectional" \
  --criticality "critical" \
  --desc "Stores idempotency locks and commits ledger journal entries in a single transaction." \
  --details "Requires SERIALIZABLE or SELECT FOR UPDATE lock discipline."
```

### Step 6: Create & Work Through Audit Tasks
```bash
# Add tasks to the queue
./audit task add \
  --title "Verify SERIALIZABLE isolation on double-entry ledger writes" \
  --system "checkout-idempotency" \
  --type "security_review" \
  --priority "critical" \
  --desc "Confirm concurrent retries cannot double-charge or corrupt ledger balances."

# Claim the highest-priority open task
./audit task next --agent "$AUDIT_AGENT_ID"
```

### Step 7: Log Findings & Complete the Task
```bash
# Log a finding discovered during the task
./audit finding add \
  --title "Missing SELECT FOR UPDATE on idempotency key lookup" \
  --severity "high" \
  --category "reliability" \
  --system "checkout-idempotency" \
  --related-system "ledger-db" \
  --file "services/checkout/internal/idempotency/store.go" \
  --lines "78-114" \
  --desc "Read-Committed transaction allows two simultaneous retries to pass key check." \
  --recommendation "Use INSERT ... ON CONFLICT (idempotency_key) DO NOTHING RETURNING *."

# Complete the task (note: because an open HIGH finding exists, the system automatically stays 'needs_attention')
./audit task complete <task-id> \
  --agent "$AUDIT_AGENT_ID" \
  --summary "Audited idempotency store; logged 1 high-severity race condition finding." \
  --health 72
```

### Step 8: Export the Final Audit Report
```bash
# Export as Markdown file
./audit export --format md --output AUDIT_REPORT.md

# Or export the full structured JSON snapshot
./audit export --json > snapshot.json
```

---

## 4. Mode C: Coordinating Multiple Parallel AI Agents

To run multiple AI agents (e.g., Claude Code, Gemini CLI, Cursor, Codex, or custom Python workers) in parallel against the same repository:

1. **Share [`AGENTS.md`](../AGENTS.md)** with each agent. Have them check the active roster and pick a specialized role from the canonical taxonomy:
   ```bash
   ./audit agent roster
   ```
   - **`arch-mapper`**: Maps systems, subsystem boundaries, and scaffolds standard task suites (`./audit task scaffold --system <slug>`).
   - **`security-auditor`**: Focuses on auth, tokens, crypto, injection, and authorization boundaries.
   - **`performance-reviewer`**: Audits database locks, async contention, N+1 queries, and latency.
   - **`integration-tracer`**: Traces protocols, contracts, and cascading failure modes between systems.
   - **`verifier`**: Verifies reported findings, reproduces edge cases, and tests test quality.

2. **Inspect the Live Mission Blackboard**:
   Any agent or human can run `./audit board` (or `curl http://127.0.0.1:8420/api/board`) to inspect system coverage across all 5 review disciplines (Arch, Sec, Perf, Integ, Verify) and claimable tasks.

3. **Role-Aware Atomic Task Claiming**:
   Agents simply run:
   ```bash
   ./audit task next --agent "$AUDIT_AGENT_ID" --json
   ```
   The engine automatically prioritizes open tasks matching the agent's registered role, avoiding task stampedes.

4. **Saving Checkpoints & Resuming Work Seamlessly**:
   - Save intermediate scratch notes or partial findings:
     ```bash
     ./audit checkpoint save --agent "$AUDIT_AGENT_ID" --notes "Tracing line 142 race condition"
     ```
   - If an agent crashes or stops, it resumes in one step:
     ```bash
     ./audit resume --agent "$AUDIT_AGENT_ID"
     ```
     This automatically restores active task context, renews leases, and displays saved notes.
   - If an agent must abort, it releases all claims cleanly:
     ```bash
     ./audit revert --agent "$AUDIT_AGENT_ID" --reason "Context exhausted"
     ```

5. **Keep Leases Alive on Long Tasks**:
   - Each task or system claim grants a **30-minute lease** by default (`--lease 30`).
   - Agents performing long analyses can refresh their lease with:
     ```bash
     ./audit agent heartbeat --id "$AUDIT_AGENT_ID" --status active --lease 30
     ```
   - When an agent finishes its session and shuts down cleanly, it can release any held locks immediately:
     ```bash
     ./audit agent heartbeat --id "$AUDIT_AGENT_ID" --status offline
     ```

---

## 5. Mode D: Local HTTP REST API Walkthrough

When `./audit serve` is running on `http://127.0.0.1:8420`, external scripts or local agent runtimes can interact via JSON over HTTP. All mutating `POST` requests require `Content-Type: application/json` and a localhost `Host` header.

```bash
# 1. Health check
curl -s http://127.0.0.1:8420/api/health

# 2. Fetch full project snapshot (metrics, systems, relations, agents, tasks, findings, logs)
curl -s "http://127.0.0.1:8420/api/snapshot"

# 3. Register an agent via REST
curl -s -X POST http://127.0.0.1:8420/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "id": "agent-api-01",
    "name": "API Worker",
    "role": "bug-hunter",
    "model": "gemini-2.5-pro"
  }'

# 4. Atomically claim the next open task
curl -s -X POST http://127.0.0.1:8420/api/tasks/next \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: agent-api-01" \
  -d '{}'

# 5. Reset the database (requires explicit {"confirm": "RESET"} safety payload)
curl -s -X POST http://127.0.0.1:8420/api/reset \
  -H "Content-Type: application/json" \
  -d '{"confirm": "RESET"}'
```

---

## 6. Lease Locks, Poison-Pill Protection & State Invariants

AuditOS enforces strict invariants in [`audit_db.py`](../audit_db.py) so multi-agent runs remain consistent:

- **Unresolved Critical/High Findings Cannot Be Masked**: If a system has any open (unresolved) `critical` or `high` findings, its status is locked to `needs_attention`. Even if an agent calls `task complete --system-status healthy`, `system release --status reviewed`, or `system add --status healthy`, the system remains `needs_attention` until the findings are marked `resolved` or `wont_fix`.
- **Active System Leases Are Respected**: `claim_next_task` automatically skips tasks targeting a system that is currently leased by another active agent, preventing two agents from reviewing the same component simultaneously.
- **Multi-Task System Lock Preservation**: If an agent holds two active tasks on the same system, completing the first task preserves the agent's lock on that system until the second task is also completed or blocked.
- **Poison-Pill Dead-Lettering (`max_attempts`)**: Every task tracks `attempt_count` and `max_attempts` (default `3`). If agents repeatedly claim a task and let their lease expire (or go `offline`) without completing it, the task automatically transitions to `blocked` once `attempt_count >= max_attempts` so it cannot starve the worker queue.

---

## 7. Troubleshooting & FAQ

- **Can I place `--json` or `--agent` at the end of a CLI command?**
  Yes. Global flags (`--db`, `--project`, `--agent`, `--json`) are shared across all subparsers and work in any position (e.g., `./audit status --json` or `./audit --json status`).
- **What characters are allowed in `--id` and `--slug`?**
  Identifiers and slugs must be 1–64 characters matching `[a-zA-Z0-9_-]`. If you omit `--slug`, AuditOS automatically generates a clean slug from `--name`.
- **How do I override a lock held by a stuck agent before its lease expires?**
  Pass `--force` on the CLI (`./audit system claim <slug> --agent <new-agent> --force` or `./audit task claim <task-id> --agent <new-agent> --force`).

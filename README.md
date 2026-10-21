# AuditOS — Generalized Multi-Agent Project & Codebase Auditing System

A zero-dependency, SQLite-backed auditing platform designed for **multiple AI agents and human engineers** to collaboratively map, review, and audit large codebases or complex systems.

It models **Systems**, hierarchical **Subsystems**, **Cross-System Interactions ("Works With")**, **Agent Workforce Identities & Lease Locks**, **Coordinated Task Queues**, **Severity-Graded Findings**, and a **Chronological Timestamped Audit Trail**.

---

## Key Capabilities

- **Hierarchical Systems & Subsystems**: Map top-level systems (`system`, `service`, `pipeline`, `datastore`) and nest any number of child subsystems (`--parent`), each with codebase path scopes, descriptions, deep architectural details, validated health scores (`0–100`), status badges, and UTC timestamps.
- **Cross-System Interaction Topology ("Works With")**: Explicitly document how systems and subsystems interact (`calls`, `depends_on`, `authenticates_via`, `publishes_to`, `consumes_from`, `orchestrates`, `reads_writes`, `syncs_with`), including protocols/interfaces (`gRPC`, `REST`, `Kafka`, `SQL`), criticality, directionality, and failure-mode details.
- **Multi-Agent Identity & Safe Concurrency**:
  - Backed by SQLite in **WAL (Write-Ahead Logging)** mode with `BEGIN IMMEDIATE` transactions.
  - Agents register unique identities (`--id`, `--name`, `--role`, `--model`, `--capabilities`), send heartbeats, and atomically claim tasks (`./audit task next`) or lock systems (`./audit system claim`) with expiring leases and ownership verification so parallel workers never collide or steal active locks.
- **Zero-Dependency Web UI & Localhost-Protected REST API**:
  - Run `./audit serve` to launch the interactive browser dashboard at `http://127.0.0.1:8420`, or open `ui/index.html` directly via `file://` (backed by atomic `ui/snapshot.js` updates).
  - Features a **Systems & Subsystems Split-Pane Explorer**, **Interactive SVG Architecture & Dependency Graph**, **Multi-Agent Roster & Kanban Task Board**, **Filterable Findings Ledger**, **Chronological Audit Trail**, and **1-Click Markdown Report Export**.

---

## Quick Start

### 1. Seed Demo Data & Launch the Web UI
```bash
# From the repository root directory:
chmod +x ./audit

# Populate a realistic multi-system, multi-agent codebase audit demo
./audit seed-demo

# Start the Web UI & REST API server on http://127.0.0.1:8420
./audit serve --port 8420
```

### 2. Initialize a Fresh Audit for Any Project
```bash
# Reset or specify a custom database path via --db /path/to/repo/.audit/audit.db
./audit reset

./audit init \
  --name "My Production Codebase" \
  --root "/path/to/repo" \
  --desc "Comprehensive multi-agent architecture and security audit"
```

### 3. Point Multiple AI Agents at Your Project
Give any LLM/coding agent the instructions in [`AGENT_GUIDE.md`](./AGENT_GUIDE.md). Each agent can run CLI commands (with `--json` placed either before or after subcommands) or call the local REST API while you watch progress live in the Web UI.

---

## CLI Reference Overview

| Command | Description |
| :--- | :--- |
| `./audit init --name "..." [--root "..."]` | Initialize a new project in the audit database |
| `./audit status [--json]` | Show coverage metrics, active agents, task queue, and findings summary |
| `./audit agent register --id <id> --name "..." --role <role>` | Register an agent worker identity |
| `./audit agent heartbeat --id <id> [--status active\|idle\|offline]` | Refresh agent heartbeat and extend active task/system leases |
| `./audit agent list` | List registered agents and their active claims |
| `./audit system add --name "..." [--parent <slug>] [--path "..."]` | Create or update a system or subsystem |
| `./audit system tree` | Display hierarchical tree of all systems and subsystems |
| `./audit system show <slug-or-id>` | Inspect full dossier (subsystems, inbound/outbound relations, findings, tasks) |
| `./audit system claim <slug> --agent <id>` | Lock a system/subsystem for review |
| `./audit system release <slug> --agent <id> --status reviewed --health 90` | Release system lock and record review outcome |
| `./audit relation add --from <sysA> --to <sysB> --type calls --protocol "gRPC"` | Document how two systems/subsystems work together |
| `./audit task add --title "..." --system <slug> --priority high` | Add an audit task to the multi-agent queue |
| `./audit task next --agent <id> [--json]` | Atomically claim the next highest-priority open task |
| `./audit task block <task-id> --agent <id> --reason "..."` | Mark a task as blocked and release its active lease |
| `./audit task complete <task-id> --agent <id> --summary "..."` | Complete a claimed task and log deliverable summary |
| `./audit finding add --title "..." --severity high --system <slug>` | Log a structured finding with file/line scope and remediation |
| `./audit export --format md --output AUDIT_REPORT.md` | Export a complete Markdown (or JSON) audit report |
| `./audit serve [--port 8420]` | Launch the Web UI & HTTP REST API server |

---

## Running the Automated Test Suite

```bash
python3 -m unittest discover -s tests -v
```

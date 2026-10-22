# Multi-Agent Codebase & Architecture Audit Playbook (`AGENT_GUIDE.md`)

> **Instructions for AI Agents / Workers**: Give this file to any coding or review agent (`Read AGENT_GUIDE.md and audit <target_repo>`). Multiple agents can run simultaneously against the same SQLite database without write collisions or duplicate work.

---

## 1. Core Principles

1. **Always Identify Yourself**: Pick a unique, descriptive alphanumeric Agent ID (e.g., `agent-arch-01`, `agent-sec-02`, `agent-perf-03`) and register it before claiming work. Either export `AUDIT_AGENT_ID=<your-id>` or pass `--agent <your-id>` on every CLI call (flags like `--agent`, `--json`, `--project`, and `--db` work either before or after subcommands).
2. **Use `--json` for Programmatic Parsing**: Every `./audit` command supports `--json` so agents can parse exact IDs, slugs, timestamps, and lease locks.
3. **Claim Before Auditing**: Always claim a task (`./audit task next --agent <id>`) or claim a system/subsystem (`./audit system claim <slug> --agent <id>`) before performing deep review so parallel agents know you own that scope.
4. **Model Hierarchy & Cross-System Interactions**:
   - Top-level systems have no `--parent`.
   - Subsystems pass `--parent <system-slug-or-id>`.
   - Whenever System/Subsystem A calls, authenticates with, publishes to, or depends on System/Subsystem B, record it with `./audit relation add`.

---

## 2. Step-by-Step Agent Workflow

### Step 1: Initialize or Check Project Status
If starting a fresh audit on a repository, initialize the project first:
```bash
./audit init \
  --name "My Target Codebase" \
  --root "/absolute/path/to/codebase" \
  --desc "Full architecture and subsystem review"
```
To inspect existing project status and hierarchy:
```bash
./audit status
./audit system tree
```

### Step 2: Register Your Agent Identity
AuditOS is provider-agnostic and subscription-friendly: any LLM agent (Claude Code, Grok, Gemini CLI, Cursor, OpenHands) can jump in without configuring API keys or model arguments.
```bash
export AUDIT_AGENT_ID="agent-sec-01"

./audit agent register --json \
  --id "$AUDIT_AGENT_ID" \
  --name "Sentinel (Security & Auth Auditor)" \
  --role "security-auditor" \
  --capabilities "auth,jwt,sql-injection,access-control"
```

### Step 3: Map Systems & Subsystems (Architecture Discovery)
Register top-level systems first, then attach subsystems under them via `--parent`:
```bash
# Top-level system 1: Edge API Gateway
./audit system add \
  --name "Edge API Gateway" \
  --slug "edge-gateway" \
  --type "system" \
  --path "services/edge-gateway/**" \
  --desc "Public ingress router handling TLS termination, rate limiting, and routing." \
  --details "Go service forwarding authenticated traffic to downstream microservices." \
  --status "reviewed" \
  --health 88

# Top-level system 2: Identity & Auth Engine
./audit system add \
  --name "Identity & Auth Engine" \
  --slug "identity-engine" \
  --type "system" \
  --path "services/identity/**" \
  --desc "Handles OAuth2, JWT issuance, and RBAC evaluation." \
  --details "Rust microservice backed by PostgreSQL and Redis." \
  --status "in_progress"

# Subsystem under identity-engine
./audit system add \
  --name "JWT Token Issuer" \
  --slug "iam-token-issuer" \
  --parent "identity-engine" \
  --type "subsystem" \
  --path "services/identity/src/tokens/**" \
  --desc "Signs short-lived access tokens and rotates refresh token families." \
  --details "EdDSA key rotation every 24h; stores token hashes in PostgreSQL."
```

### Step 4: Document How Systems & Subsystems Work With Other Systems
```bash
./audit relation add \
  --from "edge-gateway" \
  --to "identity-engine" \
  --type "authenticates_via" \
  --protocol "gRPC (IdentityService.VerifyToken)" \
  --criticality "critical" \
  --direction "unidirectional" \
  --desc "Validates bearer tokens and injects tenant claims into upstream headers." \
  --details "4ms P99 budget; circuit breaker trips after 5 consecutive timeouts."
```
Supported `--type` values include: `depends_on`, `calls`, `publishes_to`, `consumes_from`, `reads_writes`, `authenticates_via`, `orchestrates`, `syncs_with`.

### Step 5: Coordinate via the Multi-Agent Task Queue
Create tasks for yourself or other agents, or atomically claim the next highest-priority open task:
```bash
# Add a task to the shared queue
./audit task add \
  --title "Audit refresh token rotation for race conditions" \
  --system "iam-token-issuer" \
  --type "security_review" \
  --priority "critical" \
  --desc "Verify atomic consumption of refresh tokens under concurrent requests."

# Atomically claim the highest-priority open task (safe across parallel agents)
./audit task next --agent "$AUDIT_AGENT_ID" --json
```

### Step 6: Log Findings (Bugs, Security Risks, Architectural Issues)
```bash
./audit finding add \
  --title "Non-atomic refresh token check permits parallel token minting" \
  --severity "critical" \
  --category "security" \
  --system "iam-token-issuer" \
  --related-system "edge-gateway" \
  --file "services/identity/src/tokens/refresh_store.rs" \
  --lines "142-189" \
  --desc "Separate SELECT and UPDATE queries allow two concurrent requests to pass revocation checks." \
  --details "Occurs within a 4ms window under parallel mobile/web retries." \
  --recommendation "Use a single atomic UPDATE ... WHERE consumed_at IS NULL RETURNING * statement."
```

### Step 7: Complete or Block Tasks & Release System Locks
```bash
# Complete a claimed task and update the target system's health score
./audit task complete <task-id> \
  --agent "$AUDIT_AGENT_ID" \
  --summary "Audited token rotation; logged 1 critical race condition finding with remediation." \
  --health 68

# Or mark a task as blocked if waiting on an external dependency
./audit task block <task-id> \
  --agent "$AUDIT_AGENT_ID" \
  --reason "Waiting on protobuf schema definitions for v2 auth contract."

# Or release a directly claimed system
./audit system release "iam-token-issuer" \
  --agent "$AUDIT_AGENT_ID" \
  --status "needs_attention" \
  --health 68 \
  --notes "Verified EdDSA key rotation; open critical finding on refresh token rotation."
```

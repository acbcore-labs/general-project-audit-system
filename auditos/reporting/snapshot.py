"""
Snapshot generation, static snapshot file syncing, database reset, and demo dataset seeding.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional

from auditos.core.utils import utc_now_iso


class SnapshotMixin:
    """Manages snapshot generation, HTML snapshot.js syncing, reset, and demo seeding."""

    def sync_static_snapshot(self, project_ref: Optional[str] = None) -> Optional[str]:
        """Atomically write snapshot.js via temp file + os.replace to prevent 0-byte truncation races (F-07, RF-13)."""
        if getattr(self, "db_path", None) == ":memory:":
            return None
        ui_dir = getattr(self, "ui_dir", None)
        if not ui_dir or not os.path.isdir(ui_dir):
            return None
        snap = self.get_project_snapshot(project_ref)
        snap_path = os.path.join(ui_dir, "snapshot.js")
        fd, tmp_path = tempfile.mkstemp(prefix=".snapshot_", suffix=".tmp", dir=ui_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("window.__AUDIT_SNAPSHOT__ = ")
                json.dump(snap, f, indent=2)
                f.write(";\n")
                f.flush()
            os.replace(tmp_path, snap_path)
            return snap_path
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    def get_project_snapshot(self, project_ref: Optional[str] = None) -> Dict[str, Any]:
        """Resolve project and assemble the entire snapshot inside a single consistent transaction (F-16, RF-18)."""
        with self.connect() as conn:
            project_id = self.resolve_project_id(project_ref, conn=conn)
            prow = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
            if not prow:
                raise ValueError(f"Project '{project_id}' not found.")
            project = dict(prow)
            projects = self.list_projects(conn=conn)
            systems = self.list_systems(project_id, conn=conn)
            relations = self.list_relations(project_id, conn=conn)
            agents = self.list_agents(project_id=project_id, conn=conn)
            tasks = self.list_tasks(project_id, conn=conn)
            findings = self.list_findings(project_id, conn=conn)
            logs = self.list_logs(project_id, limit=120, conn=conn)

        top_systems = [s for s in systems if not s["parent_id"]]
        subsystems = [s for s in systems if s["parent_id"]]
        scored = [s["health_score"] for s in systems if s["health_score"] is not None]
        avg_health = round(sum(scored) / len(scored), 1) if scored else None

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        open_findings = 0
        for f in findings:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1
            if f["status"] not in ("resolved", "wont_fix"):
                open_findings += 1

        task_counts = {"open": 0, "claimed": 0, "completed": 0, "blocked": 0}
        for t in tasks:
            st = t["status"]
            if st in task_counts:
                task_counts[st] += 1

        return {
            "project": project,
            "projects": projects,
            "metrics": {
                "total_systems": len(top_systems),
                "total_subsystems": len(subsystems),
                "total_components": len(systems),
                "reviewed_components": sum(
                    1 for s in systems if s["status"] in ("reviewed", "healthy", "needs_attention")
                ),
                "total_relations": len(relations),
                "active_agents": sum(1 for a in agents if a["status"] == "active"),
                "total_agents": len(agents),
                "avg_health_score": avg_health,
                "open_findings": open_findings,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "task_counts": task_counts,
            },
            "systems": systems,
            "relations": relations,
            "agents": agents,
            "tasks": tasks,
            "findings": findings,
            "logs": logs,
        }

    def reset_database(self) -> None:
        """Clear all audit data across all tables."""
        with self.connect(immediate=True) as conn:
            conn.execute("DELETE FROM audit_logs;")
            conn.execute("DELETE FROM agent_checkpoints;")
            conn.execute("DELETE FROM findings;")
            conn.execute("DELETE FROM tasks;")
            conn.execute("DELETE FROM system_relations;")
            conn.execute("DELETE FROM systems;")
            conn.execute("DELETE FROM agents;")
            conn.execute("DELETE FROM projects;")

    def seed_demo_data(self, reset_first: bool = True) -> Dict[str, Any]:
        """Seed rich realistic multi-agent audit data for demonstrations."""
        prev_sync = getattr(self, "auto_sync_snapshot", False)
        self.auto_sync_snapshot = False
        pid = "proj-horizon"
        try:
            if reset_first:
                self.reset_database()

            proj = self.create_project(
                name="Horizon Distributed Commerce Engine",
                root_path="/workspace/horizon-commerce",
                description=(
                    "Multi-region microservices and event-driven fulfillment architecture "
                    "audited by a coordinated fleet of specialized AI agents."
                ),
                details="Production codebase with 4 core systems, 8 specialized subsystems, gRPC/Kafka interconnects, and PostgreSQL/Redis stores.",
                project_id=pid,
            )
            pid = proj["id"]

            self.register_agent(
                agent_id="agent-atlas-01",
                name="Atlas (Architecture Mapper)",
                role="architecture-mapper",
                model="gemini-2.5-pro",
                capabilities="system-topology, dependency-graphing, boundary-analysis",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-sentinel-02",
                name="Sentinel (Security Auditor)",
                role="security-auditor",
                model="claude-3.7-sonnet",
                capabilities="auth-flows, token-validation, injection-analysis, secrets-review",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-pulse-03",
                name="Pulse (Performance & Reliability)",
                role="performance-reviewer",
                model="gpt-4.1",
                capabilities="concurrency, db-queries, backpressure, retry-storms",
                project_id=pid,
            )
            self.register_agent(
                agent_id="agent-veritas-04",
                name="Veritas (Integration & QA Verifier)",
                role="integration-verifier",
                model="gemini-2.5-flash",
                capabilities="schema-contracts, idempotency, dead-letter-queues",
                project_id=pid,
            )

            edge = self.upsert_system(
                project_id=pid,
                name="Edge API Gateway",
                slug="edge-gateway",
                system_type="system",
                path_scope="services/edge-gateway/**",
                description="Public-facing ingress router handling TLS termination, rate limiting, and request routing.",
                details="Written in Go (Envoy + custom middleware). Handles 45k req/sec peak traffic across 3 availability zones.",
                status="reviewed",
                health_score=88,
                agent_id="agent-atlas-01",
            )
            iam = self.upsert_system(
                project_id=pid,
                name="Identity & Access Engine",
                slug="identity-engine",
                system_type="system",
                path_scope="services/identity/**",
                description="Authentication, OAuth2/OIDC token issuance, RBAC policy evaluation, and session revocation.",
                details="Rust service backed by PostgreSQL and Redis cluster for sub-2ms token introspection.",
                status="needs_attention",
                health_score=72,
                agent_id="agent-sentinel-02",
            )
            orders = self.upsert_system(
                project_id=pid,
                name="Order & Fulfillment Core",
                slug="order-core",
                system_type="system",
                path_scope="services/order-core/**",
                description="Orchestrates cart checkout, inventory reservation, payment capture, and fulfillment state machines.",
                details="TypeScript/Node.js + Temporal workflows with transactional outbox pattern publishing to Kafka.",
                status="in_progress",
                health_score=79,
                agent_id="agent-pulse-03",
            )
            telemetry = self.upsert_system(
                project_id=pid,
                name="Telemetry & Audit Pipeline",
                slug="telemetry-pipeline",
                system_type="system",
                path_scope="platform/telemetry/**",
                description="High-throughput ingestion pipeline for distributed traces, structured logs, and compliance events.",
                details="OpenTelemetry collectors streaming into ClickHouse and S3 parquet archives.",
                status="healthy",
                health_score=94,
                agent_id="agent-veritas-04",
            )

            self.upsert_system(
                project_id=pid,
                name="Rate Limiter & WAF Filter",
                slug="edge-rate-limiter",
                system_type="subsystem",
                parent_ref="edge-gateway",
                path_scope="services/edge-gateway/limiter/**",
                description="Token bucket rate limiter and IP reputation filter backed by Redis distributed counters.",
                details="Configured for 100 req/min per IP on auth routes and 5000 req/min globally.",
                status="reviewed",
                health_score=92,
                agent_id="agent-atlas-01",
            )
            self.upsert_system(
                project_id=pid,
                name="GraphQL Aggregator & Schema Stitcher",
                slug="edge-aggregator",
                system_type="subsystem",
                parent_ref="edge-gateway",
                path_scope="services/edge-gateway/aggregator/**",
                description="Federated GraphQL router stitching catalog, customer, and order subgraphs for mobile & web clients.",
                details="Golang gqlgen implementation with dataloader batching to downstream gRPC services.",
                status="needs_attention",
                health_score=68,
                agent_id="agent-atlas-01",
            )
            self.upsert_system(
                project_id=pid,
                name="JWT & Refresh Token Issuer",
                slug="iam-token-issuer",
                system_type="subsystem",
                parent_ref="identity-engine",
                path_scope="services/identity/src/tokens/**",
                description="Ed25519 asymmetrical JWT signing with rotation, refresh token rolling, and blacklist lookups.",
                details="Tokens carry tenant, scope, and user claims with a 15-minute expiry and sliding 7-day refresh window.",
                status="needs_attention",
                health_score=65,
                agent_id="agent-sentinel-02",
            )
            self.upsert_system(
                project_id=pid,
                name="RBAC Policy Evaluator",
                slug="iam-rbac-evaluator",
                system_type="subsystem",
                parent_ref="identity-engine",
                path_scope="services/identity/src/rbac/**",
                description="Evaluates fine-grained role-based access control rules compiled into WebAssembly bytecode.",
                details="Sub-millisecond policy check caching with Redis pub/sub invalidation channels.",
                status="reviewed",
                health_score=85,
                agent_id="agent-sentinel-02",
            )
            self.upsert_system(
                project_id=pid,
                name="Checkout Saga Orchestrator",
                slug="order-saga-orchestrator",
                system_type="subsystem",
                parent_ref="order-core",
                path_scope="services/order-core/sagas/**",
                description="Temporal-based distributed compensation saga executing order reserve -> charge -> dispatch.",
                details="Guarantees eventual consistency with exponential backoff and dead-letter queue escalation.",
                status="in_progress",
                health_score=76,
                agent_id="agent-pulse-03",
            )
            self.upsert_system(
                project_id=pid,
                name="Inventory Reservation Ledger",
                slug="order-inventory-ledger",
                system_type="subsystem",
                parent_ref="order-core",
                path_scope="services/order-core/inventory/**",
                description="Pessimistic locking and optimistic concurrency ledger for stock allocations across fulfillment centers.",
                details="PostgreSQL isolation level SERIALIZABLE on high-velocity SKU balances.",
                status="unreviewed",
                health_score=None,
                agent_id=None,
            )
            self.upsert_system(
                project_id=pid,
                name="OTel Ingestion Collector",
                slug="telemetry-otel-collector",
                system_type="subsystem",
                parent_ref="telemetry-pipeline",
                path_scope="platform/telemetry/otel/**",
                description="gRPC and HTTP OTLP receiver receiving trace spans and metrics from all fleet services.",
                details="Batch processor buffer sizing configured for 10k spans/sec with tail-based sampling rules.",
                status="healthy",
                health_score=96,
                agent_id="agent-veritas-04",
            )
            self.upsert_system(
                project_id=pid,
                name="Kafka Audit Event Consumer",
                slug="telemetry-kafka-consumer",
                system_type="subsystem",
                parent_ref="telemetry-pipeline",
                path_scope="platform/telemetry/consumers/**",
                description="Consumes immutable CDC audit events from Kafka and streams them to append-only compliance storage.",
                details="Python worker fleet leveraging librdkafka with exactly-once consumer group offsets.",
                status="reviewed",
                health_score=91,
                agent_id="agent-veritas-04",
            )

            # Relations
            self.add_relation(
                project_id=pid,
                source_ref="edge-gateway",
                target_ref="identity-engine",
                relation_type="authenticates_with",
                protocol="grpc",
                description="Validates incoming bearer tokens and checks API client credentials on ingress.",
                agent_id="agent-atlas-01",
            )
            self.add_relation(
                project_id=pid,
                source_ref="edge-gateway",
                target_ref="order-core",
                relation_type="routes_traffic_to",
                protocol="http",
                description="Proxies client checkout requests and order lookup queries via HTTP/2 connection pool.",
                agent_id="agent-atlas-01",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-core",
                target_ref="telemetry-pipeline",
                relation_type="publishes_events_to",
                protocol="kafka",
                description="Publishes order state transitions (Created, Reserved, Charged, Failed) to Kafka topic `orders.events`.",
                agent_id="agent-veritas-04",
            )
            self.add_relation(
                project_id=pid,
                source_ref="edge-aggregator",
                target_ref="order-saga-orchestrator",
                relation_type="calls",
                protocol="grpc",
                description="Dispatches GraphQL mutation `createOrder` to initiate saga execution.",
                agent_id="agent-atlas-01",
            )
            self.add_relation(
                project_id=pid,
                source_ref="order-saga-orchestrator",
                target_ref="order-inventory-ledger",
                relation_type="depends_on",
                protocol="sql",
                description="Executes stock reservation and release queries within saga activity blocks.",
                agent_id="agent-pulse-03",
            )
            self.add_relation(
                project_id=pid,
                source_ref="identity-engine",
                target_ref="telemetry-pipeline",
                relation_type="logs_security_events_to",
                protocol="kafka",
                description="Publishes authentication failures, token revocations, and privilege escalations to `iam.audit` topic.",
                agent_id="agent-sentinel-02",
            )

            # Tasks
            t1 = self.create_task(
                project_id=pid,
                title="Map edge gateway routing, WAF middleware, and TLS termination",
                task_type="architecture_map",
                system_ref="edge-gateway",
                priority="high",
                description="Audit Go reverse proxy routing rules, middleware chaining, and rate limit bucket allocations.",
                created_by="agent-atlas-01",
            )
            self.claim_task(t1["id"], "agent-atlas-01")
            self.complete_task(
                t1["id"],
                "agent-atlas-01",
                summary="Mapped ingress routing topology. Documented Envoy wrapper and token bucket rate limiter.",
                system_status="reviewed",
                health_score=88,
            )

            t2 = self.create_task(
                project_id=pid,
                title="Audit Ed25519 token signing, key rotation, and refresh token revocation store",
                task_type="security_review",
                system_ref="iam-token-issuer",
                priority="critical",
                description="Verify cryptographic key rotation intervals, nonces, and concurrent token revocation race conditions.",
                created_by="agent-sentinel-02",
            )
            self.claim_task(t2["id"], "agent-sentinel-02")

            t3 = self.create_task(
                project_id=pid,
                title="Profile Temporal saga compensations under simulated PostgreSQL deadlock latency",
                task_type="performance_review",
                system_ref="order-saga-orchestrator",
                priority="high",
                description="Run chaos test injecting 250ms query delay on inventory lock table during 1,000 parallel checkouts.",
                created_by="agent-pulse-03",
            )
            self.claim_task(t3["id"], "agent-pulse-03")

            self.create_task(
                project_id=pid,
                title="Audit pessimistic lock acquisition order in inventory reservation ledger",
                task_type="performance_review",
                system_ref="order-inventory-ledger",
                priority="high",
                description="Verify multi-item cart inventory locks acquire row locks in deterministic SKU order to avoid database deadlocks.",
                created_by="agent-pulse-03",
            )

            self.create_task(
                project_id=pid,
                title="Verify protobuf schema compatibility across edge-aggregator and order-core gRPC definitions",
                task_type="integration_trace",
                system_ref="edge-aggregator",
                priority="medium",
                description="Run buf lint and check backwards compatibility for wire serialization changes.",
                created_by="agent-veritas-04",
            )

            t6 = self.create_task(
                project_id=pid,
                title="Validate Kafka consumer offset commit idempotency and dead-letter routing",
                task_type="verification",
                system_ref="telemetry-kafka-consumer",
                priority="medium",
                description="Inject poison-pill JSON payloads and verify messages are committed to DLQ without stalling partition.",
                created_by="agent-veritas-04",
            )
            self.claim_task(t6["id"], "agent-veritas-04")
            self.complete_task(
                t6["id"],
                "agent-veritas-04",
                summary="Verified DLQ routing and consumer error handling across 10,000 synthetic corrupt events.",
                system_status="reviewed",
                health_score=91,
            )

            # Findings
            self.add_finding(
                project_id=pid,
                title="Non-atomic refresh token check permits parallel token minting (Race Condition)",
                severity="critical",
                category="security",
                system_ref="iam-token-issuer",
                related_system_ref="edge-gateway",
                agent_id="agent-sentinel-02",
                file_path="services/identity/src/tokens/refresh_store.rs",
                line_range="142-189",
                description="Separate SELECT followed by UPDATE in token revocation check allows concurrent requests to mint valid tokens.",
                details="Under 5ms latency spikes, two simultaneous mobile client refresh requests both pass the `is_revoked == false` predicate before the first transaction commits the revoked state.",
                recommendation="Wrap the check-and-mint operation in an atomic SQL statement (`UPDATE ... RETURNING ...`) or use a Redis distributed lock.",
                status="open",
            )

            self.add_finding(
                project_id=pid,
                title="GraphQL Aggregator lacks AST query depth limit on nested Order -> LineItems -> Product resolver",
                severity="high",
                category="security",
                system_ref="edge-aggregator",
                related_system_ref="order-core",
                agent_id="agent-sentinel-02",
                file_path="services/edge-gateway/aggregator/graphql_server.go",
                line_range="205-238",
                description="Clients can submit deeply nested GraphQL queries that fan out into N+1 gRPC calls against Order Core.",
                details="While dataloader batches single-level IDs, recursive cyclic fragments bypass batching limits.",
                recommendation="Configure max query depth = 7 and max complexity score = 500 in `graphql_server.go`.",
                status="confirmed",
            )

            self.add_finding(
                project_id=pid,
                title="RBAC policy cache TTL (60s) delays immediate privilege revocation across Order Core admin endpoints",
                severity="medium",
                category="architecture",
                system_ref="iam-rbac-evaluator",
                related_system_ref="order-core",
                agent_id="agent-sentinel-02",
                file_path="services/identity/src/rbac/evaluator.rs",
                line_range="88-115",
                description="Local LRU policy cache does not subscribe to Redis pub/sub invalidation events when an admin role is revoked.",
                details="Revoked merchant admins retain refund execution privileges for up to 60 seconds until cache expiry.",
                recommendation="Subscribe `iam-rbac-evaluator` instances to `iam:policy:invalidate` pub/sub channel for sub-second eviction.",
                status="open",
            )

            self.add_finding(
                project_id=pid,
                title="Outbox relay lacks dead-letter metric alert when Kafka broker acks time out",
                severity="low",
                category="reliability",
                system_ref="telemetry-kafka-consumer",
                related_system_ref="order-core",
                agent_id="agent-veritas-04",
                file_path="platform/telemetry/consumers/order_stream.py",
                line_range="310-342",
                description="Poison pill Avro payloads are routed to DLQ topic but do not increment Prometheus counter `telemetry_dlq_messages_total`.",
                details="Verified DLQ routing works as designed, but metric label `topic` was omitted in error handler.",
                recommendation="Emit `telemetry_dlq_messages_total{topic, reason}` counter before committing consumer offset.",
                status="open",
            )

            return self.get_project_snapshot(pid)
        finally:
            self.auto_sync_snapshot = prev_sync
            if self.auto_sync_snapshot:
                self.sync_static_snapshot(pid)

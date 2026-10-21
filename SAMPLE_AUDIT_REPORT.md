# System & Subsystem Audit Report: Horizon Distributed Commerce Engine

- **Project ID**: `proj-horizon` (`horizon-distributed-commerce-engine`)
- **Root Path**: `/workspace/horizon-commerce`
- **Generated At**: `2026-10-21T23:04:46.472Z`
- **Coverage**: 11/12 components reviewed (4 top-level systems, 8 subsystems)
- **Average Health Score**: 81.3/100
- **Findings Summary**: 5 total (1 Critical, 2 High, 1 Medium, 1 Low, 0 Info)

## Executive Overview
Multi-region microservices and event-driven fulfillment architecture audited by a coordinated fleet of specialized AI agents.

## Multi-Agent Audit Workforce

| Agent ID | Name | Role | Status | Tasks Completed | Findings Logged | Last Heartbeat |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| `agent-veritas-04` | Veritas (Integration & QA Verifier) | `integration-verifier` | `active` | 0 | 1 | `2026-10-21T23:04:46.373Z` |
| `agent-sentinel-02` | Sentinel (Security Auditor) | `security-auditor` | `active` | 0 | 3 | `2026-10-21T23:04:46.370Z` |
| `agent-pulse-03` | Pulse (Performance & Reliability) | `performance-reviewer` | `active` | 0 | 1 | `2026-10-21T23:04:46.363Z` |
| `agent-atlas-01` | Atlas (Architecture Mapper) | `architecture-mapper` | `active` | 1 | 0 | `2026-10-21T23:04:46.345Z` |

## Systems & Subsystems Hierarchy

- **Edge API Gateway** (`edge-gateway` | `system`) — Status: `reviewed` | Health: **88/100**
  - **Scope**: `services/edge-gateway/**`
  - **Description**: Public-facing ingress router handling TLS termination, rate limiting, and request routing.
  - **Details**: Written in Go (Envoy + custom middleware). Handles 45k req/sec peak traffic across 3 availability zones.
  - **Timestamps**: Created `2026-10-21T23:04:46.263Z` | Updated `2026-10-21T23:04:46.337Z`
  - **GraphQL & REST Aggregator** (`edge-aggregator` | `subsystem`) — Status: `needs_attention` | Health: **82/100**
    - **Scope**: `services/edge-gateway/aggregator/**`
    - **Description**: Federates downstream gRPC calls into unified client payloads.
    - **Details**: Uses dataloader batching but lacks strict depth limits on nested GraphQL fragments.
    - **Timestamps**: Created `2026-10-21T23:04:46.281Z` | Updated `2026-10-21T23:04:46.365Z`
  - **Rate Limiter & WAF Filter** (`edge-rate-limiter` | `subsystem`) — Status: `healthy` | Health: **92/100**
    - **Scope**: `services/edge-gateway/middleware/ratelimit/**`
    - **Description**: Token-bucket distributed rate limiter using Redis Lua scripts.
    - **Details**: Enforces per-IP and per-API-key quotas; falls back to local in-memory window if Redis latency > 15ms.
    - **Timestamps**: Created `2026-10-21T23:04:46.278Z` | Updated `2026-10-21T23:04:46.278Z`
- **Identity & Access Engine** (`identity-engine` | `system`) — Status: `needs_attention` | Health: **72/100**
  - **Scope**: `services/identity/**`
  - **Description**: Authentication, OAuth2/OIDC token issuance, RBAC policy evaluation, and session revocation.
  - **Details**: Rust service backed by PostgreSQL and Redis cluster for sub-2ms token introspection.
  - **Timestamps**: Created `2026-10-21T23:04:46.267Z` | Updated `2026-10-21T23:04:46.267Z`
  - **JWT & Refresh Token Issuer** (`iam-token-issuer` | `subsystem`) — Status: `needs_attention` | Health: **65/100** | Claimed by `agent-sentinel-02`
    - **Scope**: `services/identity/src/tokens/**`
    - **Description**: EdDSA key rotation, short-lived access JWT minting, and refresh token family tracking.
    - **Details**: Rotates signing keys every 24h; refresh token reuse detection revokes entire session family.
    - **Timestamps**: Created `2026-10-21T23:04:46.285Z` | Updated `2026-10-21T23:04:46.358Z`
  - **RBAC Policy Evaluator** (`iam-rbac-evaluator` | `subsystem`) — Status: `reviewed` | Health: **81/100**
    - **Scope**: `services/identity/src/rbac/**`
    - **Description**: Fine-grained permission resolver evaluating tenant roles and resource policies.
    - **Details**: Caches compiled policy ASTs in local LRU cache with 60-second TTL.
    - **Timestamps**: Created `2026-10-21T23:04:46.289Z` | Updated `2026-10-21T23:04:46.289Z`
- **Order & Fulfillment Core** (`order-core` | `system`) — Status: `in_progress` | Health: **79/100**
  - **Scope**: `services/order-core/**`
  - **Description**: Orchestrates cart checkout, inventory reservation, payment capture, and fulfillment state machines.
  - **Details**: TypeScript/Node.js + Temporal workflows with transactional outbox pattern publishing to Kafka.
  - **Timestamps**: Created `2026-10-21T23:04:46.270Z` | Updated `2026-10-21T23:04:46.270Z`
  - **Checkout Saga Orchestrator** (`order-checkout-saga` | `subsystem`) — Status: `needs_attention` | Health: **76/100** | Claimed by `agent-pulse-03`
    - **Scope**: `services/order-core/src/sagas/checkout/**`
    - **Description**: Coordinates multi-step checkout across inventory lock, fraud check, and payment capture.
    - **Details**: Executes compensating transactions on payment decline or inventory contention.
    - **Timestamps**: Created `2026-10-21T23:04:46.293Z` | Updated `2026-10-21T23:04:46.362Z`
  - **Inventory Reservation Ledger** (`order-inventory-ledger` | `subsystem`) — Status: `needs_attention` | Health: **68/100**
    - **Scope**: `services/order-core/src/inventory/**`
    - **Description**: Tracks SKU stock holds, warehouse allocation, and TTL expiration for abandoned carts.
    - **Details**: Uses optimistic locking (`version` column) on high-contention flash-sale SKUs.
    - **Timestamps**: Created `2026-10-21T23:04:46.300Z` | Updated `2026-10-21T23:04:46.300Z`
  - **Payment Gateway Adapter** (`order-payment-adapter` | `subsystem`) — Status: `reviewed` | Health: **84/100**
    - **Scope**: `services/order-core/src/adapters/payment/**`
    - **Description**: Idempotent wrapper around external Stripe/Adyen payment processors.
    - **Details**: Stores idempotency keys in PostgreSQL `payment_attempts` table before outbound HTTP call.
    - **Timestamps**: Created `2026-10-21T23:04:46.296Z` | Updated `2026-10-21T23:04:46.296Z`
- **Telemetry & Audit Pipeline** (`telemetry-pipeline` | `system`) — Status: `healthy` | Health: **94/100**
  - **Scope**: `platform/telemetry/**`
  - **Description**: High-throughput ingestion pipeline for distributed traces, structured logs, and compliance events.
  - **Details**: OpenTelemetry collectors streaming into ClickHouse and S3 parquet archives.
  - **Timestamps**: Created `2026-10-21T23:04:46.274Z` | Updated `2026-10-21T23:04:46.274Z`
  - **Kafka Event Stream Consumer** (`telemetry-kafka-consumer` | `subsystem`) — Status: `healthy` | Health: **95/100**
    - **Scope**: `platform/telemetry/consumers/**`
    - **Description**: Consumes domain events from `orders.*` and `identity.*` topics for compliance archiving.
    - **Details**: Batch-inserts 5,000 events per flush into ClickHouse with dead-letter routing.
    - **Timestamps**: Created `2026-10-21T23:04:46.305Z` | Updated `2026-10-21T23:04:46.305Z`

## Cross-System Interactions & Dependencies

| Source System | Relation | Target System | Protocol / Interface | Criticality | Description |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Order & Fulfillment Core** (`order-core`) | `depends_on` --> | **RBAC Policy Evaluator** (`iam-rbac-evaluator`) | `gRPC (PolicyService.CheckPermission)` | `high` | Verifies merchant admin privileges for bulk order refunds and overrides. |
| **JWT & Refresh Token Issuer** (`iam-token-issuer`) | `publishes_to` --> | **Kafka Event Stream Consumer** (`telemetry-kafka-consumer`) | `Kafka Topic: identity.security.audit` | `high` | Emits login, token rotation, and anomalous revocation events. |
| **Order & Fulfillment Core** (`order-core`) | `publishes_to` --> | **Kafka Event Stream Consumer** (`telemetry-kafka-consumer`) | `Kafka Topic: orders.lifecycle.v2 (Avro)` | `high` | Streams order state transitions via transactional outbox relay. |
| **Checkout Saga Orchestrator** (`order-checkout-saga`) | `calls` --> | **Payment Gateway Adapter** (`order-payment-adapter`) | `Temporal Activity RPC` | `critical` | Triggers asynchronous payment authorization and capture with automatic retry policy. |
| **Checkout Saga Orchestrator** (`order-checkout-saga`) | `orchestrates` <--> | **Inventory Reservation Ledger** (`order-inventory-ledger`) | `Internal Domain Service / SQL Transaction` | `critical` | Reserves SKU stock during checkout initialization and commits/releases on payment outcome. |
| **GraphQL & REST Aggregator** (`edge-aggregator`) | `calls` --> | **Order & Fulfillment Core** (`order-core`) | `gRPC / Protobuf v3 (OrderService)` | `critical` | Routes client checkout and order history mutations to Order & Fulfillment Core. |
| **Edge API Gateway** (`edge-gateway`) | `authenticates_via` --> | **Identity & Access Engine** (`identity-engine`) | `gRPC (IdentityService.VerifyToken)` | `critical` | Validates bearer tokens and enriches upstream headers with tenant claims. |

## Audit Findings & Recommendations

### [CRITICAL] Race window in Refresh Token Rotation allows parallel token minting before family revocation (`find-867de1b00136`)
- **Category**: `security` | **Status**: `open` | **System**: JWT & Refresh Token Issuer (`iam-token-issuer`) | **Logged By**: `agent-sentinel-02` at `2026-10-21T23:04:46.358Z`
- **Location**: `services/identity/src/tokens/refresh_store.rs:142-189`
- **Summary**: Non-atomic SELECT followed by UPDATE on `refresh_tokens` table permits two concurrent requests with the same token to both succeed within a 4ms window.
- **Technical Details**: When two requests arrive simultaneously at Edge Gateway with an identical refresh token, both pass `is_revoked == false` before either transaction commits. Recommend using `UPDATE refresh_tokens SET consumed_at = NOW() WHERE token_hash = $1 AND consumed_at IS NULL RETURNING *`.
- **Recommendation**: Replace read-then-write check with a single atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING` query.

### [HIGH] GraphQL Aggregator lacks AST query depth limit on nested Order -> LineItems -> Product resolver (`find-4993021242d5`)
- **Category**: `security` | **Status**: `confirmed` | **System**: GraphQL & REST Aggregator (`edge-aggregator`) | **Logged By**: `agent-sentinel-02` at `2026-10-21T23:04:46.365Z`
- **Location**: `services/edge-gateway/aggregator/graphql_server.go:205-238`
- **Summary**: Clients can submit deeply nested GraphQL queries that fan out into N+1 gRPC calls against Order Core.
- **Technical Details**: While dataloader batches single-level IDs, recursive cyclic fragments bypass batching limits.
- **Recommendation**: Configure max query depth = 7 and max complexity score = 500 in `graphql_server.go`.

### [HIGH] Unbounded retries in Checkout Saga can trigger cascading thread pool exhaustion on Inventory Ledger (`find-952e349d3ab8`)
- **Category**: `performance` | **Status**: `open` | **System**: Checkout Saga Orchestrator (`order-checkout-saga`) | **Logged By**: `agent-pulse-03` at `2026-10-21T23:04:46.362Z`
- **Location**: `services/order-core/src/sagas/checkout/reserve_step.ts:64-112`
- **Summary**: Optimistic lock failures during high-contention SKU drops trigger immediate tight-loop retries without jitter.
- **Technical Details**: When `version` mismatch occurs in `order-inventory-ledger`, `reserve_step.ts` retries up to 15 times with a fixed 10ms delay, saturating the PostgreSQL connection pool during flash sales.
- **Recommendation**: Add full jitter exponential backoff and cap synchronous retries at 4 attempts with circuit-breaker shedding.

### [MEDIUM] RBAC policy cache TTL (60s) delays immediate privilege revocation across Order Core admin endpoints (`find-cfaa46b6f6be`)
- **Category**: `architecture` | **Status**: `open` | **System**: RBAC Policy Evaluator (`iam-rbac-evaluator`) | **Logged By**: `agent-sentinel-02` at `2026-10-21T23:04:46.369Z`
- **Location**: `services/identity/src/rbac/evaluator.rs:88-115`
- **Summary**: Local LRU policy cache does not subscribe to Redis pub/sub invalidation events when an admin role is revoked.
- **Technical Details**: Revoked merchant admins retain refund execution privileges for up to 60 seconds until cache expiry.
- **Recommendation**: Subscribe `iam-rbac-evaluator` instances to `iam:policy:invalidate` pub/sub channel for sub-second eviction.

### [LOW] Outbox relay lacks dead-letter metric alert when Kafka broker acks time out (`find-f72ea12f93e5`)
- **Category**: `reliability` | **Status**: `open` | **System**: Kafka Event Stream Consumer (`telemetry-kafka-consumer`) | **Logged By**: `agent-veritas-04` at `2026-10-21T23:04:46.372Z`
- **Location**: `platform/telemetry/consumers/order_stream.py:310-342`
- **Summary**: Poison pill Avro payloads are routed to DLQ topic but do not increment Prometheus counter `telemetry_dlq_messages_total`.
- **Technical Details**: Verified DLQ routing works as designed, but metric label `topic` was omitted in error handler.
- **Recommendation**: Emit `telemetry_dlq_messages_total{topic, reason}` counter before committing consumer offset.

## Audit Task Queue

| Task ID | Priority | Type | Title | System | Status | Agent | Deliverable Summary |
| :--- | :---: | :--- | :--- | :--- | :---: | :--- | :--- |
| `task-fca926b29b3a` | `critical` | `security_review` | Audit JWT refresh token rotation & revocation race conditions | `iam-token-issuer` | `claimed` | `agent-sentinel-02` | - |
| `task-796bb0e096f3` | `high` | `performance_review` | Analyze Checkout Saga lock contention & retry backpressure under flash sales | `order-checkout-saga` | `claimed` | `agent-pulse-03` | - |
| `task-4576aecb2c60` | `high` | `bug_hunt` | Audit expired cart reservation reaper job for deadlocks | `order-inventory-ledger` | `open` | `-` | - |
| `task-026556310e3c` | `high` | `security_review` | Enforce query depth & complexity ceiling in GraphQL Aggregator | `edge-aggregator` | `open` | `-` | - |
| `task-47a073b88523` | `medium` | `integration_trace` | Verify Avro schema backward compatibility on orders.lifecycle.v2 | `telemetry-kafka-consumer` | `open` | `-` | - |
| `task-7deccb6a778b` | `critical` | `architecture_map` | Map top-level systems, subsystem boundaries, and gRPC/Kafka contracts | `edge-gateway` | `completed` | `agent-atlas-01` | Mapped 4 core systems, 8 subsystems, and 7 primary cross-system interaction channels. |

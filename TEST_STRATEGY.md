# Backend test strategy

## Baseline

On 2026-07-19, `npm run test:run` passed 2 files/37 tests in 0.673 s. Tests cover authentication helpers and utility behavior but do not compose the real application, database, billing, storage, AI, SSE, or concurrent quota behavior.

## Required layers

- Unit: environment decoding, error mapping, billing state machine, quota policy/reservation, state sanitation, ownership/key rules, provider error classification.
- Integration: `createApp` + isolated Mongo replica set + fake providers; all routes, auth and ownership, persistence, indexes, duplicate/idempotent requests, transaction/atomic behavior, SSE abort, body limits.
- Contract: generated OpenAPI matches runtime schemas and frontend client fixtures.
- Security: forged UID/tier/email, revoked/expired tokens, horizontal access, webhook signatures/replay, upload key traversal/MIME/size, malformed model output, CORS/proxy behavior.
- Resilience: provider timeout/cancellation, Mongo disconnect/readiness, graceful SIGTERM, duplicate scheduler instance, partial account deletion.

No test may use production credentials, databases, payment endpoints, object buckets, AI quota, or push subscribers. CI fails if configuration could resolve to production.

## Merge gate

Lockfile install; strict typecheck; lint/format; unit/integration/contract tests; production build; container build if retained; startup/liveness/readiness smoke; dependency audit review. Coverage is a diagnostic, not a substitute for critical-path assertions.

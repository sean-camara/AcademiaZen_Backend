# API inventory

Observed from `server.js` on 2026-07-19. Unless noted public, routes require a Firebase bearer token and resource queries scope by `req.user.uid`.

| Method/path | Purpose | Key side effects / risks |
|---|---|---|
| GET `/health` | public process health | Does not prove Mongo readiness. |
| GET `/api/auth/ping` | authenticated token check | Stable auth smoke route. |
| GET `/api/me` | user/billing summary | Creates/loads user. |
| GET `/api/vapid-public-key` | public push key | Configuration exposure is expected. |
| POST `/api/uploads/presign` | authorize PDF upload | Validates PDF MIME/size/tier and server-owned key; signature validation remains client-declared. |
| POST `/api/uploads/signed-url` | owned PDF download URL | Key ownership enforced by UID prefix. |
| GET `/api/billing/plans` | plan display | Authenticated; values are server-owned. |
| GET `/api/billing/status` | entitlement and quota | Lazy counter resets mutate state. |
| POST `/api/billing/auto-renew` | preference | Must not imply provider cancellation. |
| POST `/api/billing/cancel` | cancel at period end | Server entitlement only. |
| POST `/api/billing/checkout` | PayMongo checkout | Rate-limited; duplicate/idempotency handling required. |
| POST `/api/billing/secret-checkout` | coupon/secret checkout | Direct grants now fail closed; provider-verified checkout remains available. |
| POST `/api/billing/extend` | extension checkout | Requires active non-renewing premium. |
| POST `/api/billing/refresh` | reconcile pending checkout | External provider read and user update. |
| POST `/api/billing/webhook/paymongo` | public signed webhook | Signature verified; payment-key lock and processed-key history make paid-event replay idempotent. |
| GET `/api/focus/summary` | target session summary | Query-scoped; validate target type/id. |
| POST `/api/focus/sessions/start` | start session | Abandons other active sessions; duplicate start semantics needed. |
| POST `/api/focus/sessions/end` | finish/partial session | Ownership query; repeat submission behavior needs idempotency. |
| POST `/api/focus/sessions/complete` | complete with reflection | Ownership query. |
| POST `/api/focus/sessions/abandon` | abandon session | Ownership query. |
| GET `/api/focus/analytics` | aggregate analytics | Several aggregate/count queries. |
| GET `/api/focus/history` | paginated history | page default 1, limit max 50. |
| GET `/api/focus/suggestions` | study suggestions | Reads embedded state and recent sessions. |
| GET `/api/state` | current embedded state | Creates missing user/defaults. |
| PUT `/api/state` | replace/sanitize state | Whole-document last-writer-wins; max size enforced. |
| DELETE `/api/account` | delete account | Deletes owned R2 objects, application records, AI logs/quota state, then Firebase identity; retry-safe but not transactional across providers. |
| POST `/api/subscribe` | upsert owned push subscription | Unique UID+endpoint. |
| DELETE `/api/unsubscribe` | remove owned endpoint | Validate endpoint length/shape. |
| GET `/api/subscriptions/count` | admin count | Email allowlist authorization. |
| POST `/api/send-notification` | send to current user | Validate bounded safe content. |
| POST `/api/schedule-notification` | in-process delayed push | Lost on restart; unbounded timers risk memory. |
| POST `/api/notify-new-task` | task notification | Duplicates product state logic. |
| POST `/api/sync-tasks` | task notification reconciliation | Writes notification metadata. |
| POST `/api/ai/chat` | non-streaming chat | Per-user quota guard/provider call/logging. |
| POST `/api/ai/chat/stream` | SSE chat | Long-lived request, provider stream, cancellation/logging. |
| GET `/api/ai/reviewer-status` | generation quota/status | Reads billing generation history. |
| POST `/api/ai/generate-reviewer` | generate structured reviewer | Large input/model output validation/quota/provider cost. |

## Contract gaps

There is no generated OpenAPI contract, runtime schemas are ad hoc, successful/error shapes vary, and request IDs are absent. General limiter state is in-process. Required target error shape:

```json
{"error":{"code":"STABLE_CODE","message":"User-safe explanation","requestId":"uuid"}}
```

Document authentication, ownership, body/query/path schema, result, errors, rate limit, idempotency key, and side effects for every route in generated OpenAPI before removing old response compatibility.

# Backend security assessment

## Existing controls

Firebase ID tokens are verified server-side; most routes are authenticated and query by token UID. Admin access uses a server-side email allowlist. Helmet, strict origin allowlist, body size limit, per-route/general rate limiting, PDF MIME/size checks, server-owned R2 keys, short-lived signed URLs, PayMongo signature verification code, loopback port binding, TLS, key-only SSH, and non-root application user ownership are present.

## Priority findings

| Severity | Finding | Required treatment |
|---|---|---|
| Critical | AI quota guard is read-modify-save, fails open on exceptions, and charges before provider success | Atomic request reservation with idempotency; explicit failed-request policy; fail closed on guard/storage error. |
| High | Billing coupon/direct-grant route can activate premium under configuration | Disable direct grant in production, rotate/remove shared coupons, require signed provider events, test entitlement source. |
| High | Payment webhook replay/idempotency is not backed by a unique processed-event store | Verify raw-body signature and timestamp policy; atomically insert unique event before transition. |
| High | Account deletion spans collections but not Firebase/R2 and is not transactional/resumable | Define retention, re-auth, deletion job/checkpoints, orphan report, and recovery. |
| High | Rate-limit stores are in memory and proxy trust is hard-coded | Shared store for multi-instance; validate exact proxy hops and real IP behavior. |
| Medium | Global JSON limit is 15 MB and many bodies are validated ad hoc | Route-specific limits and runtime schemas; bounded strings/arrays. |
| Medium | Provider requests lack a uniform timeout/cancellation/retry policy | Abort signals, bounded safe retries, circuit/latency metrics, safe normalized errors. |
| Medium | Raw errors/log calls are inconsistent | Structured redacted logger; stable error envelope; no stack/provider details in production. |
| Medium | `autoIndex: true` runs index work at application startup | Disable in production after explicit index migration/verification. |

## Modernization controls implemented

- AI quota mutation is serialized per user and fails closed when its lock store is unavailable.
- Paid events use a provider payment ID (event/checkout fallback), a database-backed concurrency lock, and a bounded durable processed-key history. Replaying the same payment no longer extends entitlement.
- Direct coupon entitlement grants fail closed. The provider-verified coupon checkout path remains compatible.
- Account deletion removes owned R2 objects before application records and Firebase identity. Object-store failure leaves the identity available for retry.
- Provider calls have bounded abort timeouts; production startup validates required identity, database, push, origin, and HTTPS settings without printing values.
- Mongoose automatic index creation is disabled in production.

Never log bearer tokens, passwords, API/service-account/payment/storage keys, database URIs, signed URLs, full prompts/documents, payment details, or SSH material. Use pseudonymous user IDs only where operationally necessary.

Security changes that affect SSH, firewall, TLS, billing, credentials, or data require explicit production authority, backup, rollback, and independent verification.

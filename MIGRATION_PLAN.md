# Backend modernization plan

## Phases and gates

1. **Characterize:** test auth/ownership, current errors, state sanitation, billing transitions, AI quota, focus idempotency, upload ownership, push ownership, and graceful startup behavior.
2. **Foundation:** strict environment schema, structured logger/redaction, request IDs/timing, central errors, liveness/readiness, `createApp` composition, graceful shutdown.
3. **Contracts:** runtime request/response schemas, OpenAPI generation, old-response compatibility, typed frontend client.
4. **Extract low-risk modules:** health/auth, uploads, notifications, then focus. Each extraction keeps route behavior and passes integration tests.
5. **Data consistency:** state revision conflicts, atomic quota reservation, webhook event idempotency, account-deletion workflow. No production migration until dry-run/restore gates pass.
6. **Provider boundaries:** Firebase, R2, Web Push, OpenRouter/DeepSeek, PayMongo with timeout/cancellation/retry classification and normalized errors.
7. **TypeScript:** convert module-by-module to native ESM strict TypeScript; do not recreate a monolithic `server.ts`.
8. **Operations:** multi-stage non-root image, resource/health controls, CI, versioned releases, smoke/rollback automation.

## TypeScript version rule

Verify TypeScript 7 is a stable release and supported by Vite/Vitest/Node/Mongoose types at implementation time. A prerelease is not acceptable for production merely to satisfy a nominal target. Use strict options, including unchecked-index and exact-optional checks, without `any` escapes.

TypeScript 7.0.2 is now pinned. The strict build compiles migrated TypeScript services and copies compatibility JavaScript into `dist`; tests import compiled modules. Billing, environment validation, and account-deletion orchestration are the first converted boundaries. Route/provider extraction remains required before `server.js` can be converted without suppressions.

## Production ordering

Additive backend compatibility deploy -> smoke/observe -> frontend deploy -> adoption window -> later cleanup. Database changes are a separate explicit operation. Rollback always restores the previous application image without requiring a reverse data migration.

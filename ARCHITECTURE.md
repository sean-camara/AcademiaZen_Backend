# Backend architecture

## Observed architecture (2026-07-19)

The API is Express 4/CommonJS on Node, with 29 route handlers and most behavior in a 3,444-line `server.js`. Firebase Admin authenticates bearer tokens. Mongoose stores one embedded user/state aggregate plus separate focus sessions, push subscriptions, and expiring AI logs. External adapters are inline for OpenRouter/DeepSeek, PayMongo, R2, and Web Push. Background notification scans run in-process with timers.

```text
Host Nginx/TLS
  -> Docker backend :3001 (loopback only)
     -> Express middleware/routes/background timers
        -> Firebase Admin
        -> MongoDB
        -> OpenRouter / DeepSeek
        -> PayMongo
        -> Cloudflare R2-compatible S3
        -> Web Push
```

## Principal coupling

HTTP parsing, validation, billing rules, quota accounting, persistence, provider calls, prompt construction, streaming, notifications, and scheduling share one process/file. Importing `server.js` starts connections and a listener, preventing isolated integration composition. Background jobs are not leader-elected, so multiple replicas could duplicate notifications.

## Target composition

```text
src/app/create-app.ts, server.ts, routes.ts
src/config/env.ts, database.ts, firebase.ts, providers.ts
src/modules/{users,state,focus,billing,uploads,notifications,ai}/
src/middleware/{auth,authorization,validation,rate-limit,request-id,error-handler}.ts
src/infrastructure/{database,firebase,ai,storage,push,payments,logging}/
src/shared/{errors,contracts,types,security}/
```

`createApp(dependencies)` has no network side effects. `server.ts` validates configuration, connects dependencies, starts HTTP, and handles SIGTERM/SIGINT gracefully. Routes validate with backend-owned schemas and return a consistent error envelope. Atomic repository operations enforce quota/idempotency. A scheduler lock or single-worker deployment owns periodic jobs.

## Decisions

- Incrementally retain Express/Mongoose; migration risk outweighs framework replacement value.
- Convert vertical modules to strict native-ESM TypeScript, leaving compatibility entrypoints only while needed.
- Keep the embedded `state` document initially; add revision conflict control before considering collection decomposition.
- Add liveness (process) and readiness (Mongo/providers required for core API) separately.

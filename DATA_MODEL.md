# Data model and compatibility

## Collections

### `users`

Unique indexed `uid`, email, embedded application `state`, billing, AI usage counters, and notification metadata. `state` embeds tasks, subjects, flashcards, folders/items/PDF metadata, reviewers/questions/attempts, quiz progress, chat, profile, and settings.

Risks: document growth and large arrays; whole-state replacement; string dates/timezones; mixed quiz answers; embedded signed/public URL fields; no revision token; reviewer generation arrays and chat require explicit caps.

### `focussessions`

UID-owned session lifecycle with target, planned/actual time, completion status, blockers, reflection, and timestamps. Indexes `{uid, endedAt:-1}` and `{uid, startedAt:-1}` support history/analytics. Add idempotency/active-session uniqueness only after production duplicate analysis.

### `pushsubscriptions`

UID and browser subscription payload with a unique compound `{uid, endpoint}` index. Invalid 410 subscriptions are removed. Consider endpoint hashing for logs and lifecycle metadata.

### `ailogs`

UID, endpoint/model/mode, token/cost/length/success/error/latency/tier. UID+time and UID+endpoint+time indexes; TTL expires records after 90 days. Confirm this retention against audit/product requirements before altering it.

## Production evidence

The 2026-07-19 backup log recorded 11 users, 29 focus sessions, 5 push subscriptions, and 35 AI logs. These counts are audit evidence only, not marketing claims.

## Migration policy

No destructive change. Add schema versions and compatibility readers first; write the new form while retaining old reads; backfill with `--dry-run`, bounded batches, checkpoints, and invariant reports; deploy new readers before migration; retain rollback that does not require deleting new data. Production backup and isolated restore validation are mandatory.

## Priority data controls

1. Add optimistic revision/ETag to state reads and conditional writes.
2. Replace AI read-modify-save counters with atomic reservation/finalization and request idempotency.
3. Add webhook event storage/unique event ID for payment idempotency.
4. Define account deletion across Mongo, Firebase, R2, push, and audit retention, with resumable partial-failure handling.
5. Measure document sizes/array percentiles and inspect actual indexes read-only before proposing schema changes.

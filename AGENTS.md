# AcademiaZen backend working agreement

This repository serves the live AcademiaZen API. Preserve Firebase users, MongoDB documents/indexes, AI usage/audit history, billing entitlements, R2 objects, push subscriptions, and old-client compatibility.

## Safety

- Work on `modernization/production-v2`; never rewrite `main`, force-push, or run destructive production commands.
- Never print or commit `.env`, service-account material, tokens, payment secrets, database URIs, signed URLs, SSH keys, prompts, or private study data.
- Schema/index changes require compatibility analysis, a dry-run migration, tested rollback, backup evidence, and post-migration checks.
- Billing and quota changes require explicit business rules and concurrency/idempotency tests. Fail closed on authorization/quota uncertainty.
- Production audit is read-only until backups, impact, rollback, validation, and access continuity are established.
- Maintain old/new frontend-backend interoperability during rolling deploy and rollback.

## Architecture and verification

Controllers translate HTTP; services own application rules; repositories own persistence; adapters own Firebase, AI, R2, PayMongo, push, and logging. Use focused contracts only where they improve testability.

Before merge: clean install, strict typecheck, lint/format, unit/integration tests, production build, dependency review, and safe startup/health tests with test-only configuration. Never connect a local test run to production MongoDB or providers.

# Rollback

## Trigger

Rollback on readiness failure, sustained elevated 5xx/latency, auth/billing/quota regression, data-integrity warning, uncontrolled provider cost, service-worker incompatibility, or resource exhaustion.

## Application rollback

1. Stop rollout; preserve candidate logs/evidence.
2. Select the recorded prior immutable backend/frontend image IDs and Compose configuration.
3. Restore the prior backend first when API compatibility is affected, verify loopback health, then host proxy health.
4. Restore prior frontend assets/image and verify stale/new service-worker clients.
5. Run safe public/authenticated smoke and monitor CPU, memory, swap, disk, logs, and data invariants.

Do not use `git reset --hard`, delete volumes, drop collections, or rebuild an unknown moving branch. Do not reverse a schema migration unless its tested rollback explicitly preserves data. Prefer forward compatibility/repair.

## Data incident

Quiesce affected writes, preserve logs and current database evidence, identify the recovery point, and restore to an isolated target first. Production restoration requires owner authorization, documented data-loss window, RPO/RTO decision, and post-restore reconciliation of Firebase, billing, R2, push, and AI audit state.

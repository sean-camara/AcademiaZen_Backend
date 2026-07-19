# Production runbook

## Read-only triage

1. Check `https://academiazen.app` and `https://api.academiazen.app/health` status/timing.
2. SSH as the authorized deployment user; record time and incident owner.
3. Inspect `df -h`, `free -h`, `swapon --show`, uptime/load, `docker compose ps`, container restart status, `systemctl --failed`, and recent sanitized service logs.
4. Identify deployed Git commits and image IDs. Never print environment or `docker inspect` environment blocks.
5. Decide: application fault, dependency fault, TLS/proxy, disk/memory, deployment, or security incident.

## Common responses

### API 502/503

Verify loopback `/live`/`ready` (or current `/health`), container status, port binding, Mongo reachability, and Nginx upstream. Preserve logs. Restart/recreate only after identifying the failure and confirming rollback image.

### Disk above 90%

Stop builds; identify `docker system df`, backups, logs, and application data. Never delete database volumes/backups/logs during diagnosis. After snapshot/off-site backup and image inventory, remove only approved unused build cache/images; confirm free space and health.

### Memory/OOM

Inspect kernel/container evidence, RSS, active streams/jobs, and swap. Stop a runaway candidate deployment before touching healthy production. Scale capacity or apply tested limits; do not loop restarts.

### Certificate expiry

Confirm DNS, certificate dates, Certbot timer/logs, and `nginx -t`. Renew with owner/sudo authority, retain config backup, reload only valid Nginx, and verify both domains externally.

### Backup failure

Preserve the failing archive/log; check disk, credentials by presence only, network, and tool image. Do not overwrite last good backup. Run a new timestamped backup after remediation, checksum it, copy off-host, and schedule restore validation.

### Suspected billing/quota/security incident

Preserve request IDs, redacted logs, webhook event IDs, and relevant immutable records. Disable only the narrow risky feature through a tested server-side control if available. Do not expose secrets or private prompts; coordinate credential rotation/provider actions with the owner.

## Deployment/rollback

Follow `DEPLOYMENT.md` and `ROLLBACK.md`. Every production change states problem, command/file, impact, backup, rollback, and verification. SSH/firewall changes require a second active session and provider console access. Nginx changes require config backup and `nginx -t`; package/reboot work requires a maintenance window.

## Escalation data

Timestamp/timezone, affected URL/workflow, request IDs, status/latency, deployed commits/images, container/service state, CPU/memory/swap/disk, last successful backup, recent change, and actions taken. Keep contact names/phone numbers in a private operations system, not this repository.

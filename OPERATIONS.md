# Operations

## Service inventory

Production is a DigitalOcean Ubuntu 24.04.3 LTS droplet. Host Nginx terminates TLS and proxies loopback ports 5173/3001. Docker Compose runs `web` and `backend` with `unless-stopped`. DigitalOcean monitoring, cron, Fail2ban, unattended upgrades, and a webhook listener are active.

## Signals

Collect structured logs with request ID, route template, status, duration, safe UID hash, database latency, provider/model latency, token/cost totals, upload/push failure category, and shutdown lifecycle. Alert on 5xx/error rate, p95/p99 latency, readiness failure, container restart, CPU saturation, available memory/swap growth, disk >80/90%, backup failure/age, TLS <30 days, Mongo storage/connection pressure, and provider failure/cost anomalies.

## Health semantics

- `/live`: event loop/process is responsive; no external dependency call.
- `/ready`: startup configuration valid and Mongo ping succeeds; return 503 during shutdown.
- `/health`: retain current compatibility while migrating monitors.

## Change safety

Identify deployed commits/images, verify backup and disk headroom, build a new image, start/health it, switch/recreate only after validation, run public/auth-safe smoke, and retain the previous image. Never edit live source, prune before rollback is secured, or restart repeatedly without evidence.

The current root disk is 88% full. Docker reports 12.14 GB reclaimable build cache, but cleanup is a deliberate production change: inventory active/rollback images, create provider snapshot/off-site backup, then prune only unused build cache with before/after disk and health checks.

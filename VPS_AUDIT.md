# Production VPS audit

Audit date: 2026-07-19 UTC. Mode: read-only SSH as `sean`. No packages, files, services, firewall, containers, database, DNS, or production data were changed.

## Inventory

- Provider/model: DigitalOcean KVM Droplet; hostname `academiazen-backend`.
- OS/kernel: Ubuntu 24.04.3 LTS, Linux 6.8.0-90; restart required; uptime 166 days.
- Capacity: 1 vCPU, 961 MiB RAM, 2 GiB swap, 25 GB disk. 610 MiB RAM and 426 MiB swap used; root filesystem 88% used with 3.0 GB free.
- Runtime: Docker 29.1.5, Compose 5.0.2; two containers up five months. Host Nginx, Docker/containerd, cron, Fail2ban, unattended upgrades, DigitalOcean monitoring, and webhook listener active.
- Network: public 22/80/443; loopback 3001 backend, 5173 frontend, and 9000 webhook. No public Mongo listener observed.
- SSH readable config: root login disabled; public-key auth enabled; password and keyboard-interactive auth disabled. User `sean` is in sudo/docker groups. Sudo required an interactive password.
- TLS: Let's Encrypt certificate for `academiazen.app` also serves API; valid 2026-05-27 through 2026-08-25. HTTP redirects to HTTPS. Renewal timer could not be verified without additional inspection.
- Deployment: `/opt/academiazen`, repositories on `main` at expected commits; env permission 600, root frontend build `.env` permission 664. Host Nginx proxies loopback containers.
- Backup: daily 03:00 UTC, 14 days, local only as observed; latest run successful and gzip integrity passed.

## Findings

### High — root disk pressure and oversized Docker cache

Evidence: root is 88% full; Docker reports 12.93 GB images (11.78 GB reclaimable) and 12.61 GB build cache (12.14 GB reclaimable). Impact: failed builds/backups/log writes, database/application outage. Remediation: first capture active/prior image IDs and provider snapshot/off-site backup; then prune only verified unused build cache/images, add build retention and disk alerts. Possible downtime: none expected, but loss of rollback/build cache is possible. Rollback: retained immutable previous image or rebuild pinned commits; cache itself is not recoverable. Verify: `df`, `docker system df`, container health, public smoke.

### High — backups share the production disk and restore is unproven

Evidence: about 957 MB under `/home/sean/academiazen_backups`; no observed off-site copy or isolated restore. Impact: disk/VPS/account failure can remove production and backups; corrupt dumps may be discovered during incident. Remediation: encrypted off-site versioned copy, checksums, alerting, isolated restore drill. Downtime: none for copy/test when isolated. Rollback: preserve local backup job while adding destination. Verify restored counts/indexes/invariants.

### High — application-level quota/billing risks

Evidence: deployed backend commit contains fail-open non-atomic AI quota guard and secret/direct-grant billing route. Impact: quota bypass, cost exposure, entitlement abuse. Remediation: code/test/deploy atomic quota and signed idempotent billing transitions; disable direct grant. Downtime: none with additive compatibility. Rollback: prior image, while monitoring for abuse. Verify concurrency and replay tests plus production-safe metrics.

### Medium — constrained memory and active swap

Evidence: 961 MiB RAM with 426 MiB swap in use; Fail2ban has also swapped. Impact: latency/OOM during Docker builds, PDF/AI traffic, or concurrent streams. Remediation: measure container limits/RSS/event-loop latency; serialize builds, add limits/alerts, consider a larger droplet based on measurements. Rollback: remove limits only if they cause controlled failures. Verify load and p95 latency.

### Medium — reboot and package maintenance pending

Evidence: `/var/run/reboot-required` exists and many OS/Docker packages are upgradable; current kernel dates to 2025. Impact: missing fixes and untested accumulated reboot. Remediation: review security advisories, snapshot/backup, maintenance window, upgrade supported packages, controlled reboot with console access. Downtime: expected brief downtime on single node. Rollback: provider snapshot/recovery console and retained configs. Verify SSH, firewall, Docker, Nginx, TLS, public smoke.

### Medium — configuration drift and permissive root build-env mode

Evidence: production Compose differs from local health/restart configuration; `/opt/academiazen/.env` is mode 664. Frontend Vite values are public after build, but the file should still use least privilege and be classified. Impact: surprise deploy behavior and unnecessary local disclosure. Remediation: reconcile declarative Compose after diff; classify keys; set 600 if any value is non-public. Downtime: none for permission change, but sudo/change approval required. Verify owner/group and reproducible config without rendering secrets.

### Medium — health check is liveness only

Evidence: `/health` returns process status; production Compose has no healthcheck/dependency gate. Impact: proxy can serve a process unable to reach Mongo. Remediation: add separate live/ready endpoints and Compose health checks. Rollback: old endpoint/container config. Verify dependency outage returns readiness 503 while liveness remains 200.

### Low — public response header hardening incomplete

Evidence: frontend HEAD response exposes Nginx version and did not show CSP/HSTS in the sampled output. Impact: reduced browser hardening/information disclosure. Remediation: full privileged `nginx -T`/header audit, deliberate CSP and HSTS after compatibility testing, `server_tokens off`. Rollback: backed-up Nginx config, `nginx -t`, reload only. Verify external headers and app/Firebase flows.

## Blocked or unverified

Sudo-required effective firewall/iptables, full `sshd -T`, Certbot timer/config, complete Nginx config test, provider firewall, sudoers/users, Docker daemon policy, and privileged logs were not accessible non-interactively. Mongo authentication/bind/TLS/index/query health and backup restore were not inspected through production credentials. Monitoring alert delivery, provider snapshots, DNS account configuration, and external secret stores were not available. These are explicitly unverified, not assumed safe.

## Urgent change recommendation

Disk cleanup is justified soon but is destructive and can remove rollback images; it was not performed during audit. Obtain interactive sudo/provider snapshot authority, record images, verify off-site backup, then execute the narrow cleanup runbook with live health monitoring.

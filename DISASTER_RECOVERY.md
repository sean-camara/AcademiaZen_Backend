# Disaster recovery

## Scope and provisional objectives

Recover MongoDB, application releases, environment/configuration, Nginx/TLS renewal, scheduled jobs, and external-provider references. Provisional targets pending owner approval: RPO 24 hours (current daily backups), RTO 4 hours for application restore and 8 hours for full VPS rebuild.

## Current evidence

Cron runs `/opt/academiazen/ops/backup/backup.sh` daily at 03:00 UTC with 14-day local retention. On 2026-07-19 it successfully dumped four Mongo collections and archived application/Nginx/Let's Encrypt data. Latest Mongo and application archives passed gzip integrity checks. Backups occupy about 957 MB on the same 88%-full VPS disk.

This does **not** prove recoverability: there is no observed off-site copy, provider snapshot evidence, checksum manifest, encryption evidence, alert delivery, or isolated `mongorestore` test.

## Recovery requirements

1. Copy encrypted backups off-host with immutable/versioned retention and least-privilege credentials.
2. Produce SHA-256 manifests and alert on failure/age/size anomaly.
3. Monthly: create isolated Mongo target, restore latest archive without `--drop` against production, compare collection counts/indexes/sample invariants, then destroy the isolated target under approved procedure.
4. Quarterly: rebuild a fresh supported VPS from documented prerequisites, restore config/releases/database, issue/attach TLS, verify DNS cutover plan, and run smoke tests.

## Dependency inventory

DigitalOcean account/DNS, GitHub repositories, Firebase project/service account, MongoDB service, R2 bucket/credentials, OpenRouter/DeepSeek, PayMongo/webhook, VAPID keys, domain registrar/DNS, Let's Encrypt, monitoring, and SSH emergency access. Secret values remain outside this document.

## Emergency sequence

Declare incident/owner; stop unsafe changes; preserve evidence; determine whether failover, application rollback, or data restore is needed; restore into isolation; validate; obtain authorization for production data impact; cut over; reconcile external systems; monitor; document timeline and prevention actions.

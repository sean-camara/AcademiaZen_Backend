# Safe deployment

## Current production method

`/opt/academiazen` contains both Git repositories and `docker-compose.yml`. Deployment scripts pull `main`, build Docker images, and run Compose. Host Nginx proxies `academiazen.app` to `127.0.0.1:5173` and `api.academiazen.app` to `127.0.0.1:3001`. Production baseline commits are frontend `f4d0b0a...` and backend `418f9eb...`.

## Preflight

1. CI/clean lockfile builds and compatibility matrix pass.
2. Release commits/images are immutable and identified.
3. Latest Mongo/application/config backup is successful, integrity-checked, copied off-host, and a recent isolated restore is proven.
4. Root disk has build plus rollback headroom; do not build at 88% without a reviewed cleanup/snapshot plan.
5. Environment key requirements are compared by name only; permissions are 600.
6. Current Compose/Nginx/TLS config and running images are captured; rollback commands are ready.
7. Any migration is a separate dry-run/backup-approved operation.

## Rollout

Build the backend image without replacing the live container, label it with the commit, start a candidate on a private alternate port/network if capacity permits, verify `/live` and `/ready`, then update Compose to the immutable image and recreate only the backend. Verify local and reverse-proxy health, unauthenticated rejection, designated test-account API, Mongo, logs, resources, and provider smoke within cost/safety limits. Deploy the frontend only after backend compatibility is observed.

The existing direct `git pull && docker compose up -d --build` flow is not atomic and can consume excessive disk. Replace it only after a tested versioned-image process exists; do not introduce automatic production deployment yet.

## Postflight

Record frontend/backend commits and image IDs; verify HTTPS/public/auth/static/service-worker behavior; watch 5xx, latency, restarts, memory/swap/disk for at least one normal usage window; retain previous images/releases until the rollback window closes.

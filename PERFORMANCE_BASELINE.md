# Backend performance baseline

Measured 2026-07-19.

| Measure | Baseline |
|---|---:|
| backend tests | 37 passed in 0.673 s |
| public `/health` from VPS | 200 in 0.430 s (TLS included) |
| container age/status | up 5 months, no reported restart loop |
| droplet | 1 vCPU, 961 MiB RAM |
| memory | 610 MiB used, 350 MiB available |
| swap | 426 MiB used of 2 GiB |
| root disk | 21/24 GiB, 88% |
| Mongo backup evidence | 11 users, 29 focus sessions, 5 subscriptions, 35 AI logs |

Startup time and representative authenticated/database/provider endpoint latency were not measured safely because the local `.env` may target production and no isolated test database/provider configuration exists. Production logs/metrics available to the unprivileged SSH user were insufficient for percentile measurement.

## Risks and targets

In-process scans load all matching users; analytics issue multiple queries; long SSE requests use 300-second proxy timeouts; embedded state can approach 5 MB. Establish p50/p95/p99 per route, Mongo query explain/index metrics, event-loop delay, RSS/heap, provider first-token/total latency, and connection pool saturation. Require bounded pagination/fields/lean reads where appropriate and measure before caching.

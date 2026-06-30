# Changelog

All notable changes to ARGUS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-30

### Added

- **Full detection pipeline** — end-to-end flow: collect → normalize (OCSF) → detect → index → dashboard. Every stage is independently testable and wired together in a single `docker compose up`.

- **4 log source parsers** — Linux SSH (`/var/log/auth.log`), Cisco ASA syslog, Windows Active Directory EventID 4625 (failed logon), and VMware vSphere. Each parser emits a typed OCSF `Authentication` event.

- **Brute-force detection rule** — fires when a single IP accumulates 10 failed authentications within a 60-second window. Threshold and window are YAML-configurable; no code change required to tune sensitivity.

- **Contract-first architecture** — 7 machine-readable contracts (OCSF event schemas, OpenAPI specs for internal HTTP surfaces, Sigma rule schema) committed alongside code. Contracts are the source of truth; implementations are verified against them in CI.

- **Shared message bus abstraction** — a single `Bus` interface with two concrete backends: an in-memory implementation for unit and acceptance tests (zero infrastructure), and a Redis Streams implementation for production. Services never import a backend directly.

- **Shared runner** — common event-loop component used by every service. Provides ack-after-handler semantics, configurable redelivery on failure, a dead-letter queue for poison messages, and a `/health` HTTP endpoint that CI and Docker health checks hit.

- **Deterministic alert IDs (T7)** — alert IDs are derived from a stable hash of the triggering evidence. Re-processing the same log stream produces identical IDs, making the pipeline idempotent under at-least-once delivery.

- **Global window counter (T6)** — sliding-window counts are stored in Redis sorted sets (`ZCOUNT`). All replicas share a single counter, so horizontal scaling does not split detection windows or cause missed alerts.

- **Zero-infrastructure acceptance test (`make e2e`)** — the full pipeline (parse → detect → index) runs in-process with the in-memory bus. No Docker, no Redis, no OpenSearch required locally. The same test is the CI gate.

- **Live dashboard** — a browser-based UI served by nginx, which also acts as a reverse proxy to OpenSearch. No CORS configuration needed; the browser talks only to nginx.

- **Auto-feeder (devkit-feeder)** — a companion container that injects a synthetic brute-force log sequence on `docker compose up`. A real alert appears in the dashboard within seconds of the stack starting, with no manual curl commands.

- **Secret scanning in CI** — gitleaks runs on every push and pull request. Any credential committed by mistake blocks the build before it reaches reviewers.

- **Apache-2.0 license** — permissive license; use in commercial products, fork freely.

[Unreleased]: https://github.com/supermhel/argus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/supermhel/argus/releases/tag/v0.1.0

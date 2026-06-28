# Security Policy

ARGUS is a Security Information and Event Management (SIEM) tool. We take the
security of the project — and the safety of anyone running it — seriously. This
document describes the **v0.1 threat boundary** (what ARGUS does and does not
protect against today) and **how to report a vulnerability**.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **security@argus-siem.example** *(placeholder — replace with
the project's real disclosure address before publishing)*.

If GitHub Private Vulnerability Reporting is enabled on this repository, you may
also use **Security → Report a vulnerability**.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a proof-of-concept rule, log line, or request is ideal).
- The affected service / file and version or commit.

**What to expect:**

- Acknowledgement of your report within a few business days.
- An initial assessment and, where applicable, a coordinated disclosure timeline.
- Credit in the release notes if you would like it.

---

## v0.1 threat boundary

ARGUS v0.1 is a **local, single-host development and demonstration stack**. It is
**not** hardened for production or internet exposure. Understand these boundaries
before running it:

### 1. Localhost / Compose-network only — not internet-exposed

All v0.1 services are intended to run on `localhost` or inside the Docker Compose
network on a trusted machine. They are **not** designed to be reachable from the
public internet or an untrusted network.

- Do **not** expose the published ports (`6379`, `9200`, `5601`, `8000`, `8080`)
  to untrusted networks.
- The bundled OpenSearch runs with its security plugin **disabled** for
  zero-friction local development (`DISABLE_SECURITY_PLUGIN=true` in
  `infra/docker-compose.yml`). It must not be exposed beyond the local host.

### 2. No authentication in v0.1 — by design

There is **no authentication or authorization** on any ARGUS service in v0.1.
Anyone who can reach a service's port can call its API. This is an accepted,
documented limitation for the local demo stack. Authentication is **out of scope
for v0.1** and is planned for a later release. Until then, the mitigation is the
network boundary above: keep the stack on a trusted, non-exposed host.

### 3. Rule files are executed by the detection engine — only run trusted rules

The detection engine (WS-4) loads and evaluates **rule files** from
`contracts/rules/`. Rule conditions are part of the engine's evaluation path.
**Treat rule files like code:** only load rules you have written or reviewed and
trust. Do not run rule files from untrusted sources. When accepting a community
rule via a pull request, review its `condition` and fields as carefully as you
would review code.

### 4. Demo credentials must not leak

The local stack is configured for convenience, not secrecy. Never commit a real
`.env`, real credentials, or production secrets to the repository. Default/demo
credentials must never be reachable from outside the Compose network.

---

## Out of scope for v0.1

The following are **known** and **deferred** to later releases (tracked in the
[build plan](docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md)):

- Authentication / authorization on services.
- TLS between services and for external endpoints.
- Multi-tenancy and per-tenant isolation.
- Hardened, production-grade OpenSearch security configuration.
- AI-triage prompt-injection guardrails (the AI service is a passthrough stub in
  v0.1).

Reports about these documented, out-of-scope limitations are welcome as
**feature requests**, but they are not treated as vulnerabilities against v0.1.

---

## Supported versions

ARGUS is pre-1.0. Security fixes target the latest `main` and the current
release line only.

| Version | Supported |
|---------|-----------|
| v0.1 (`main`) | ✅ |
| < v0.1 | ❌ |

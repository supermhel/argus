# Contributing to ARGUS

Thanks for your interest in ARGUS. This guide gets you productive fast — and the
fastest, highest-value contribution is **adding a parser**.

---

## The zero-infra inner loop

**You do NOT need Docker or OpenSearch to add a parser.** The entire inner loop is
one command that runs in seconds on plain Python:

```sh
cd services/ws2-normalization && python test_contract.py
```

That test parses every registered source's sample, validates the output against the
OCSF schema (Contract A), and runs the full bus loop on the in-memory bus — no Redis,
no OpenSearch, no containers. Write your parser, run that command, see it pass. That's
the whole loop.

The repo-wide gate is just as light:

```sh
make test          # or: ./run_all_tests.sh
```

It runs the contract validator plus every workstream's `test_contract.py` on the
memory bus / in-memory stores / stub LLM. No infrastructure required.

Want to watch the whole pipeline produce a real alert end-to-end (still no Docker)?

```sh
make e2e           # or: python tools/demo_e2e.py
```

This injects a 10-event SSH brute-force burst and asserts a real alert reaches the
index and is idempotent under replay. It's the v0.1 acceptance test — a good thing to
run before and after your change.

---

## Add a parser (the best first contribution)

The five parsers below are **deferred to v0.2** and are the obvious first PRs. Each
is a self-contained module with a clean extension point — adding one never touches
an existing parser.

- Generic syslog
- SNMP
- NetFlow *(binary format — bigger lift)*
- Windows Event Log
- Custom JSON

**Step-by-step walkthrough:** [docs/adding-a-parser.md](docs/adding-a-parser.md).

In short, it's three small edits:

1. Add a new parser module under `services/ws2-normalization/parsers/`, subclassing
   `Parser` (copy `linux_ssh.py` as your template).
2. Register it in `services/ws2-normalization/parsers/__init__.py` (around line 19).
3. Add a sample + expectation so `test_contract.py` exercises it.

Then verify with `python test_contract.py`. Done.

---

## Project scope — read this before filing a feature request

ARGUS is built in versioned slices. Knowing the scope keeps requests triaged
correctly:

- **v0.1 = the detection pipeline.** Collect → normalize (4 parsers: Cisco ASA,
  Active Directory, VMware vSphere, Linux SSH) → detect (correlation rules + scoring)
  → index → dashboard. This is what works today.
- **AI triage is v0.2.** The AI service (WS-5) is a **passthrough stub** in v0.1 — it
  does not classify with a model yet. Local Ollama/Qwen triage is the v0.2 headline.
- **The 5 parsers above are v0.2** and are tracked as good first issues.

So:

- A request to **improve the pipeline, a parser, a rule, or the dashboard** → in scope
  for v0.1, very welcome.
- A request for **AI-triage behavior** → that's v0.2; file it, but expect it to be
  triaged against the v0.2 milestone, not v0.1.

See the [build plan](docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md) for
the full scope and roadmap.

---

## Pull request expectations

- **Open an issue first** for anything beyond a small fix, so we can agree on the
  approach. Use the [issue templates](.github/ISSUE_TEMPLATE/) — there's a dedicated
  one for parser requests.
- **Tests pass.** `make test` (i.e. `./run_all_tests.sh`) must be green. New behavior
  needs a contract test or sample that exercises it.
- **One logical change per PR.** A new parser is one PR; don't bundle unrelated
  refactors.
- **Match the existing style.** Keep parsers isolated (one module per source), derive
  `type_uid` (never hand-set it), and keep the output validating against Contract A.
- **Honest status.** Don't claim a capability works if it's stubbed. Accuracy over
  impressiveness is a core project value — especially for a security tool.
- **License.** By contributing, you agree your contribution is licensed under the
  project's [Apache-2.0 License](LICENSE).
- **Security.** If you found a vulnerability, do **not** open a public PR/issue —
  follow [SECURITY.md](SECURITY.md). Remember the detection engine executes rule
  files, so review any contributed rule's `condition` carefully.

---

## Code of conduct

Be respectful and constructive. We want ARGUS to be a welcoming project for
first-time open-source contributors.

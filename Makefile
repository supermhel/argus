# ARGUS — developer entry points.
# Quick start:  make preflight && make demo
# Contributor loop (no Docker):  make test

COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: help preflight demo test e2e up down

PYTHON ?= python3

help:
	@echo "ARGUS targets:"
	@echo "  make preflight  - check this machine is ready (vm.max_map_count, Docker RAM, free ports)"
	@echo "  make demo       - preflight + bring up the full stack (see banner for current limits)"
	@echo "  make test       - run the full zero-infra contract test suite (no Docker needed)"
	@echo "  make e2e        - zero-infra ACCEPTANCE test: SSH brute-force -> real alert (no Docker)"
	@echo "  make up         - start the stack detached (docker compose up -d)"
	@echo "  make down       - stop the stack and remove volumes"

# DX3 — the "doctor". Fails fast with plain-English remedies before anything starts.
preflight:
	@sh infra/preflight.sh

# One-command Dockerized stack. Honest about what is and isn't wired yet.
demo: preflight
	@echo ""
	@echo "=================================================================="
	@echo " Services are daemons now (T0 done). For a no-Docker proof that the"
	@echo " full detection pipeline produces a real alert, run:  make e2e"
	@echo " Remaining in-stack items: live demo feeder + dashboard reading"
	@echo " alerts straight from OpenSearch (DX2-live / DX4)."
	@echo "=================================================================="
	@echo ""
	$(COMPOSE) up

# Contributor inner loop — zero infrastructure.
test:
	@sh run_all_tests.sh

# v0.1 acceptance test — proves SSH brute-force -> real alert in the index,
# idempotent under replay, with no Docker/Redis/OpenSearch.
e2e:
	@$(PYTHON) tools/demo_e2e.py

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

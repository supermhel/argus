# WS-7 Dashboard — Interface Declaration

## Consumes
- HTTP: WS-6 inventory API (`GET /assets`, `/assets/{mac}`) — Contract C.
- Alerts from the `alerts` index (Contract E) — mocked here, wire to OpenSearch later.

## Produces
- Static single-file UI (`index.html`). No backend of its own.

## Structure (3 levels, per the agreed design)
- Level 1 **Vue globale** — device counts, critical alerts.
- Level 2 **Inventaire** — search by IP or MAC → device detail with IP history.
- Level 3 **Sources** — events per protocol/source.

Live vs mock: set `window.INVENTORY_API` to a WS-6 URL; otherwise `mocks/mock_data.js`.

## Contract tests
- `python test_contract.py`  (static checks: views present, API calls, mock shape)

## Run locally
- open `index.html`, or `docker compose up dashboard` (nginx).

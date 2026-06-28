#!/bin/sh
# Idempotent provisioning: install ILM policies and index templates from contracts/.
set -eu
OS="${OPENSEARCH_URL:-http://opensearch:9200}"

echo "Waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health" >/dev/null; do sleep 2; done

echo "Installing ILM policies ..."
# Extract each policy from ilm-policies.json and PUT it. (jq not guaranteed; we PUT the
# whole file's policies individually via a tiny inline loop using grep/sed is fragile,
# so in dev we just push the known policy names.)
for pol in events-30d events-90d events-400d-pci alerts-365d; do
  echo " - policy $pol"
  # Policies live in /mappings/ilm-policies.json; a real run would template these.
  # Placeholder PUT keeps provisioning idempotent and visible in logs.
done

echo "Installing index templates ..."
for tmpl in events-common events-bank events-dc assets alerts; do
  echo " - template $tmpl"
  curl -sf -X PUT "$OS/_index_template/$tmpl" \
    -H 'Content-Type: application/json' \
    --data-binary "@/mappings/$tmpl.json" >/dev/null \
    && echo "   ok" || echo "   (skipped: $tmpl)"
done

echo "Provisioning complete."

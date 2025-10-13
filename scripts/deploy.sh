#!/usr/bin/env bash
set -euo pipefail

VM_IP="134.199.198.192"
VM_USER="root"

echo "== Sync frontend =="
rsync -avz --delete ~/btc_did_api/site/ ${VM_USER}@${VM_IP}:/var/www/site/

echo "== Sync backend app/ =="
rsync -avz --delete ~/btc_did_api/app/  ${VM_USER}@${VM_IP}:/opt/sbm-api/app/

echo "== Sync requirements (if changed) =="
rsync -avz ~/btc_did_api/requirements.txt ${VM_USER}@${VM_IP}:/opt/sbm-api/requirements.txt

echo "== Install deps + restart API =="
ssh ${VM_USER}@${VM_IP} '
  set -e
  /opt/sbm-api/.venv/bin/pip install -r /opt/sbm-api/requirements.txt >/dev/null
  systemctl restart sbm-api
'

echo "== Done. Smoke tests =="
curl -sS https://beta.privacy-lion.com/ >/dev/null && echo "Frontend OK"
curl -sS https://api.beta.privacy-lion.com/healthz && echo

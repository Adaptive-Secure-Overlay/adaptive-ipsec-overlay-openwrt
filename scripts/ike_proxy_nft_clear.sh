#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if command -v nft >/dev/null 2>&1 && nft list table inet ikeproxy >/dev/null 2>&1; then
  nft delete table inet ikeproxy
  echo "[OK] nft IKE proxy rules removed"
else
  echo "[OK] nft IKE proxy rules are not present"
fi

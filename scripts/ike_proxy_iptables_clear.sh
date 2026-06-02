#!/usr/bin/env bash
set -euo pipefail
MARK_HEX="0x53"
CAP500="15000"
CAP4500="15001"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if command -v iptables >/dev/null 2>&1; then
  while iptables -t nat -C OUTPUT -p udp --dport 500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP500}" 2>/dev/null; do
    iptables -t nat -D OUTPUT -p udp --dport 500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP500}"
  done
  while iptables -t nat -C OUTPUT -p udp --dport 4500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP4500}" 2>/dev/null; do
    iptables -t nat -D OUTPUT -p udp --dport 4500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP4500}"
  done
fi
echo "[OK] iptables IKE proxy rules removed"

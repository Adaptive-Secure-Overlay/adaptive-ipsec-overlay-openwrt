#!/usr/bin/env bash
set -euo pipefail

# Legacy/iptables-nft fallback. Prefer ike_proxy_nft_apply.sh on Debian 13.
# This script redirects UDP/500 only by default because blindly redirecting UDP/4500
# may capture ESP-in-UDP after CHILD_SA is established. Use --with-4500 only for tests
# where you are sure UDP/4500 carries IKE, not ESP-in-UDP.

MARK_HEX="0x53"
CAP500="15000"
CAP4500="15001"
WITH_4500="${1:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

command -v iptables >/dev/null 2>&1 || { echo "iptables is not installed" >&2; exit 1; }

sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true

iptables -t nat -C OUTPUT -p udp --dport 500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP500}" 2>/dev/null || \
iptables -t nat -A OUTPUT -p udp --dport 500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP500}"

if [[ "${WITH_4500}" == "--with-4500" ]]; then
  iptables -t nat -C OUTPUT -p udp --dport 4500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP4500}" 2>/dev/null || \
  iptables -t nat -A OUTPUT -p udp --dport 4500 -m mark ! --mark "${MARK_HEX}" -j REDIRECT --to-ports "${CAP4500}"
  echo "[WARN] UDP/4500 fully redirected. ESP-in-UDP will also hit the adapter; prefer nft rules for real NAT-T."
fi

echo "[OK] iptables IKE proxy rules installed: UDP/500 -> ${CAP500}"

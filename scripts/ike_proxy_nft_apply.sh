#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/adaptive-ipsec-overlay/env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
fi

CONFIG="${OVERLAY_CONFIG:-/etc/adaptive-ipsec-overlay/overlay.json}"
MARK_HEX="${IKE_SOCKET_MARK:-0x53}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

command -v nft >/dev/null 2>&1 || { echo "nft is not installed" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is not installed" >&2; exit 1; }
[[ -f "${CONFIG}" ]] || { echo "Missing config: ${CONFIG}" >&2; exit 1; }

sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true

nft list table inet ikeproxy >/dev/null 2>&1 && nft delete table inet ikeproxy

tmp="$(mktemp)"
python3 - "${CONFIG}" "${MARK_HEX}" > "${tmp}" <<'PY'
import json
import sys

config_path, mark_hex = sys.argv[1], sys.argv[2]
with open(config_path, "r", encoding="utf-8") as handle:
    cfg = json.load(handle)

users = cfg.get("users", {})
cap500_base = int(cfg.get("ike_capture_500_base", 15100))
cap4500_base = int(cfg.get("ike_capture_4500_base", 15200))

print("add table inet ikeproxy")
print("add chain inet ikeproxy output_raw { type filter hook output priority raw; policy accept; }")
print("add chain inet ikeproxy output { type nat hook output priority dstnat; policy accept; }")
print(f"add rule inet ikeproxy output_raw meta mark {mark_hex} notrack")
print(f"add rule inet ikeproxy output meta mark {mark_hex} return")

for index, (name, user) in enumerate(users.items(), 1):
    ip = user["ip"]
    cap500 = int(user.get("ike500_port", cap500_base + index))
    print(f"add rule inet ikeproxy output ip daddr {ip} udp dport 500 redirect to :{cap500}")

for index, (name, user) in enumerate(users.items(), 1):
    ip = user["ip"]
    cap4500 = int(user.get("ike4500_port", cap4500_base + index))
    print(
        "add rule inet ikeproxy output "
        f"ip daddr {ip} udp dport 4500 @th,64,32 0x00000000 redirect to :{cap4500}"
    )
PY

nft -f "${tmp}"
rm -f "${tmp}"

echo "[OK] nft IKE proxy rules installed from ${CONFIG}, mark ${MARK_HEX}"

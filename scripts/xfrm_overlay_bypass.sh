#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/adaptive-ipsec-overlay/env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
fi

CONFIG="${OVERLAY_CONFIG:-/etc/adaptive-ipsec-overlay/overlay.json}"
OVERLAY_PORT="${OVERLAY_PORT:-9000}"
PRIORITY="${OVERLAY_XFRM_BYPASS_PRIORITY:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

command -v ip >/dev/null 2>&1 || { echo "iproute2/ip-full is not installed" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is not installed" >&2; exit 1; }
[[ -f "${CONFIG}" ]] || { echo "Missing config: ${CONFIG}" >&2; exit 1; }

readarray -t KNOWN_IPS < <(python3 - "${CONFIG}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    cfg = json.load(handle)
for user in cfg.get("users", {}).values():
    print(user["ip"])
PY
)

LOCAL_IP=""
for ip_addr in "${KNOWN_IPS[@]}"; do
  if ip -4 addr show | grep -qw "${ip_addr}"; then
    LOCAL_IP="${ip_addr}"
    break
  fi
done

if [[ -z "${LOCAL_IP}" ]]; then
  echo "[WARN] no configured overlay local IP found; xfrm overlay bypass not installed" >&2
  exit 0
fi

add_policy() {
  local dir="$1"
  local src="$2"
  local dst="$3"
  ip xfrm policy delete dir "${dir}" src "${src}/32" dst "${dst}/32" \
    proto udp sport "${OVERLAY_PORT}" dport "${OVERLAY_PORT}" >/dev/null 2>&1 || true
  ip xfrm policy add dir "${dir}" src "${src}/32" dst "${dst}/32" \
    proto udp sport "${OVERLAY_PORT}" dport "${OVERLAY_PORT}" \
    action allow priority "${PRIORITY}"
}

for peer in "${KNOWN_IPS[@]}"; do
  [[ "${peer}" == "${LOCAL_IP}" ]] && continue
  add_policy out "${LOCAL_IP}" "${peer}"
  add_policy in "${peer}" "${LOCAL_IP}"
done

echo "[OK] XFRM overlay bypass installed for ${LOCAL_IP}: UDP/${OVERLAY_PORT}, priority ${PRIORITY}"

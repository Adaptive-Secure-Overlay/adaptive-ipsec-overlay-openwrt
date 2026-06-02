#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-User11}"
ENV_FILE="${ENV_FILE:-/etc/adaptive-ipsec-overlay/env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
fi

BASE_DIR="${BASE_DIR:-/opt/adaptive-ipsec-overlay}"
PID_FILE="${PID_FILE:-/var/run/hybrid-overlay.pid}"
LOG_FILE="${LOG_FILE:-/var/log/hybrid-overlay-${NAME}.log}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

"${BASE_DIR}/scripts/openwrt_hybrid_stop.sh" >/dev/null 2>&1 || true

ip xfrm state flush >/dev/null 2>&1 || true
ip xfrm policy flush >/dev/null 2>&1 || true

"${BASE_DIR}/scripts/ike_proxy_nft_apply.sh"
/etc/init.d/ipsec stop >/dev/null 2>&1 || true
killall starter >/dev/null 2>&1 || true
killall charon >/dev/null 2>&1 || true
rm -f /var/run/charon.* /var/run/starter.charon.pid
/etc/init.d/ipsec start

cd "${BASE_DIR}"
rm -f "${PID_FILE}"
: > "${LOG_FILE}"
setsid /usr/bin/python3 "${BASE_DIR}/node_daemon.py" --name "${NAME}" --ike-proxy \
  >>"${LOG_FILE}" 2>&1 < /dev/null &
echo "$!" > "${PID_FILE}"
sleep 1

if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
  echo "hybrid overlay failed to start, see ${LOG_FILE}" >&2
  exit 1
fi

echo "[OK] OpenWrt hybrid overlay started as ${NAME}, pid=$(cat "${PID_FILE}")"

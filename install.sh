#!/usr/bin/env bash
set -euo pipefail

NODE_NAME="${1:-${NODE_NAME:-}}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/adaptive-ipsec-overlay}"
CONFIG_DIR="${CONFIG_DIR:-/etc/adaptive-ipsec-overlay}"
CONFIG_SOURCE="${CONFIG_SOURCE:-}"
START_NOW="${START_NOW:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

if [[ -z "${NODE_NAME}" ]]; then
  echo "Usage: NODE_NAME=User11 $0" >&2
  exit 1
fi

if command -v opkg >/dev/null 2>&1; then
  opkg update
  opkg install bash python3 python3-pip python3-cryptography nftables strongswan-full tcpdump ip-full || true
fi

install -d "${INSTALL_DIR}" "${INSTALL_DIR}/scripts" "${CONFIG_DIR}"
install -m 0644 "${PROJECT_DIR}/core/"*.py "${INSTALL_DIR}/"
install -m 0755 "${PROJECT_DIR}/scripts/"*.sh "${INSTALL_DIR}/scripts/"

if [[ -n "${CONFIG_SOURCE}" ]]; then
  install -m 0600 "${CONFIG_SOURCE}" "${CONFIG_DIR}/overlay.json"
elif [[ ! -f "${CONFIG_DIR}/overlay.json" ]]; then
  install -m 0600 "${PROJECT_DIR}/examples/overlay.sample.json" "${CONFIG_DIR}/overlay.json"
  echo "[WARN] Installed sample config to ${CONFIG_DIR}/overlay.json; edit it before starting real sessions."
fi

cat > "${CONFIG_DIR}/env" <<EOF
BASE_DIR=${INSTALL_DIR}
OVERLAY_CONFIG=${CONFIG_DIR}/overlay.json
NODE_NAME=${NODE_NAME}
IKE_PRIVACY_OVERLAY=1
IKE_PRIVACY_INLINE=1
PRECONNECT_ENABLED=1
EOF
chmod 0644 "${CONFIG_DIR}/env"

cat > /etc/init.d/adaptive-ipsec-overlay <<'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10

start() {
  [ -f /etc/adaptive-ipsec-overlay/env ] && . /etc/adaptive-ipsec-overlay/env
  /usr/bin/env bash /opt/adaptive-ipsec-overlay/scripts/openwrt_hybrid_start.sh "${NODE_NAME:-User11}"
}

stop() {
  /usr/bin/env bash /opt/adaptive-ipsec-overlay/scripts/openwrt_hybrid_stop.sh
}
EOF
chmod +x /etc/init.d/adaptive-ipsec-overlay

/etc/init.d/adaptive-ipsec-overlay enable
if [[ "${START_NOW}" == "1" ]]; then
  /etc/init.d/adaptive-ipsec-overlay restart
fi

echo "[OK] OpenWRT node ${NODE_NAME} installed in ${INSTALL_DIR}"

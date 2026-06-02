#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${PID_FILE:-/var/run/hybrid-overlay.pid}"

if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}" || true)"
  if command -v start-stop-daemon >/dev/null 2>&1; then
    start-stop-daemon -K -p "${PID_FILE}" >/dev/null 2>&1 || true
  elif [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${pid}" 2>/dev/null || true
  fi
  rm -f "${PID_FILE}"
fi

pkill -f '[n]ode_daemon.py' >/dev/null 2>&1 || true
nft delete table inet ikeproxy >/dev/null 2>&1 || true

echo "[OK] OpenWrt hybrid overlay stopped"

#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-User1}"
BASE_DIR="${BASE_DIR:-/opt/adaptive-ipsec-overlay}"
PID_FILE="${PID_FILE:-/var/run/hybrid-overlay-${NAME}.pid}"

if [[ -f "${PID_FILE}" ]]; then
  pid="$(cat "${PID_FILE}" || true)"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${pid}" 2>/dev/null || true
  fi
  rm -f "${PID_FILE}"
fi

pids="$(pgrep -f "${BASE_DIR}/[n]ode_daemon.py --name ${NAME}" || true)"
if [[ -n "${pids}" ]]; then
  kill -9 ${pids} >/dev/null 2>&1 || true
fi

killall tcpdump >/dev/null 2>&1 || true

echo "[OK] Debian hybrid overlay stopped as ${NAME}"

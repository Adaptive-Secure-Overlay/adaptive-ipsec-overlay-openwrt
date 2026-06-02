#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
STAGE="${DIST}/adaptive-ipsec-overlay"

rm -rf "${STAGE}"
mkdir -p "${STAGE}"
cp -r "${ROOT}/core" "${ROOT}/scripts" "${ROOT}/linux" "${ROOT}/openwrt" "${ROOT}/routeros7" "${ROOT}/examples" "${ROOT}/docs" "${STAGE}/"
cp "${ROOT}/README.md" "${STAGE}/"

mkdir -p "${DIST}"
tar -C "${DIST}" -czf "${DIST}/adaptive-ipsec-overlay.tar.gz" adaptive-ipsec-overlay
echo "[OK] ${DIST}/adaptive-ipsec-overlay.tar.gz"

import json
import os
from pathlib import Path
from typing import Dict


def _truthy(value: str, default: bool = False) -> bool:
    if value == "":
        return default
    return value.lower() in ("1", "true", "yes", "on")


CONFIG_PATH = Path(os.environ.get("OVERLAY_CONFIG", "/etc/adaptive-ipsec-overlay/overlay.json"))


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


_CONFIG = _load_config()

USERS: Dict[str, dict] = _CONFIG.get("users", {})

_active_users_env = os.environ.get("OVERLAY_ACTIVE_USERS", "").strip()
if _active_users_env:
    ACTIVE_USERS = [name.strip() for name in _active_users_env.split(",") if name.strip() in USERS]
elif _CONFIG.get("active_users"):
    ACTIVE_USERS = [name for name in _CONFIG["active_users"] if name in USERS]
else:
    ACTIVE_USERS = list(USERS.keys())

if not ACTIVE_USERS and USERS:
    ACTIVE_USERS = list(USERS.keys())

UDP_TIMEOUT_S = float(os.environ.get("UDP_TIMEOUT_S", _CONFIG.get("udp_timeout_s", 2.0)))
RETRIES = int(os.environ.get("OVERLAY_RETRIES", _CONFIG.get("retries", 3)))
PRECONNECT_ENABLED = _truthy(
    os.environ.get("PRECONNECT_ENABLED", str(_CONFIG.get("preconnect_enabled", True))),
    default=True,
)

I3_LEN = int(os.environ.get("I3_LEN", _CONFIG.get("i3_len", 24)))

IKE_PROXY_ENABLED = False
IKE_CAPTURE_BIND = os.environ.get("IKE_CAPTURE_BIND", _CONFIG.get("ike_capture_bind", "0.0.0.0"))
IKE_CAPTURE_PORTS = {500: 15000, 4500: 15001}

_cap500_base = int(_CONFIG.get("ike_capture_500_base", os.environ.get("IKE_CAPTURE_500_BASE", 15100)))
_cap4500_base = int(_CONFIG.get("ike_capture_4500_base", os.environ.get("IKE_CAPTURE_4500_BASE", 15200)))

IKE_CAPTURE_USER_PORTS = {500: {}, 4500: {}}
for index, name in enumerate(USERS.keys(), 1):
    user = USERS[name]
    IKE_CAPTURE_USER_PORTS[500][name] = int(user.get("ike500_port", _cap500_base + index))
    IKE_CAPTURE_USER_PORTS[4500][name] = int(user.get("ike4500_port", _cap4500_base + index))

IKE_CHARON_HOST = os.environ.get("IKE_CHARON_HOST", _CONFIG.get("ike_charon_host", "127.0.0.1"))
IKE_CHARON_PORTS = {500: 500, 4500: 4500}
IKE_SOCKET_MARK = int(str(_CONFIG.get("ike_socket_mark", os.environ.get("IKE_SOCKET_MARK", "0x53"))), 0)
IKE_TRANSPARENT_INJECT_REQUIRED = _truthy(
    os.environ.get(
        "IKE_TRANSPARENT_INJECT_REQUIRED",
        str(_CONFIG.get("ike_transparent_inject_required", True)),
    ),
    default=True,
)
IKE_PROXY_DEFAULT_DST_USER = os.environ.get(
    "IKE_PROXY_DEFAULT_DST_USER",
    str(_CONFIG.get("ike_proxy_default_dst_user", "")).strip(),
).strip()
IKE_ROUTE_TIMEOUT_S = float(os.environ.get("IKE_ROUTE_TIMEOUT_S", _CONFIG.get("ike_route_timeout_s", 10.0)))
IKE_ROUTE_CACHE_TTL_S = float(os.environ.get("IKE_ROUTE_CACHE_TTL_S", _CONFIG.get("ike_route_cache_ttl_s", 120.0)))
IKE_INLINE_ROUTE_TIMEOUT_S = float(
    os.environ.get("IKE_INLINE_ROUTE_TIMEOUT_S", _CONFIG.get("ike_inline_route_timeout_s", 5.0))
)
IKE_ROUTE_COOLDOWN_S = float(os.environ.get("IKE_ROUTE_COOLDOWN_S", _CONFIG.get("ike_route_cooldown_s", 30.0)))

IKE_PRIVACY_OVERLAY = _truthy(
    os.environ.get("IKE_PRIVACY_OVERLAY", str(_CONFIG.get("ike_privacy_overlay", True))),
    default=True,
)
IKE_PRIVACY_INLINE = _truthy(
    os.environ.get("IKE_PRIVACY_INLINE", str(_CONFIG.get("ike_privacy_inline", True))),
    default=True,
)

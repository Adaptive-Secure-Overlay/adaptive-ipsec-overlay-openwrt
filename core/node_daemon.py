# -*- coding: utf-8 -*-
"""
node_daemon.py (stable build)

Current route-selection mode:
- A picks X1 randomly from all known participants except A.
- X1 picks X2 randomly from all known participants except X1.
- Repeated logical roles are valid, e.g. A->B->A->B or A->X->B->B.
- PROXY hop ensures session to next hop on-demand (ensure_session) instead of hard-failing.

Requires: config.py, crypto_util.py, logging_util.py, protocol.py
"""

import argparse
import os
import random
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

from cryptography.hazmat.primitives.asymmetric import x25519

from config import (
    USERS, ACTIVE_USERS, UDP_TIMEOUT_S, RETRIES, I3_LEN, PRECONNECT_ENABLED,
    IKE_PROXY_ENABLED, IKE_ROUTE_TIMEOUT_S, IKE_ROUTE_CACHE_TTL_S,
    IKE_INLINE_ROUTE_TIMEOUT_S, IKE_ROUTE_COOLDOWN_S,
    IKE_PRIVACY_OVERLAY, IKE_PRIVACY_INLINE,
)
from logging_util import setup_logger
from crypto_util import (
    aesgcm_encrypt, aesgcm_decrypt,
    hkdf_sha256,
    xpub_bytes, xpub_from_bytes,
)
from protocol import (
    jdump, jload, err,
    T_MGMT_INIT, T_MGMT_INIT_RESP, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_I1, T_I2, T_OKX2,
    T_PROXY_BLOB, T_PRIV_FWD, T_PRIV_DELIVER, T_PRIV_BACK,
    T_PRIV_BKEY_REQ, T_PRIV_BKEY_RESP, T_PRIV_X1B_SEAL,
    T_PRIV_INLINE_START, T_PRIV_INLINE_X2,
    T_LOCAL_CONNECT,
    T_ERROR,
)

try:
    from ike_proxy import IkeProxy
except Exception:  # pragma: no cover - daemon can run demo mode without Linux IKE adapter
    IkeProxy = None

# =========================
# Structures
# =========================

@dataclass
class PendingHS:
    priv: x25519.X25519PrivateKey
    nr: bytes
    ni: bytes
    i_pub: bytes
    label: str

@dataclass
class MgmtSession:
    peer: str
    sid: str
    key: bytes

@dataclass
class ConnState:
    conn_id: str
    src: str
    dst: str
    x1: str
    x2: str
    ike_init_len: int
    ike_auth_len: int
    retries_left: int
    okx2_event: threading.Event
    done_event: threading.Event
    okx2_payload: Optional[bytes] = None
    last_error: Optional[dict] = None


@dataclass
class OverlayRoute:
    conn_id: str
    src: str
    dst: str
    x1: str
    x2: str
    created_at: float
    privacy: bool = False
    x2_pub: str = ""
    ab_pub: str = ""
    inline: bool = False


# =========================
# Daemon
# =========================

class NodeDaemon:
    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logger(name)

        if name not in USERS:
            raise RuntimeError(f"Unknown user {name} in config USERS")

        port = USERS[name]["port"]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # REUSEADDR helps after crashes; does not allow two active binds reliably on same IP:port (good).
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(0.2)

        self.lock = threading.Lock()
        self.running = True

        # sessions / pending responder state
        self.sessions: Dict[str, MgmtSession] = {}
        self.pending: Dict[str, PendingHS] = {}

        # ---- Mailboxes (only receiver thread reads socket) ----
        self.hs_initresp: Dict[str, dict] = {}
        self.hs_authresp: Dict[str, dict] = {}
        self.hs_init_ev: Dict[str, threading.Event] = {}
        self.hs_auth_ev: Dict[str, threading.Event] = {}

        # OKX2 mailbox by conn_id
        self.okx2_ev: Dict[str, threading.Event] = {}
        self.okx2_data: Dict[str, bytes] = {}
        self.okx2_x2name: Dict[str, str] = {}

        # active connections (initiator only)
        self.conns: Dict[str, ConnState] = {}
        self.ensure_inflight: Dict[str, threading.Event] = {}

        # Real-IKE overlay route cache. Key format: "SRC>DST" where SRC/DST are USERS keys.
        self.ike_routes: Dict[str, OverlayRoute] = {}
        self.ike_route_lock = threading.Lock()
        self.ike_proxy: Optional[object] = None
        self.route_cooldowns: Dict[str, float] = {}
        self.route_failure_counts: Dict[str, int] = {}

        # Experimental privacy/on-demand state. These maps deliberately keep only
        # local hop knowledge: X1 knows A/X2, X2 knows X1/B, B knows X2/A.
        self.priv_x1_state: Dict[str, dict] = {}
        self.priv_x2_state: Dict[str, dict] = {}
        self.priv_b_state: Dict[str, dict] = {}
        self.priv_ab_state: Dict[str, dict] = {}
        self.priv_x2_pub: Dict[str, str] = {}

        self.preconnect_thread: Optional[threading.Thread] = None

    # ---------- address book ----------
    def peer_addr(self, peer: str) -> Tuple[str, int]:
        rec = USERS[peer]
        return rec.get("overlay_ip", rec["ip"]), rec["port"]

    def send_peer(self, peer: str, payload: bytes):
        if peer == self.name:
            self.logger.error(f"[BUG] attempt to send to self peer={peer} DROP")
            return
        ip, port = self.peer_addr(peer)
        self.sock.sendto(payload, (ip, port))

    def peer_from_src(self, src: Tuple[str, int]) -> Optional[str]:
        sip, sport = src
        for u, rec in USERS.items():
            if rec.get("overlay_ip", rec["ip"]) == sip and rec["port"] == sport:
                return u
        return None

    def user_by_ip(self, ip: str) -> Optional[str]:
        for u, rec in USERS.items():
            if rec.get("ip") == ip:
                return u
        return None

    # ---------- JSON ----------
    def safe_load(self, data: bytes) -> Optional[dict]:
        try:
            return jload(data)
        except Exception:
            self.logger.warning("Malformed packet (non-json)")
            return None

    # ---------- mgmt KDF ----------
    def mgmt_kdf(self, shared: bytes, ni: bytes, nr: bytes, label: str) -> bytes:
        salt = ni + nr
        info = b"mgmt|ikev2-like|" + label.encode("utf-8")
        return hkdf_sha256(shared, salt=salt, info=info, length=32)

    # ---------- recv ----------
    def recv_one(self) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        try:
            data, src = self.sock.recvfrom(65535)
            return data, src
        except socket.timeout:
            return None
        except (ConnectionResetError, OSError) as exc:
            # Windows UDP sockets can surface ICMP port-unreachable/reset as
            # WinError 10054 on recvfrom().  The overlay must keep listening:
            # a transient unreachable peer should not kill the whole daemon.
            self.logger.warning(f"[UDP] recv ignored {type(exc).__name__}: {exc}")
            return None

    # =========================
    # Link crypto
    # =========================

    def link_send(self, peer: str, mtype: str, payload: bytes, meta: dict = None):
        with self.lock:
            sess = self.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session to {peer}")

        aad = f"{mtype}:{self.name}->{peer}:{sess.sid}".encode()
        nonce, ct = aesgcm_encrypt(sess.key, payload, aad=aad)

        msg = {"t": mtype, "sid": sess.sid, "from": self.name, "to": peer,
               "nonce": nonce.hex(), "ct": ct.hex(), "meta": meta or {}}
        self.send_peer(peer, jdump(msg))

    def link_decrypt(self, msg: dict) -> bytes:
        peer = msg["from"]
        with self.lock:
            sess = self.sessions.get(peer)
        if not sess:
            raise RuntimeError(f"No session from {peer}")
        msg_sid = msg.get("sid", "")
        if msg_sid and msg_sid != sess.sid:
            raise RuntimeError(f"Stale session from {peer}: got sid={msg_sid}, current sid={sess.sid}")

        aad = f"{msg['t']}:{peer}->{self.name}:{sess.sid}".encode()
        return aesgcm_decrypt(sess.key, bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), aad=aad)

    # =========================
    # One and only packet dispatcher
    # =========================

    def handle_packet(self, data: bytes, src: Tuple[str, int]):
        peer = self.peer_from_src(src)
        p = self.safe_load(data)
        if not p:
            return

        t = p.get("t")

        if t == T_LOCAL_CONNECT:
            self.on_local_connect(p, src)
            return

        # mgmt responder
        if t == T_MGMT_INIT:
            self.on_mgmt_init(p, peer)
            return
        if t == T_MGMT_AUTH:
            self.on_mgmt_auth(p, peer)
            return

        # mgmt initiator mailbox
        if t == T_MGMT_INIT_RESP:
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_initresp[sid] = p
                    ev = self.hs_init_ev.get(sid)
                if ev:
                    ev.set()
            return

        if t == T_MGMT_AUTH_RESP:
            sid = p.get("sid")
            if sid:
                with self.lock:
                    self.hs_authresp[sid] = p
                    ev = self.hs_auth_ev.get(sid)
                if ev:
                    ev.set()
            return

        # errors are plaintext
        if t == T_ERROR:
            self.on_error(p, peer)
            return

        # secure messages
        if t in (
            T_I1, T_I2, T_OKX2, T_PROXY_BLOB,
            T_PRIV_FWD, T_PRIV_DELIVER, T_PRIV_BACK,
            T_PRIV_BKEY_REQ, T_PRIV_BKEY_RESP, T_PRIV_X1B_SEAL,
            T_PRIV_INLINE_START, T_PRIV_INLINE_X2,
        ):
            self.on_secure_msg(p, peer)
            return

        self.logger.info(f"[DROP] unknown t={t} from={peer}")

    # =========================
    # MGMT responder
    # =========================

    def on_mgmt_init(self, p: dict, peer: Optional[str]):
        if not peer:
            # unknown sender endpoint (ip:port not in USERS)
            return
        sid = p["sid"]
        i_pub = bytes.fromhex(p["ke"])
        ni = bytes.fromhex(p["ni"])

        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = xpub_bytes(r_priv.public_key())
        nr = secrets.token_bytes(16)

        label = f"{peer}-{self.name}"  # initiator-responder
        with self.lock:
            self.pending[sid] = PendingHS(priv=r_priv, nr=nr, ni=ni, i_pub=i_pub, label=label)

        resp = jdump({
            "t": T_MGMT_INIT_RESP, "sid": sid, "from": self.name, "to": peer,
            "nr": nr.hex(), "ke": r_pub.hex()
        })
        self.send_peer(peer, resp)
        self.logger.info(f"[MGMT] <- {peer} INIT; -> INIT_RESP sid={sid}")

    def on_mgmt_auth(self, p: dict, peer: Optional[str]):
        if not peer:
            return
        sid = p["sid"]

        with self.lock:
            st = self.pending.get(sid)
        if not st:
            self.logger.warning(f"[MGMT] AUTH unknown sid={sid}")
            return

        shared = st.priv.exchange(xpub_from_bytes(st.i_pub))
        kd = self.mgmt_kdf(shared, st.ni, st.nr, label=st.label)

        aad = f"AUTH:{st.label}:{peer}->{self.name}:{sid}".encode()
        try:
            _ = aesgcm_decrypt(kd, bytes.fromhex(p["nonce"]), bytes.fromhex(p["ct"]), aad=aad)
        except Exception as e:
            self.logger.error(f"[MGMT] AUTH decrypt fail sid={sid}: {e}")
            self.send_peer(peer, err("AUTH_FAIL", "mgmt auth decrypt failed"))
            return

        aad2 = f"AUTH:{st.label}:{self.name}->{peer}:{sid}".encode()
        auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
        n2, c2 = aesgcm_encrypt(kd, auth_plain, aad=aad2)

        resp = jdump({"t": T_MGMT_AUTH_RESP, "sid": sid, "from": self.name, "to": peer,
                      "nonce": n2.hex(), "ct": c2.hex()})
        self.send_peer(peer, resp)

        with self.lock:
            self.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)
            self.pending.pop(sid, None)

        self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid}")

    # =========================
    # MGMT initiator (ensure_session)
    # =========================

    def ensure_session(self, peer: str, reason: str = "") -> bool:
        if peer == self.name:
            self.logger.error(f"[MGMT] ensure_session to self is forbidden, reason={reason}")
            return False
        with self.lock:
            if peer in self.sessions:
                return True
            inflight = self.ensure_inflight.get(peer)
            if inflight:
                wait_ev = inflight
            else:
                wait_ev = threading.Event()
                self.ensure_inflight[peer] = wait_ev

        if inflight:
            wait_ev.wait(UDP_TIMEOUT_S * RETRIES)
            with self.lock:
                return peer in self.sessions

        label = f"{self.name}-{peer}"  # initiator-responder

        for attempt in range(RETRIES):
            if attempt == 0:
                self.logger.info(f"[MGMT] ensure_session start {self.name}->{peer} reason={reason or 'unspecified'}")

            sid = secrets.token_hex(8)
            init_ev = threading.Event()
            auth_ev = threading.Event()
            with self.lock:
                self.hs_init_ev[sid] = init_ev
                self.hs_auth_ev[sid] = auth_ev
                self.hs_initresp.pop(sid, None)
                self.hs_authresp.pop(sid, None)

            i_priv = x25519.X25519PrivateKey.generate()
            i_pub = xpub_bytes(i_priv.public_key())
            ni = secrets.token_bytes(16)

            init_msg = jdump({
                "t": T_MGMT_INIT, "sid": sid, "from": self.name, "to": peer,
                "ni": ni.hex(), "ke": i_pub.hex()
            })
            self.send_peer(peer, init_msg)
            self.logger.info(f"[MGMT] -> {peer} INIT sid={sid} attempt={attempt+1}")

            if not init_ev.wait(UDP_TIMEOUT_S):
                self.logger.warning(f"[MGMT] timeout INIT_RESP from {peer} sid={sid} reason={reason or 'unspecified'}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp = self.hs_initresp.get(sid)

            if not resp or resp.get("from") != peer or resp.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad INIT_RESP mailbox sid={sid} reason={reason or 'unspecified'}")
                self._cleanup_hs(sid)
                continue

            nr = bytes.fromhex(resp["nr"])
            r_pub = bytes.fromhex(resp["ke"])
            shared = i_priv.exchange(xpub_from_bytes(r_pub))
            kd = self.mgmt_kdf(shared, ni, nr, label=label)

            aad = f"AUTH:{label}:{self.name}->{peer}:{sid}".encode()
            auth_plain = b"ID=" + self.name.encode() + b"|AUTH=" + secrets.token_bytes(16)
            n1, c1 = aesgcm_encrypt(kd, auth_plain, aad=aad)
            auth_msg = jdump({"t": T_MGMT_AUTH, "sid": sid, "from": self.name, "to": peer,
                              "nonce": n1.hex(), "ct": c1.hex()})
            self.send_peer(peer, auth_msg)

            if not auth_ev.wait(UDP_TIMEOUT_S):
                self.logger.warning(f"[MGMT] timeout AUTH_RESP from {peer} sid={sid} reason={reason or 'unspecified'}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                resp2 = self.hs_authresp.get(sid)

            if not resp2 or resp2.get("from") != peer or resp2.get("to") != self.name:
                self.logger.warning(f"[MGMT] bad AUTH_RESP mailbox sid={sid} reason={reason or 'unspecified'}")
                self._cleanup_hs(sid)
                continue

            aad2 = f"AUTH:{label}:{peer}->{self.name}:{sid}".encode()
            try:
                _ = aesgcm_decrypt(kd, bytes.fromhex(resp2["nonce"]), bytes.fromhex(resp2["ct"]), aad=aad2)
            except Exception as e:
                self.logger.error(f"[MGMT] AUTH_RESP decrypt fail: {e}")
                self._cleanup_hs(sid)
                continue

            with self.lock:
                self.sessions[peer] = MgmtSession(peer=peer, sid=sid, key=kd)

            self._cleanup_hs(sid)
            self.logger.info(f"[MGMT] EST {self.name}<->{peer} sid={sid} reason={reason or 'unspecified'}")
            with self.lock:
                self.ensure_inflight.pop(peer, None)
                wait_ev.set()
            return True

        with self.lock:
            self.ensure_inflight.pop(peer, None)
            wait_ev.set()
        return False

    def _cleanup_hs(self, sid: str):
        with self.lock:
            self.hs_init_ev.pop(sid, None)
            self.hs_auth_ev.pop(sid, None)
            self.hs_initresp.pop(sid, None)
            self.hs_authresp.pop(sid, None)

    # =========================
    # Secure messages
    # =========================

    def on_secure_msg(self, p: dict, peer: Optional[str]):
        if not peer:
            return
        t = p["t"]
        try:
            plain = self.link_decrypt(p)
        except Exception as e:
            self.logger.error(f"[SEC] decrypt fail t={t} from={peer}: {e}")
            bad_sid = str(p.get("sid", ""))
            with self.lock:
                sess = self.sessions.get(peer)
                if sess and (not bad_sid or sess.sid == bad_sid):
                    self.sessions.pop(peer, None)
            try:
                self.send_peer(peer, err(
                    "SESSION_RESET",
                    f"{self.name} could not decrypt {t}; re-establish management session",
                    meta={"bad_sid": bad_sid, "failed_t": t, "reset_by": self.name},
                ))
            except Exception:
                pass
            return

        if t == T_I1:
            self.handle_I1(peer, plain)
        elif t == T_I2:
            self.handle_I2(peer, plain)
        elif t == T_OKX2:
            self.handle_OKX2(peer, plain)
        elif t == T_PROXY_BLOB:
            self.handle_PROXY(peer, plain, p.get("meta") or {})
        elif t == T_PRIV_FWD:
            self.handle_PRIV_FWD(peer, plain)
        elif t == T_PRIV_DELIVER:
            self.handle_PRIV_DELIVER(peer, plain)
        elif t == T_PRIV_BACK:
            self.handle_PRIV_BACK(peer, plain)
        elif t == T_PRIV_BKEY_REQ:
            self.handle_PRIV_BKEY_REQ(peer, plain)
        elif t == T_PRIV_BKEY_RESP:
            self.handle_PRIV_BKEY_RESP(peer, plain)
        elif t == T_PRIV_X1B_SEAL:
            self.handle_PRIV_X1B_SEAL(peer, plain)
        elif t == T_PRIV_INLINE_START:
            self.handle_PRIV_INLINE_START(peer, plain)
        elif t == T_PRIV_INLINE_X2:
            self.handle_PRIV_INLINE_X2(peer, plain)

    @staticmethod
    def _kv_parse(s: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in s.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _seal_key_for_user(self, user: str) -> bytes:
        # Prototype recipient seal. In production this should be replaced by a
        # per-node private key / X25519 session so intermediate nodes cannot
        # derive recipient keys from the shared lab config.
        secret = USERS[user]["password"].encode("utf-8")
        return hkdf_sha256(secret, salt=b"overlay-recipient-seal-v1", info=f"seal:{user}".encode(), length=32)

    def _seal_for_user(self, user: str, conn_id: str, obj: dict) -> dict:
        aad = f"seal:{conn_id}:{user}".encode("utf-8")
        nonce, ct = aesgcm_encrypt(self._seal_key_for_user(user), jdump(obj), aad=aad)
        return {"to": user, "nonce": nonce.hex(), "ct": ct.hex()}

    def _open_seal_for_me(self, conn_id: str, sealed: dict) -> dict:
        if sealed.get("to") != self.name:
            raise RuntimeError(f"sealed payload is for {sealed.get('to')}, not {self.name}")
        aad = f"seal:{conn_id}:{self.name}".encode("utf-8")
        plain = aesgcm_decrypt(
            self._seal_key_for_user(self.name),
            bytes.fromhex(sealed["nonce"]),
            bytes.fromhex(sealed["ct"]),
            aad=aad,
        )
        return jload(plain)

    def _x1b_key(self, shared: bytes, conn_id: str) -> bytes:
        return hkdf_sha256(shared, salt=conn_id.encode("utf-8"), info=b"priv-x1-b-v1", length=32)

    def _ab_key(self, shared: bytes, conn_id: str) -> bytes:
        return hkdf_sha256(shared, salt=conn_id.encode("utf-8"), info=b"priv-b-a-v1", length=32)

    def _seal_x1b_locator(self, conn_id: str, b_pub_hex: str, req: str) -> dict:
        x1_priv = x25519.X25519PrivateKey.generate()
        x1_pub = xpub_bytes(x1_priv.public_key())
        shared = x1_priv.exchange(xpub_from_bytes(bytes.fromhex(b_pub_hex)))
        aad = f"priv-x1-b:{conn_id}".encode("utf-8")
        locator = {
            "src": req,
            "ike_src_ip": USERS[req]["ip"],
        }
        nonce, ct = aesgcm_encrypt(self._x1b_key(shared, conn_id), jdump(locator), aad=aad)
        return {
            "conn_id": conn_id,
            "x1ke": x1_pub.hex(),
            "nonce": nonce.hex(),
            "ct": ct.hex(),
        }

    def _open_x1b_locator_for_me(self, conn_id: str, sealed: dict) -> dict:
        if sealed.get("conn_id") != conn_id:
            raise RuntimeError(f"x1-b seal conn mismatch got={sealed.get('conn_id')} expected={conn_id}")
        with self.lock:
            st = self.priv_b_state.get(conn_id)
        if not st:
            raise RuntimeError(f"no B-side x1-b state for CONN={conn_id}")
        shared = st["priv"].exchange(xpub_from_bytes(bytes.fromhex(sealed["x1ke"])))
        aad = f"priv-x1-b:{conn_id}".encode("utf-8")
        plain = aesgcm_decrypt(
            self._x1b_key(shared, conn_id),
            bytes.fromhex(sealed["nonce"]),
            bytes.fromhex(sealed["ct"]),
            aad=aad,
        )
        return jload(plain)

    def _seal_back_for_a(self, route: OverlayRoute, payload: bytes,
                         ike_src_ip: str, ike_src_port: int,
                         ike_dst_ip: str, ike_dst_port: int,
                         udp_port: int) -> dict:
        if not route.ab_pub:
            return self._seal_for_user(route.src, route.conn_id, {
                "src": route.src,
                "dst": route.dst,
                "ike_payload": payload.hex(),
                "ike_src_ip": ike_src_ip,
                "ike_src_port": int(ike_src_port),
                "ike_dst_ip": ike_dst_ip,
                "ike_dst_port": int(ike_dst_port),
                "udp_port": int(udp_port),
            })

        b_priv = x25519.X25519PrivateKey.generate()
        b_pub = xpub_bytes(b_priv.public_key())
        shared = b_priv.exchange(xpub_from_bytes(bytes.fromhex(route.ab_pub)))
        aad = f"priv-b-a:{route.conn_id}".encode("utf-8")
        nonce, ct = aesgcm_encrypt(self._ab_key(shared, route.conn_id), jdump({
            "src": route.src,
            "dst": route.dst,
            "ike_payload": payload.hex(),
            "ike_src_ip": ike_src_ip,
            "ike_src_port": int(ike_src_port),
            "ike_dst_ip": ike_dst_ip,
            "ike_dst_port": int(ike_dst_port),
            "udp_port": int(udp_port),
        }), aad=aad)
        return {
            "mode": "x25519",
            "conn_id": route.conn_id,
            "bke": b_pub.hex(),
            "nonce": nonce.hex(),
            "ct": ct.hex(),
        }

    def _open_back_for_a(self, conn_id: str, sealed_a: dict) -> dict:
        if sealed_a.get("mode") != "x25519":
            return self._open_seal_for_me(conn_id, sealed_a)
        if sealed_a.get("conn_id") != conn_id:
            raise RuntimeError(f"back seal conn mismatch got={sealed_a.get('conn_id')} expected={conn_id}")
        with self.lock:
            st = self.priv_ab_state.get(conn_id)
        if not st:
            raise RuntimeError(f"no A-side B->A state for CONN={conn_id}")
        shared = st["priv"].exchange(xpub_from_bytes(bytes.fromhex(sealed_a["bke"])))
        aad = f"priv-b-a:{conn_id}".encode("utf-8")
        plain = aesgcm_decrypt(
            self._ab_key(shared, conn_id),
            bytes.fromhex(sealed_a["nonce"]),
            bytes.fromhex(sealed_a["ct"]),
            aad=aad,
        )
        return jload(plain)

    def _canonical_ike_ports(self, ike_src_port: int, ike_dst_port: int, udp_port: int) -> Tuple[int, int]:
        # nft REDIRECT / raw inject can expose transient local ports. For IKE
        # semantics and correct NAT-T/XFRM state, overlay metadata carries the
        # canonical IKE port matching the captured UDP service.
        if int(udp_port) in (500, 4500):
            return int(udp_port), int(udp_port)
        return int(ike_src_port), int(ike_dst_port)

    # I1: A->X1 (Enc_KD1): legacy "CONN=<id>|REQ=<A>|DST=<B>".
    # Privacy mode intentionally omits DST: "CONN=<id>|REQ=<A>|MODE=PRIV".
    def handle_I1(self, peer: str, plain: bytes):
        s = plain.rstrip(b"\x00").decode(errors="ignore")
        self.logger.info(f"[I1] from={peer} '{s}'")
        kv = self._kv_parse(s)
        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        dst = kv.get("DST", "")
        mode = kv.get("MODE", "")

        if mode == "PRIV":
            if not conn_id or not req:
                self.logger.error("[I1/PRIV] bad fields")
                return
            if req not in USERS:
                self.logger.error("[I1/PRIV] unknown REQ")
                return

            cand_x2 = [u for u in ACTIVE_USERS if u != self.name]
            random.shuffle(cand_x2)
            if not cand_x2:
                self.logger.error("[I1/PRIV] no X2 candidates after exclusions")
                self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_X2_CAND", msg="no X2 candidates")
                return

            self.logger.info(f"[ROLE] PRIV X1={self.name} selected by A={req}; DST hidden; CONN={conn_id}")
            th = threading.Thread(
                target=self._try_route_x2_priv,
                args=(conn_id, req, cand_x2),
                daemon=True,
            )
            th.start()
            return

        if not conn_id or not req or not dst:
            self.logger.error("[I1] bad fields")
            return
        if req not in USERS or dst not in USERS:
            self.logger.error("[I1] unknown REQ/DST")
            return

        # Dissertation mode: roles are allowed to repeat across logical hops.
        # X1 only excludes itself, so X2 may be the requester (A) or destination (B).
        cand_x2 = [u for u in ACTIVE_USERS if u != self.name]
        random.shuffle(cand_x2)
        if not cand_x2:
            self.logger.error("[I1] no X2 candidates after exclusions")
            self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_X2_CAND", msg="no X2 candidates")
            return

        self.logger.info(f"[ROLE] X1={self.name} selected by A={req} for DST={dst} CONN={conn_id}")
        th = threading.Thread(
            target=self._try_route_x2,
            args=(conn_id, req, dst, cand_x2),
            daemon=True,
        )
        th.start()

    # I2: X1->X2
    def handle_I2(self, peer: str, plain: bytes):
        s = plain.rstrip(b"\x00").decode(errors="ignore")
        self.logger.info(f"[I2] from={peer} '{s}'")
        kv = self._kv_parse(s)
        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        dst = kv.get("DST", "")
        x2 = kv.get("X2", "")
        mode = kv.get("MODE", "")

        if mode == "PRIV":
            if not conn_id or not x2:
                self.logger.error("[I2/PRIV] bad fields")
                return
            if x2 != self.name:
                self.logger.error(f"[I2/PRIV] wrong X2={x2} on {self.name}")
                return

            x2_priv = x25519.X25519PrivateKey.generate()
            x2_pub = xpub_bytes(x2_priv.public_key())
            with self.lock:
                self.priv_x2_state[conn_id] = {
                    "x1": peer,
                    "priv": x2_priv,
                    "created_at": time.time(),
                }

            ok = secrets.token_bytes(32)
            header = f"CONN={conn_id}|MODE=PRIV|X2={x2}|KE={x2_pub.hex()}".encode()
            payload = header + b"|OK=" + ok
            self.link_send(peer, T_OKX2, payload)
            self.logger.info(f"[OKX2/PRIV] -> {peer} CONN={conn_id} X2={x2}; A/DST hidden from X2 at this stage")
            return

        if not conn_id or not req or not dst or not x2:
            self.logger.error("[I2] bad fields")
            return

        ok = secrets.token_bytes(32) + secrets.token_bytes(16)
        header = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode()
        payload = header + b"|OK=" + ok

        self.link_send(peer, T_OKX2, payload)
        self.logger.info(f"[OKX2] -> {peer} CONN={conn_id} for REQ={req} ok_len={len(ok)}")

    # OKX2: X2->X1 (KD2) then X1->A (KD1)
    def handle_OKX2(self, peer: str, plain: bytes):
        marker = b"|OK="
        if marker not in plain:
            self.logger.warning("[OKX2] bad format (no |OK=)")
            return

        hdr_b, ok = plain.split(marker, 1)
        hdr_s = hdr_b.decode(errors="ignore")
        kv = self._kv_parse(hdr_s)

        conn_id = kv.get("CONN", "")
        req = kv.get("REQ", "")
        x2 = kv.get("X2", "")
        mode = kv.get("MODE", "")
        x2_pub = kv.get("KE", "")

        self.logger.info(f"[OKX2] from={peer} CONN={conn_id} REQ={req} X2={x2} ok_len={len(ok)}")

        if mode == "PRIV" and self.name != req:
            with self.lock:
                st = self.priv_x1_state.get(conn_id)
            if not st:
                self.logger.warning(f"[OKX2/PRIV] no X1 state CONN={conn_id}")
                return
            req = st.get("req", "")
            if not req or req not in USERS:
                self.logger.warning(f"[OKX2/PRIV] bad req in X1 state CONN={conn_id}")
                return
            if req not in self.sessions and not self.ensure_session(req, reason=f"OKX2/PRIV forward CONN={conn_id}"):
                self.logger.error(f"[OKX2/PRIV] cannot ensure session to {req}")
                return
            hdr_forward = f"CONN={conn_id}|MODE=PRIV|REQ={req}|X2={x2}|KE={x2_pub}".encode()
            self.link_send(req, T_OKX2, hdr_forward + b"|OK=" + ok)
            self.logger.info(f"[OKX2/PRIV] fwd {self.name}->{req} CONN={conn_id}; DST still hidden from X1")
            return

        # forward to requester if I'm not requester
        if self.name != req:
            if req not in USERS:
                return
            if req not in self.sessions and not self.ensure_session(req, reason=f"OKX2 forward CONN={conn_id}"):
                self.logger.error(f"[OKX2] cannot ensure session to {req}")
                return
            self.link_send(req, T_OKX2, plain)
            self.logger.info(f"[OKX2] fwd {self.name}->{req} CONN={conn_id}")
            return

        # I'm requester(A)
        with self.lock:
            ev = self.okx2_ev.get(conn_id)
            self.okx2_data[conn_id] = ok
            self.okx2_x2name[conn_id] = x2
            if mode == "PRIV" and x2_pub:
                self.priv_x2_pub[conn_id] = x2_pub
        if ev:
            ev.set()
        if mode == "PRIV":
            self.logger.info(f"[ROLE] PRIV A={self.name} got X2={x2} pub via {peer} CONN={conn_id}")
        else:
            self.logger.info(f"[ROLE] A={self.name} got OKX2 from X2={x2} via {peer} CONN={conn_id}")

    # PROXY_BLOB forward path: src->x1->x2->dst; back path: dst->x2->x1->src
    def handle_PROXY(self, peer: str, plain: bytes, meta: dict):
        conn_id = meta.get("conn_id", "")
        src_u = meta.get("src", "")
        dst_u = meta.get("dst", "")
        x1_u = meta.get("x1", "")
        x2_u = meta.get("x2", "")
        idx = int(meta.get("idx", 0))
        direction = meta.get("dir", "fwd")
        phase = meta.get("phase", "UNK")

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        if idx < 0 or idx >= len(route) or route[idx] != self.name:
            self.logger.warning(f"[PROXY] route mismatch idx={idx} dir={direction} route={route}")
            return

        # Repeated logical roles are valid in the dissertation model.  Example:
        # A->X->B->B means B is both X2 and final destination.  There is no network
        # hop between the adjacent B positions, so consume same-node hops locally.
        while idx + 1 < len(route) and route[idx + 1] == self.name:
            idx += 1
            meta = dict(meta)
            meta["idx"] = idx
            self.logger.info(
                f"[PROXY] local self-hop collapse idx={idx} dir={direction} "
                f"route={src_u}->{x1_u}->{x2_u}->{dst_u} CONN={conn_id}"
            )

        kind = meta.get("kind", "demo")

        # Real IKE mode: terminal nodes inject into local strongSwan/charon.
        # No echo is generated here; the real strongSwan response will be captured by IkeProxy
        # and sent back over the cached reverse route.
        if kind == "ike":
            if direction == "fwd" and self.name == dst_u and idx == 3:
                self.logger.info(f"[IKE-OVERLAY] ARRIVE DST={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
                self.deliver_ike_to_local_strongswan(plain, meta)
                return
            if direction == "back" and self.name == src_u and idx == 3:
                self.logger.info(f"[IKE-OVERLAY] ARRIVE SRC={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
                self.deliver_ike_to_local_strongswan(plain, meta)
                return
            self.forward_proxy(plain, meta)
            return

        # Demo mode retained for the old synthetic test: destination echoes payload back.
        if direction == "fwd" and self.name == dst_u and idx == 3:
            self.logger.info(f"[PROXY] ARRIVE DST={self.name} phase={phase} len={len(plain)} CONN={conn_id}")
            resp = plain
            meta2 = dict(meta)
            meta2["dir"] = "back"
            meta2["idx"] = 0
            self.forward_proxy(resp, meta2)
            return

        self.forward_proxy(plain, meta)

    def forward_proxy(self, payload: bytes, meta: dict):
        src_u = meta["src"]; dst_u = meta["dst"]; x1_u = meta["x1"]; x2_u = meta["x2"]
        idx = int(meta["idx"])
        direction = meta.get("dir", "fwd")
        phase = meta.get("phase", "UNK")
        conn_id = meta.get("conn_id", "")

        route_fwd = [src_u, x1_u, x2_u, dst_u]
        route_back = [dst_u, x2_u, x1_u, src_u]
        route = route_fwd if direction == "fwd" else route_back

        nxt_idx = idx + 1
        if nxt_idx >= len(route):
            return
        nxt = route[nxt_idx]

        meta2 = dict(meta)
        meta2["idx"] = nxt_idx
        if nxt == self.name:
            self.logger.info(
                f"[PROXY] local self-hop forward idx={nxt_idx} dir={direction} "
                f"route={src_u}->{x1_u}->{x2_u}->{dst_u} CONN={conn_id}"
            )
            self.handle_PROXY(self.name, payload, meta2)
            return

        # Do not run a blocking management handshake from inside the single UDP
        # receiver/dispatcher thread. If we block here waiting for INIT_RESP,
        # the same thread cannot receive INIT_RESP and we get the observed
        # false NO_SESSION_NEXT despite the peer sending a response.
        with self.lock:
            has_session = nxt in self.sessions
        if not has_session:
            self.logger.info(
                f"[PROXY] no session to {nxt}; async ensure before forwarding "
                f"phase={phase} CONN={conn_id}"
            )
            threading.Thread(
                target=self._ensure_and_link_send_proxy,
                args=(nxt, payload, meta2, src_u, x1_u, phase, conn_id, direction),
                daemon=True,
                name=f"proxy-ensure-{self.name}-{nxt}-{conn_id}",
            ).start()
            return

        self._link_send_proxy_checked(nxt, payload, meta2, direction, phase, conn_id)

    def _ensure_and_link_send_proxy(self, nxt: str, payload: bytes, meta2: dict,
                                    src_u: str, x1_u: str, phase: str,
                                    conn_id: str, direction: str):
        if not self.ensure_session(nxt, reason=f"PROXY {direction} phase={phase} CONN={conn_id}"):
            self.logger.error(f"[PROXY] cannot ensure session to {nxt}")
            self.send_error_back(conn_id, src_u, x1_u, phase, code="NO_SESSION_NEXT", msg=f"cannot ensure {nxt}")
            return
        self._link_send_proxy_checked(nxt, payload, meta2, direction, phase, conn_id)

    def _link_send_proxy_checked(self, nxt: str, payload: bytes, meta2: dict,
                                 direction: str, phase: str, conn_id: str):
        src_u = meta2.get("src", ""); dst_u = meta2.get("dst", "")
        x1_u = meta2.get("x1", ""); x2_u = meta2.get("x2", "")
        try:
            self.link_send(nxt, T_PROXY_BLOB, payload, meta=meta2)
        except Exception as e:
            self.logger.error(f"[PROXY] send to {nxt} failed phase={phase} CONN={conn_id}: {e}")
            return
        self.logger.info(
            f"[PROXY] {direction} {self.name}->{nxt} idx={meta2.get('idx')} phase={phase} "
            f"route={src_u}->{x1_u}->{x2_u}->{dst_u} CONN={conn_id}"
        )

    # =========================
    # Experimental privacy/on-demand IKE path
    # =========================

    def _ensure_priv_ab_pub(self, conn_id: str, dst: str) -> str:
        with self.lock:
            ab_state = self.priv_ab_state.get(conn_id)
            if not ab_state:
                ab_priv = x25519.X25519PrivateKey.generate()
                ab_pub = xpub_bytes(ab_priv.public_key()).hex()
                self.priv_ab_state[conn_id] = {
                    "priv": ab_priv,
                    "pub": ab_pub,
                    "dst": dst,
                    "created_at": time.time(),
                }
                return ab_pub
            return ab_state["pub"]

    def _build_inline_x2_capsule(self, x2: str, route: OverlayRoute, payload: bytes,
                                 ike_dst_ip: str, ike_dst_port: int, udp_port: int) -> dict:
        return self._seal_for_user(x2, route.conn_id, {
            "conn_id": route.conn_id,
            "dst": route.dst,
            "ike_payload": payload.hex(),
            "a_to_b_ke": self._ensure_priv_ab_pub(route.conn_id, route.dst),
            "ike_dst_ip": ike_dst_ip,
            "ike_dst_port": int(ike_dst_port),
            "udp_port": int(udp_port),
            "inline": True,
        })

    def _send_priv_inline_start(self, route: OverlayRoute, payload: bytes,
                                ike_src_ip: str, ike_src_port: int,
                                ike_dst_ip: str, ike_dst_port: int,
                                udp_port: int):
        if route.x1 not in self.sessions and not self.ensure_session(route.x1, reason=f"PRIV INLINE A->X1 start CONN={route.conn_id}"):
            raise RuntimeError(f"cannot ensure inline X1={route.x1} CONN={route.conn_id}")
        cand_x2 = [u for u in ACTIVE_USERS if u != route.x1]
        capsules = {
            x2: self._build_inline_x2_capsule(x2, route, payload, ike_dst_ip, ike_dst_port, udp_port)
            for x2 in cand_x2
        }
        msg = {
            "conn_id": route.conn_id,
            "req": route.src,
            "capsules": capsules,
            "inline": True,
            "ike_src_ip_hint": ike_src_ip,
            "ike_src_port_hint": int(ike_src_port),
        }
        self.link_send(route.x1, T_PRIV_INLINE_START, jdump(msg), meta={"conn_id": route.conn_id, "mode": "priv-inline"})
        self.logger.info(
            f"[IKE-OVERLAY/PRIV-INLINE] START sent first IKE len={len(payload)} "
            f"A={route.src}->X1={route.x1}->X2(on-demand)->DST(hidden from X1) CONN={route.conn_id}"
        )

    def _send_priv_inline_ike_fwd(self, route: OverlayRoute, payload: bytes,
                                  ike_src_ip: str, ike_src_port: int,
                                  ike_dst_ip: str, ike_dst_port: int,
                                  udp_port: int):
        if not route.x2:
            self._send_priv_inline_start(route, payload, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, udp_port)
            return
        if route.x1 not in self.sessions and not self.ensure_session(route.x1, reason=f"PRIV INLINE A->X1 fwd CONN={route.conn_id}"):
            raise RuntimeError(f"cannot ensure inline X1={route.x1} CONN={route.conn_id}")
        capsule = self._build_inline_x2_capsule(route.x2, route, payload, ike_dst_ip, ike_dst_port, udp_port)
        msg = {"conn_id": route.conn_id, "x2": route.x2, "capsule": capsule, "inline": True}
        self.link_send(route.x1, T_PRIV_INLINE_X2, jdump(msg), meta={"conn_id": route.conn_id, "mode": "priv-inline"})
        self.logger.info(
            f"[IKE-OVERLAY/PRIV-INLINE] SEND fwd len={len(payload)} "
            f"A={route.src}->X1={route.x1}->X2={route.x2}->DST(hidden from X1, A-locator sealed by X1-B) CONN={route.conn_id}"
        )

    def _send_priv_ike_fwd(self, route: OverlayRoute, payload: bytes,
                           ike_src_ip: str, ike_src_port: int,
                           ike_dst_ip: str, ike_dst_port: int,
                           udp_port: int):
        a_priv = x25519.X25519PrivateKey.generate()
        a_pub = xpub_bytes(a_priv.public_key())
        shared = a_priv.exchange(xpub_from_bytes(bytes.fromhex(route.x2_pub)))
        k_ax2 = hkdf_sha256(shared, salt=route.conn_id.encode("utf-8"), info=b"priv-a-x2-v1", length=32)

        inner = {
            "conn_id": route.conn_id,
            "dst": route.dst,
            "ike_payload": payload.hex(),
            "a_to_b_ke": self._ensure_priv_ab_pub(route.conn_id, route.dst),
            "ike_dst_ip": ike_dst_ip,
            "ike_dst_port": int(ike_dst_port),
            "udp_port": int(udp_port),
        }
        aad = f"priv-a-x2:{route.conn_id}:{route.x2}".encode("utf-8")
        nonce, ct = aesgcm_encrypt(k_ax2, jdump(inner), aad=aad)
        fwd = {
            "conn_id": route.conn_id,
            "x2": route.x2,
            "ake": a_pub.hex(),
            "nonce": nonce.hex(),
            "ct": ct.hex(),
        }
        self.link_send(route.x1, T_PRIV_FWD, jdump(fwd), meta={"conn_id": route.conn_id, "mode": "priv"})
        self.logger.info(
            f"[IKE-OVERLAY/PRIV] SEND fwd len={len(payload)} "
            f"A={route.src}->X1={route.x1}->X2={route.x2}->DST(hidden from X1, A-locator sealed by X1-B) CONN={route.conn_id}"
        )

    def _send_priv_ike_back(self, route: OverlayRoute, payload: bytes,
                            ike_src_ip: str, ike_src_port: int,
                            ike_dst_ip: str, ike_dst_port: int,
                            udp_port: int):
        if not route.x2:
            raise RuntimeError(f"privacy reverse route has no X2 CONN={route.conn_id}")
        sealed_a = self._seal_back_for_a(
            route, payload,
            ike_src_ip, ike_src_port,
            ike_dst_ip, ike_dst_port,
            udp_port,
        )
        back = {"conn_id": route.conn_id, "sealed_a": sealed_a, "inline": bool(route.inline)}
        if route.x2 == self.name:
            self.logger.info(f"[IKE-OVERLAY/PRIV] reverse local B==X2 on {self.name}; consume local hop CONN={route.conn_id}")
            self.handle_PRIV_BACK(self.name, jdump(back))
            return
        self.link_send(route.x2, T_PRIV_BACK, jdump(back), meta={"conn_id": route.conn_id, "mode": "priv"})
        self.logger.info(
            f"[IKE-OVERLAY/PRIV] SEND back len={len(payload)} "
            f"DST={route.dst}->X2={route.x2}->X1(hidden)->A(sealed) CONN={route.conn_id}"
        )

    def _prepare_priv_bkey_response(self, conn_id: str, x2_peer: str) -> dict:
        b_priv = x25519.X25519PrivateKey.generate()
        b_pub = xpub_bytes(b_priv.public_key())
        with self.lock:
            self.priv_b_state[conn_id] = {
                "priv": b_priv,
                "x2": x2_peer,
                "created_at": time.time(),
            }
        self.logger.info(f"[PRIV/BKEY] B={self.name} prepared ephemeral X25519 key for hidden X1-B locator seal CONN={conn_id}")
        return {"conn_id": conn_id, "bke": b_pub.hex()}

    def _forward_priv_bkey_resp_as_x2(self, conn_id: str, resp: dict):
        with self.lock:
            st = self.priv_x2_state.get(conn_id)
            x1 = st.get("x1", "") if st else ""
        if not x1:
            self.logger.error(f"[PRIV/BKEY] X2={self.name} has no X1 state for CONN={conn_id}")
            return
        if x1 == self.name:
            self.handle_PRIV_BKEY_RESP(self.name, jdump(resp))
            return
        if x1 not in self.sessions and not self.ensure_session(x1, reason=f"PRIV BKEY_RESP X2->X1 CONN={conn_id}"):
            self.logger.error(f"[PRIV/BKEY] cannot ensure X1={x1} CONN={conn_id}")
            return
        self.link_send(x1, T_PRIV_BKEY_RESP, jdump(resp), meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/BKEY] X2={self.name} forwarded B pubkey to hidden X1={x1}; A locator still absent CONN={conn_id}")

    def _request_priv_bkey(self, conn_id: str, dst: str):
        if dst == self.name:
            resp = self._prepare_priv_bkey_response(conn_id, self.name)
            self._forward_priv_bkey_resp_as_x2(conn_id, resp)
            return
        if not self.ensure_session(dst, reason=f"PRIV BKEY_REQ X2->B CONN={conn_id}"):
            self.logger.error(f"[PRIV/BKEY] cannot ensure B={dst} CONN={conn_id}")
            return
        self.link_send(dst, T_PRIV_BKEY_REQ, jdump({"conn_id": conn_id}), meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/BKEY] X2={self.name}->B={dst} requested B pubkey; A hidden from X2 CONN={conn_id}")

    def _send_priv_deliver_to_dst(self, dst: str, deliver: dict, conn_id: str):
        if dst == self.name:
            self.logger.info(f"[PRIV/FWD] X2 is also B on {self.name}; consume local X2->B hop CONN={conn_id}")
            self.handle_PRIV_DELIVER(self.name, jdump(deliver))
            return
        if dst not in self.sessions and not self.ensure_session(dst, reason=f"PRIV X2->DST CONN={conn_id}"):
            self.logger.error(f"[PRIV/FWD] cannot ensure dst={dst}")
            return
        self.link_send(dst, T_PRIV_DELIVER, jdump(deliver), meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/FWD] X2={self.name} delivered IKE to B={dst}; A locator is X1-B sealed and opaque to X2; CONN={conn_id}")

    def _flush_priv_deliveries(self, conn_id: str):
        with self.lock:
            st = self.priv_x2_state.get(conn_id)
            if not st:
                return
            dst = st.get("dst", "")
            seal = st.get("x1b_seal")
            queued = list(st.get("queued_deliveries", []))
            st["queued_deliveries"] = []
        if not dst or not seal:
            return
        for deliver in queued:
            deliver["x1b_seal"] = seal
            self._send_priv_deliver_to_dst(dst, deliver, conn_id)

    def _queue_priv_x2_inner(self, conn_id: str, inner: dict, log_prefix: str = "[PRIV/FWD]"):
        dst = inner.get("dst", "")
        if dst not in USERS:
            self.logger.error(f"{log_prefix} X2 got unknown dst={dst} CONN={conn_id}")
            return

        deliver = {
            "conn_id": conn_id,
            "ike_payload": inner.get("ike_payload", ""),
            "a_to_b_ke": inner.get("a_to_b_ke", ""),
            "ike_dst_ip": inner.get("ike_dst_ip", ""),
            "ike_dst_port": int(inner.get("ike_dst_port", 0)),
            "udp_port": int(inner.get("udp_port", 0)),
            "inline": bool(inner.get("inline", False)),
        }

        with self.lock:
            st = self.priv_x2_state.get(conn_id)
            if not st:
                self.logger.warning(f"{log_prefix} X2 has no state CONN={conn_id}")
                return
            st["dst"] = dst
            if inner.get("inline"):
                st["inline"] = True
            seal = st.get("x1b_seal")
            if not seal:
                st.setdefault("queued_deliveries", []).append(deliver)
                need_bkey = not st.get("bkey_requested")
                st["bkey_requested"] = True
            else:
                need_bkey = False

        if not seal:
            if need_bkey:
                threading.Thread(
                    target=self._request_priv_bkey,
                    args=(conn_id, dst),
                    daemon=True,
                    name=f"priv-bkey-{self.name}-{dst}-{conn_id}",
                ).start()
            self.logger.info(
                f"{log_prefix} X2={self.name} queued IKE for B={dst}; waiting X1-B seal so A locator stays hidden from X2 CONN={conn_id}"
            )
            return

        deliver["x1b_seal"] = seal
        threading.Thread(
            target=self._send_priv_deliver_to_dst,
            args=(dst, deliver, conn_id),
            daemon=True,
            name=f"priv-deliver-{self.name}-{dst}-{conn_id}",
        ).start()

    def handle_PRIV_FWD(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
        except Exception as e:
            self.logger.error(f"[PRIV/FWD] bad json from={peer}: {e}")
            return
        conn_id = msg.get("conn_id", "")
        x2 = msg.get("x2", "")
        if not conn_id or not x2:
            self.logger.error("[PRIV/FWD] bad fields")
            return

        if self.name != x2:
            with self.lock:
                st = self.priv_x1_state.get(conn_id)
            if not st:
                self.logger.warning(f"[PRIV/FWD] X1 has no state CONN={conn_id}")
                return
            if st.get("x2") != x2:
                self.logger.warning(f"[PRIV/FWD] X1 state x2 mismatch CONN={conn_id} got={x2} expected={st.get('x2')}")
                return
            if x2 not in self.sessions and not self.ensure_session(x2, reason=f"PRIV forward X1->X2 CONN={conn_id}"):
                self.logger.error(f"[PRIV/FWD] cannot ensure X2={x2}")
                return
            self.link_send(x2, T_PRIV_FWD, plain, meta={"conn_id": conn_id, "mode": "priv"})
            self.logger.info(f"[PRIV/FWD] X1={self.name} forwarded opaque A->X2 bundle to {x2}; DST hidden; CONN={conn_id}")
            return

        with self.lock:
            st = self.priv_x2_state.get(conn_id)
        if not st:
            self.logger.warning(f"[PRIV/FWD] X2 has no state CONN={conn_id}")
            return
        try:
            shared = st["priv"].exchange(xpub_from_bytes(bytes.fromhex(msg["ake"])))
            k_ax2 = hkdf_sha256(shared, salt=conn_id.encode("utf-8"), info=b"priv-a-x2-v1", length=32)
            aad = f"priv-a-x2:{conn_id}:{self.name}".encode("utf-8")
            inner = jload(aesgcm_decrypt(k_ax2, bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), aad=aad))
        except Exception as e:
            self.logger.error(f"[PRIV/FWD] X2 decrypt fail CONN={conn_id}: {e}")
            return

        self._queue_priv_x2_inner(conn_id, inner, log_prefix="[PRIV/FWD]")

    def handle_PRIV_INLINE_START(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
        except Exception as e:
            self.logger.error(f"[PRIV/INLINE_START] bad json from={peer}: {e}")
            return
        conn_id = msg.get("conn_id", "")
        req = msg.get("req", "")
        capsules = msg.get("capsules", {})
        if not conn_id or req not in USERS or not isinstance(capsules, dict):
            self.logger.error(f"[PRIV/INLINE_START] bad fields from={peer} CONN={conn_id}")
            return

        start_selector = False
        with self.lock:
            st = self.priv_x1_state.get(conn_id)
            if not st:
                st = {
                    "req": req,
                    "x2": "",
                    "inline": True,
                    "pending_inline": [],
                    "selecting": True,
                    "created_at": time.time(),
                }
                self.priv_x1_state[conn_id] = st
                start_selector = True
            st.setdefault("pending_inline", []).append(msg)
            x2 = st.get("x2", "")
            if x2:
                pending = list(st.get("pending_inline", []))
                st["pending_inline"] = []
            else:
                pending = []

        self.logger.info(f"[PRIV/INLINE_START] X1={self.name} got first IKE capsule from A={req}; DST hidden; CONN={conn_id}")
        if pending and x2:
            self._flush_priv_inline_to_x2(conn_id, pending, x2)
        if start_selector:
            cand_x2 = [u for u in capsules.keys() if u in USERS and u != self.name]
            threading.Thread(
                target=self._try_route_x2_priv_inline,
                args=(conn_id, req, cand_x2),
                daemon=True,
                name=f"priv-inline-x2-{self.name}-{conn_id}",
            ).start()

    def _try_route_x2_priv_inline(self, conn_id: str, req: str, cand_x2: List[str]):
        cand_x2 = self._ordered_route_candidates(cand_x2, "IKE_DEBUG_FORCE_X2", "X2")

        for x2 in cand_x2:
            self.logger.info(f"[PRIV/INLINE_START] X1={self.name} try X2={x2} for REQ={req}; DST hidden; CONN={conn_id}")
            if not self.ensure_session(x2, reason=f"PRIV INLINE X1->X2 CONN={conn_id} REQ={req}"):
                self.logger.warning(f"[PRIV/INLINE_START] cannot establish session to X2={x2}, trying next")
                self._mark_route_peer_bad(x2, f"cannot ensure session to X2={x2}")
                continue
            with self.lock:
                st = self.priv_x1_state.get(conn_id)
                if not st:
                    return
                st["x2"] = x2
                st["selecting"] = False
                pending = list(st.get("pending_inline", []))
                st["pending_inline"] = []
            self.logger.info(f"[PRIV/INLINE_START] choose X2={x2}; forwarding already captured IKE; REQ/DST hidden from X1 CONN={conn_id}")
            self._flush_priv_inline_to_x2(conn_id, pending, x2)
            return

        with self.lock:
            st = self.priv_x1_state.get(conn_id)
            if st:
                st["selecting"] = False
        self.logger.error(f"[PRIV/INLINE_START] cannot establish session to any X2 candidate CONN={conn_id}")
        self.send_error_back(conn_id, req, self.name, phase="INLINE_X2", code="NO_SESSION_X2", msg="cannot ensure any X2")

    def _flush_priv_inline_to_x2(self, conn_id: str, pending: List[dict], x2: str):
        if x2 not in self.sessions and not self.ensure_session(x2, reason=f"PRIV INLINE flush X1->X2 CONN={conn_id}"):
            self.logger.error(f"[PRIV/INLINE_START] cannot ensure X2={x2} for flush CONN={conn_id}")
            return
        for item in pending:
            capsules = item.get("capsules", {})
            capsule = capsules.get(x2)
            if not capsule:
                self.logger.warning(f"[PRIV/INLINE_START] no capsule for selected X2={x2} CONN={conn_id}")
                continue
            fwd = {"conn_id": conn_id, "x2": x2, "capsule": capsule, "inline": True}
            self.link_send(x2, T_PRIV_INLINE_X2, jdump(fwd), meta={"conn_id": conn_id, "mode": "priv-inline"})
            self.logger.info(f"[PRIV/INLINE_START] X1={self.name} forwarded selected sealed capsule to X2={x2}; DST hidden from X1 CONN={conn_id}")

    def handle_PRIV_INLINE_X2(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
            conn_id = msg.get("conn_id", "")
            x2 = msg.get("x2", "")
            capsule = msg.get("capsule", {})
        except Exception as e:
            self.logger.error(f"[PRIV/INLINE_X2] bad json from={peer}: {e}")
            return
        if not conn_id or not x2 or not capsule:
            self.logger.error(f"[PRIV/INLINE_X2] bad fields from={peer} CONN={conn_id} x2={x2}")
            return

        if self.name != x2:
            with self.lock:
                st = self.priv_x1_state.get(conn_id)
            if not st:
                self.logger.warning(f"[PRIV/INLINE_X2] X1 has no state CONN={conn_id}")
                return
            if st.get("x2") != x2:
                self.logger.warning(f"[PRIV/INLINE_X2] X1 state x2 mismatch CONN={conn_id} got={x2} expected={st.get('x2')}")
                return
            if x2 not in self.sessions and not self.ensure_session(x2, reason=f"PRIV INLINE forward X1->X2 CONN={conn_id}"):
                self.logger.error(f"[PRIV/INLINE_X2] cannot ensure X2={x2}")
                return
            self.link_send(x2, T_PRIV_INLINE_X2, plain, meta={"conn_id": conn_id, "mode": "priv-inline"})
            self.logger.info(f"[PRIV/INLINE_X2] X1={self.name} forwarded selected sealed capsule to X2={x2}; DST hidden from X1 CONN={conn_id}")
            return

        try:
            inner = self._open_seal_for_me(conn_id, capsule)
        except Exception as e:
            self.logger.error(f"[PRIV/INLINE_X2] capsule open fail from={peer} CONN={conn_id}: {e}")
            return
        with self.lock:
            st = self.priv_x2_state.get(conn_id)
            if not st:
                self.priv_x2_state[conn_id] = {
                    "x1": peer,
                    "created_at": time.time(),
                    "inline": True,
                }
            else:
                st["x1"] = st.get("x1") or peer
                st["inline"] = True
        self.logger.info(f"[PRIV/INLINE_X2] X2={self.name} opened selected capsule; B known only now, A locator still absent CONN={conn_id}")
        self._queue_priv_x2_inner(conn_id, inner, log_prefix="[PRIV/INLINE_X2]")

    def _ensure_and_priv_deliver(self, dst: str, deliver: dict, conn_id: str):
        self._send_priv_deliver_to_dst(dst, deliver, conn_id)

    def handle_PRIV_BKEY_REQ(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
            conn_id = msg.get("conn_id", "")
        except Exception as e:
            self.logger.error(f"[PRIV/BKEY_REQ] bad json from={peer}: {e}")
            return
        if not conn_id:
            self.logger.error("[PRIV/BKEY_REQ] missing conn_id")
            return
        resp = self._prepare_priv_bkey_response(conn_id, peer)
        if peer not in self.sessions and not self.ensure_session(peer, reason=f"PRIV BKEY_RESP B->X2 CONN={conn_id}"):
            self.logger.error(f"[PRIV/BKEY_REQ] cannot ensure X2={peer} CONN={conn_id}")
            return
        self.link_send(peer, T_PRIV_BKEY_RESP, jdump(resp), meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/BKEY_REQ] B={self.name}->X2={peer} returned B pubkey; A still unknown here CONN={conn_id}")

    def handle_PRIV_BKEY_RESP(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
            conn_id = msg.get("conn_id", "")
            bke = msg.get("bke", "")
        except Exception as e:
            self.logger.error(f"[PRIV/BKEY_RESP] bad json from={peer}: {e}")
            return
        if not conn_id or not bke:
            self.logger.error("[PRIV/BKEY_RESP] bad fields")
            return

        with self.lock:
            x2_state = self.priv_x2_state.get(conn_id)
            x1_state = self.priv_x1_state.get(conn_id)

        if x2_state and not x1_state:
            self._forward_priv_bkey_resp_as_x2(conn_id, msg)
            return

        if not x1_state:
            self.logger.warning(f"[PRIV/BKEY_RESP] no X1 state on {self.name} CONN={conn_id}")
            return

        req = x1_state.get("req", "")
        x2 = x1_state.get("x2", "")
        if req not in USERS or x2 not in USERS:
            self.logger.warning(f"[PRIV/BKEY_RESP] bad X1 state req={req} x2={x2} CONN={conn_id}")
            return

        try:
            seal = self._seal_x1b_locator(conn_id, bke, req)
        except Exception as e:
            self.logger.error(f"[PRIV/BKEY_RESP] X1 seal failed CONN={conn_id}: {e}")
            return

        if x2 == self.name:
            self.handle_PRIV_X1B_SEAL(self.name, jdump(seal))
            return
        if x2 not in self.sessions and not self.ensure_session(x2, reason=f"PRIV X1B_SEAL X1->X2 CONN={conn_id}"):
            self.logger.error(f"[PRIV/BKEY_RESP] cannot ensure X2={x2} CONN={conn_id}")
            return
        self.link_send(x2, T_PRIV_X1B_SEAL, jdump(seal), meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/X1B] X1={self.name} sealed A={req} locator for hidden B pubkey via X2={x2}; X2 cannot open CONN={conn_id}")

    def handle_PRIV_X1B_SEAL(self, peer: str, plain: bytes):
        try:
            seal = jload(plain)
            conn_id = seal.get("conn_id", "")
        except Exception as e:
            self.logger.error(f"[PRIV/X1B] bad json from={peer}: {e}")
            return
        if not conn_id:
            self.logger.error("[PRIV/X1B] missing conn_id")
            return
        with self.lock:
            st = self.priv_x2_state.get(conn_id)
            if st:
                st["x1b_seal"] = seal
        if not st:
            self.logger.warning(f"[PRIV/X1B] X2={self.name} has no state CONN={conn_id}")
            return
        self.logger.info(f"[PRIV/X1B] X2={self.name} received opaque X1-B seal from {peer}; A locator remains hidden from X2 CONN={conn_id}")
        self._flush_priv_deliveries(conn_id)

    def handle_PRIV_DELIVER(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
            conn_id = msg.get("conn_id", "")
            sealed = msg.get("x1b_seal", {})
            opened = self._open_x1b_locator_for_me(conn_id, sealed)
            payload = bytes.fromhex(msg.get("ike_payload", ""))
        except Exception as e:
            self.logger.error(f"[PRIV/DELIVER] bad/seal fail from={peer}: {e}")
            return

        src = opened.get("src", "")
        if src not in USERS:
            self.logger.error(f"[PRIV/DELIVER] bad endpoint src={src} dst={self.name} on {self.name}")
            return

        route = OverlayRoute(
            conn_id=conn_id,
            src=src,
            dst=self.name,
            x1="",
            x2=peer,
            created_at=time.time(),
            privacy=True,
            ab_pub=msg.get("a_to_b_ke", ""),
            inline=bool(msg.get("inline", False)),
        )
        self._cache_route(route)
        meta = {
            "kind": "ike",
            "privacy": True,
            "inline": bool(msg.get("inline", False)),
            "conn_id": conn_id,
            "src": src,
            "dst": self.name,
            "x1": "",
            "x2": peer,
            "dir": "fwd",
            "idx": 3,
            "phase": "REAL_IKE_PRIV",
            "ike_src_ip": opened.get("ike_src_ip", USERS[src]["ip"]),
            "ike_src_port": int(opened.get("ike_src_port", msg.get("udp_port", 500))),
            "ike_dst_ip": msg.get("ike_dst_ip", USERS[self.name]["ip"]),
            "ike_dst_port": int(msg.get("ike_dst_port", msg.get("udp_port", 500))),
            "udp_port": int(msg.get("udp_port", 500)),
            "ab_pub": msg.get("a_to_b_ke", ""),
        }
        self.logger.info(f"[IKE-OVERLAY/PRIV] ARRIVE B={self.name} from X2={peer}; A locator opened from X1-B seal only at B; CONN={conn_id}")
        self.deliver_ike_to_local_strongswan(payload, meta)

    def handle_PRIV_BACK(self, peer: str, plain: bytes):
        try:
            msg = jload(plain)
        except Exception as e:
            self.logger.error(f"[PRIV/BACK] bad json from={peer}: {e}")
            return
        conn_id = msg.get("conn_id", "")
        sealed_a = msg.get("sealed_a", {})
        if not conn_id or not sealed_a:
            self.logger.error("[PRIV/BACK] bad fields")
            return

        # If this daemon is currently the X2 role, it must forward the reverse
        # bundle to X1 first. This preserves physical paths such as A-X-A-B:
        # B->A(X2)->X1->A(final), instead of opening at A too early.
        with self.lock:
            x2_state = self.priv_x2_state.get(conn_id)
            x1_state = self.priv_x1_state.get(conn_id)
        if x2_state and peer != x2_state.get("x1"):
            nxt = x2_state.get("x1")
            if not nxt or nxt == self.name:
                self.logger.warning(f"[PRIV/BACK] bad X2 reverse next={nxt} on {self.name} CONN={conn_id}")
                return
            if nxt not in self.sessions and not self.ensure_session(nxt, reason=f"PRIV reverse X2->X1 CONN={conn_id}"):
                self.logger.error(f"[PRIV/BACK] cannot ensure X1={nxt}")
                return
            fwd_msg = dict(msg)
            fwd_msg["x2"] = self.name
            fwd_msg["x1"] = nxt
            if x2_state.get("inline"):
                fwd_msg["inline"] = True
            self.link_send(nxt, T_PRIV_BACK, jdump(fwd_msg), meta={"conn_id": conn_id, "mode": "priv"})
            self.logger.info(f"[PRIV/BACK] X2={self.name}->{nxt} forwarded sealed reverse bundle CONN={conn_id}")
            return

        with self.lock:
            has_ab_state = conn_id in self.priv_ab_state
        if (sealed_a.get("mode") == "x25519" and has_ab_state) or sealed_a.get("to") == self.name:
            try:
                opened = self._open_back_for_a(conn_id, sealed_a)
                payload = bytes.fromhex(opened.get("ike_payload", ""))
            except Exception as e:
                self.logger.error(f"[PRIV/BACK] final open fail CONN={conn_id}: {e}")
                return
            meta_x1 = msg.get("x1", "")
            meta_x2 = msg.get("x2", "")
            if x2_state and peer == x2_state.get("x1"):
                # In routes like A-B-A-B the initiator is also X2.  The B->A
                # reverse hop arrives directly from X1, so infer X1/X2 from
                # the local X2 state instead of waiting for a forwarded header.
                meta_x1 = meta_x1 or x2_state.get("x1", "")
                meta_x2 = meta_x2 or self.name
            meta = {
                "kind": "ike",
                "privacy": True,
                "conn_id": conn_id,
                "src": opened.get("src", self.name),
                "dst": opened.get("dst", ""),
                "x1": meta_x1,
                "x2": meta_x2 or peer,
                "dir": "back",
                "idx": 3,
                "phase": "REAL_IKE_PRIV",
                "inline": bool(msg.get("inline", False)),
                "ike_src_ip": opened.get("ike_src_ip", ""),
                "ike_src_port": int(opened.get("ike_src_port", 500)),
                "ike_dst_ip": opened.get("ike_dst_ip", USERS[self.name]["ip"]),
                "ike_dst_port": int(opened.get("ike_dst_port", 500)),
                "udp_port": int(opened.get("udp_port", 500)),
            }
            if meta["inline"] and meta["x1"] and meta["x2"]:
                self.logger.info(
                    f"[IKE-ROUTE/PRIV] READY {meta['src']}->{meta['x1']}->X2({meta['x2']})->DST(hidden until X2/B) CONN={conn_id}"
                )
            self.logger.info(f"[IKE-OVERLAY/PRIV] ARRIVE A={self.name} reverse from {peer}; B opened only at A; CONN={conn_id}")
            self.deliver_ike_to_local_strongswan(payload, meta)
            return

        fwd_plain = plain
        if x2_state and x2_state.get("x1"):
            nxt = x2_state.get("x1")
        elif x1_state and x1_state.get("req"):
            nxt = x1_state.get("req")
            try:
                fwd_msg = dict(msg)
                fwd_msg["x1"] = fwd_msg.get("x1") or self.name
                if x1_state.get("x2"):
                    fwd_msg["x2"] = fwd_msg.get("x2") or x1_state.get("x2")
                if x1_state.get("inline"):
                    fwd_msg["inline"] = True
                fwd_plain = jdump(fwd_msg)
            except Exception:
                fwd_plain = plain
        else:
            self.logger.warning(f"[PRIV/BACK] no reverse state on {self.name} CONN={conn_id}")
            return
        if not nxt or nxt == self.name:
            self.logger.warning(f"[PRIV/BACK] bad next hop={nxt} on {self.name} CONN={conn_id}")
            return
        if nxt not in self.sessions and not self.ensure_session(nxt, reason=f"PRIV reverse CONN={conn_id}"):
            self.logger.error(f"[PRIV/BACK] cannot ensure next={nxt}")
            return
        self.link_send(nxt, T_PRIV_BACK, fwd_plain, meta={"conn_id": conn_id, "mode": "priv"})
        self.logger.info(f"[PRIV/BACK] {self.name}->{nxt} forwarded sealed reverse bundle CONN={conn_id}")

    # =========================
    # Real IKE capture/proxy API
    # =========================

    def start_ike_proxy(self):
        if IkeProxy is None:
            raise RuntimeError("ike_proxy.py is unavailable or failed to import")
        if self.ike_proxy is None:
            self.ike_proxy = IkeProxy(self)
            self.ike_proxy.start()

    def _route_key(self, src: str, dst: str) -> str:
        return f"{src}>{dst}"

    def _is_inline_pending(self, route: OverlayRoute) -> bool:
        return bool(route.privacy and route.inline and not route.x2)

    def _mark_route_peer_bad(self, peer: str, reason: str):
        if not peer or peer == self.name:
            return
        until = time.time() + max(0.0, IKE_ROUTE_COOLDOWN_S)
        with self.lock:
            self.route_cooldowns[peer] = until
            self.route_failure_counts[peer] = self.route_failure_counts.get(peer, 0) + 1
            count = self.route_failure_counts[peer]
        self.logger.warning(
            f"[ROUTE-HEALTH] peer={peer} cooldown={IKE_ROUTE_COOLDOWN_S:.1f}s "
            f"failures={count} reason={reason}"
        )

    def _drop_conn_state_by_id(self, conn_id: str):
        with self.lock:
            st = self.conns.pop(conn_id, None)
            self.priv_ab_state.pop(conn_id, None)
            self.priv_x2_pub.pop(conn_id, None)
            self.okx2_data.pop(conn_id, None)
            self.okx2_x2name.pop(conn_id, None)
            ev = self.okx2_ev.pop(conn_id, None)
        if ev:
            ev.set()
        if st and st.done_event:
            st.done_event.set()

    def _drop_route_state(self, route: OverlayRoute, reason: str, penalize_x1: bool = False):
        self._drop_conn_state_by_id(route.conn_id)
        if penalize_x1:
            self._mark_route_peer_bad(route.x1, reason)

    def _drop_cached_route_by_conn(self, conn_id: str, reason: str, penalize_x1: bool = True) -> bool:
        dropped = None
        with self.ike_route_lock:
            for key, route in list(self.ike_routes.items()):
                if route.conn_id == conn_id:
                    dropped = self.ike_routes.pop(key)
                    break
        if not dropped:
            return False
        self._drop_route_state(dropped, reason, penalize_x1=penalize_x1)
        self.logger.warning(
            f"[IKE-ROUTE] dropped route {dropped.src}->{dropped.x1}->{dropped.x2 or '?'}->{dropped.dst} "
            f"CONN={conn_id} reason={reason}"
        )
        return True

    def _healthy_route_candidates(self, candidates: List[str], role: str) -> List[str]:
        now = time.time()
        with self.lock:
            cooldowns = dict(self.route_cooldowns)
        healthy = [u for u in candidates if cooldowns.get(u, 0.0) <= now]
        if healthy and len(healthy) < len(candidates):
            skipped = [u for u in candidates if u not in healthy]
            self.logger.info(f"[ROUTE-HEALTH] skip cooldown {role} candidates={skipped}")
        return healthy or list(candidates)

    def _choose_route_candidate(self, candidates: List[str], env_name: str, role: str) -> str:
        if not candidates:
            return ""
        forced = os.environ.get(env_name, "").strip()
        healthy = self._healthy_route_candidates(candidates, role)
        if forced in candidates:
            if forced in healthy:
                return forced
            if healthy:
                self.logger.warning(f"[ROUTE-HEALTH] forced {role}={forced} is cooling down; selecting healthy peer")
        pool = list(healthy)
        random.shuffle(pool)
        return pool[0]

    def _ordered_route_candidates(self, candidates: List[str], env_name: str, role: str) -> List[str]:
        unique = list(dict.fromkeys(candidates))
        if not unique:
            return []
        forced = os.environ.get(env_name, "").strip()
        healthy = self._healthy_route_candidates(unique, role)
        ordered: List[str] = []
        if forced in healthy:
            ordered.append(forced)
        elif forced in unique and healthy:
            self.logger.warning(f"[ROUTE-HEALTH] forced {role}={forced} is cooling down; selecting healthy peer")

        pool = [u for u in healthy if u not in ordered]
        random.shuffle(pool)
        ordered.extend(pool)

        if not ordered:
            fallback = [u for u in unique if u not in ordered]
            random.shuffle(fallback)
            ordered.extend(fallback)
        return ordered

    def _cache_route(self, route: OverlayRoute) -> None:
        with self.ike_route_lock:
            self.ike_routes[self._route_key(route.src, route.dst)] = route

    def _get_cached_route(self, src: str, dst: str) -> Optional[OverlayRoute]:
        dropped = None
        drop_reason = ""
        penalize = False
        with self.ike_route_lock:
            key = self._route_key(src, dst)
            route = self.ike_routes.get(key)
            if not route:
                return None
            age = time.time() - route.created_at
            if age > IKE_ROUTE_CACHE_TTL_S:
                self.ike_routes.pop(key, None)
                dropped = route
                drop_reason = f"route TTL expired after {age:.3f}s"
            elif self._is_inline_pending(route) and age > IKE_INLINE_ROUTE_TIMEOUT_S:
                self.ike_routes.pop(key, None)
                dropped = route
                drop_reason = f"inline route not READY after {age:.3f}s"
                penalize = True
            else:
                return route
        if dropped:
            self._drop_route_state(dropped, drop_reason, penalize_x1=penalize)
            self.logger.warning(
                f"[IKE-ROUTE] invalidated {dropped.src}->{dropped.x1}->{dropped.x2 or '?'}->{dropped.dst} "
                f"CONN={dropped.conn_id} reason={drop_reason}"
            )
        return None

    def _ike_response_flag(self, payload: bytes) -> bool:
        # IKEv2 over UDP/4500 starts with a 4-byte Non-ESP marker.
        offset = 4 if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00" else 0
        if len(payload) < offset + 20:
            return False
        flags = payload[offset + 19]
        return bool(flags & 0x20)

    def _start_privacy_inline_route(self, dst: str) -> OverlayRoute:
        cached = self._get_cached_route(self.name, dst)
        if cached:
            return cached
        if dst not in USERS:
            raise RuntimeError(f"unknown IKE dst user {dst}")
        if dst == self.name:
            raise RuntimeError("cannot build inline privacy overlay route to self")

        cand_x1 = [u for u in ACTIVE_USERS if u != self.name]
        if not cand_x1:
            raise RuntimeError("no X1 candidates for inline privacy route")
        tried = set()
        last_error = ""
        for _ in range(max(RETRIES, 1)):
            remaining = [u for u in cand_x1 if u not in tried] or cand_x1
            x1 = self._choose_route_candidate(remaining, "IKE_DEBUG_FORCE_X1", "X1")
            if not x1:
                break
            tried.add(x1)
            conn_id = secrets.token_hex(8)
            self.logger.info(
                f"[IKE-ROUTE/PRIV-INLINE] start {self.name}->DST(hidden from X1) via X1={x1}; "
                f"first IKE will drive X2/B setup CONN={conn_id}"
            )
            if not self.ensure_session(x1, reason=f"privacy inline A->X1 CONN={conn_id}"):
                last_error = f"cannot ensure session to X1={x1}"
                self._mark_route_peer_bad(x1, last_error)
                continue
            route = OverlayRoute(
                conn_id=conn_id,
                src=self.name,
                dst=dst,
                x1=x1,
                x2="",
                created_at=time.time(),
                privacy=True,
                inline=True,
            )
            self._cache_route(route)
            self._ensure_priv_ab_pub(conn_id, dst)
            return route
        raise RuntimeError(f"cannot build inline privacy route {self.name}->{dst}: {last_error or 'no viable X1'}")

    def _build_privacy_overlay_route(self, dst: str) -> OverlayRoute:
        cached = self._get_cached_route(self.name, dst)
        if cached:
            return cached
        if dst not in USERS:
            raise RuntimeError(f"unknown IKE dst user {dst}")
        if dst == self.name:
            raise RuntimeError("cannot build privacy overlay route to self")

        cand_x1 = [u for u in ACTIVE_USERS if u != self.name]
        if not cand_x1:
            raise RuntimeError("no X1 candidates for privacy overlay route")
        ordered_x1 = self._ordered_route_candidates(cand_x1, "IKE_DEBUG_FORCE_X1", "X1")
        last_error = None
        for attempt, x1 in enumerate(ordered_x1[:max(RETRIES, 1)], start=1):
            conn_id = secrets.token_hex(8)
            ok_ev = threading.Event()
            done_ev = threading.Event()
            st = ConnState(
                conn_id=conn_id,
                src=self.name,
                dst=dst,
                x1=x1,
                x2="",
                ike_init_len=0,
                ike_auth_len=0,
                retries_left=0,
                okx2_event=ok_ev,
                done_event=done_ev,
            )
            with self.lock:
                self.conns[conn_id] = st
                self.okx2_ev[conn_id] = ok_ev
                self.okx2_data.pop(conn_id, None)
                self.okx2_x2name.pop(conn_id, None)
                self.priv_x2_pub.pop(conn_id, None)

            self.logger.info(f"[IKE-ROUTE/PRIV] build attempt={attempt} {self.name}->DST(hidden from X1) via X1={x1} CONN={conn_id}")
            if not self.ensure_session(x1, reason=f"privacy IKE A->X1 CONN={conn_id}"):
                last_error = f"cannot ensure session to X1={x1}"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            i1 = f"CONN={conn_id}|REQ={self.name}|MODE=PRIV".encode().ljust(128, b"\x00")
            self.link_send(x1, T_I1, i1)

            deadline = time.monotonic() + IKE_ROUTE_TIMEOUT_S
            while time.monotonic() < deadline:
                if ok_ev.wait(0.1):
                    break
                if done_ev.is_set():
                    break

            if done_ev.is_set():
                last_error = str(st.last_error)
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue
            if not ok_ev.is_set():
                last_error = "timeout waiting OKX2/PRIV"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            with self.lock:
                x2 = self.okx2_x2name.get(conn_id, "")
                x2_pub = self.priv_x2_pub.get(conn_id, "")
            if not x2 or not x2_pub:
                last_error = "OKX2/PRIV without X2 pub"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            route = OverlayRoute(
                conn_id=conn_id,
                src=self.name,
                dst=dst,
                x1=x1,
                x2=x2,
                created_at=time.time(),
                privacy=True,
                x2_pub=x2_pub,
            )
            self._cache_route(route)
            self.logger.info(f"[IKE-ROUTE/PRIV] READY {route.src}->{route.x1}->X2({route.x2})->DST(hidden until X2/B) CONN={route.conn_id}")
            return route

        raise RuntimeError(f"cannot build privacy overlay route {self.name}->{dst}: {last_error}")

    def _build_overlay_route(self, dst: str) -> OverlayRoute:
        """Build A->X1->X2->B route and wait until OKX2 is received."""
        if IKE_PRIVACY_OVERLAY:
            return self._build_privacy_overlay_route(dst)

        cached = self._get_cached_route(self.name, dst)
        if cached:
            return cached

        if dst not in USERS:
            raise RuntimeError(f"unknown IKE dst user {dst}")
        if dst == self.name:
            raise RuntimeError("cannot build overlay route to self")

        # Serialize route construction for real IKE, otherwise two captured IKE datagrams
        # may start two different overlay routes for the same peer.
        with self.ike_route_lock:
            cached = self.ike_routes.get(self._route_key(self.name, dst))
            if cached:
                return cached

        # Dissertation mode: X1 can be the final destination (B).
        # The sender only excludes itself.
        cand_x1 = [u for u in ACTIVE_USERS if u != self.name]
        if not cand_x1:
            raise RuntimeError("no X1 candidates for real-IKE overlay route")
        ordered_x1 = self._ordered_route_candidates(cand_x1, "IKE_DEBUG_FORCE_X1", "X1")
        last_error = None
        for attempt, x1 in enumerate(ordered_x1[:max(RETRIES, 1)], start=1):
            conn_id = secrets.token_hex(8)
            ok_ev = threading.Event()
            done_ev = threading.Event()
            st = ConnState(
                conn_id=conn_id,
                src=self.name,
                dst=dst,
                x1=x1,
                x2="",
                ike_init_len=0,
                ike_auth_len=0,
                retries_left=0,
                okx2_event=ok_ev,
                done_event=done_ev,
            )
            with self.lock:
                self.conns[conn_id] = st
                self.okx2_ev[conn_id] = ok_ev
                self.okx2_data.pop(conn_id, None)
                self.okx2_x2name.pop(conn_id, None)

            self.logger.info(f"[IKE-ROUTE] build attempt={attempt} {self.name}->{dst} via X1={x1} CONN={conn_id}")
            if not self.ensure_session(x1, reason=f"real IKE A->X1 CONN={conn_id}"):
                last_error = f"cannot ensure session to X1={x1}"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            i1 = f"CONN={conn_id}|REQ={self.name}|DST={dst}".encode().ljust(128, b"\x00")
            self.link_send(x1, T_I1, i1)

            deadline = time.monotonic() + IKE_ROUTE_TIMEOUT_S
            while time.monotonic() < deadline:
                if ok_ev.wait(0.1):
                    break
                if done_ev.is_set():
                    break

            if done_ev.is_set():
                last_error = str(st.last_error)
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue
            if not ok_ev.is_set():
                last_error = "timeout waiting OKX2"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            with self.lock:
                x2 = self.okx2_x2name.get(conn_id, "")
            if not x2:
                last_error = "OKX2 without X2 name"
                self._mark_route_peer_bad(x1, last_error)
                self._drop_conn_state_by_id(conn_id)
                continue

            route = OverlayRoute(
                conn_id=conn_id,
                src=self.name,
                dst=dst,
                x1=x1,
                x2=x2,
                created_at=time.time(),
            )
            self._cache_route(route)
            self.logger.info(f"[IKE-ROUTE] READY {route.src}->{route.x1}->{route.x2}->{route.dst} CONN={route.conn_id}")
            return route

        raise RuntimeError(f"cannot build overlay route {self.name}->{dst}: {last_error}")

    def send_ike_datagram(self, dst_user: str, ike_src_ip: str, ike_src_port: int,
                          ike_dst_ip: str, ike_dst_port: int, payload: bytes, udp_port: int):
        """Called by IkeProxy when local strongSwan emits a real IKE UDP datagram."""
        # Prefer reverse use of an already established route A->B when this node is B
        # and the captured packet is B->A.
        route = self._get_cached_route(dst_user, self.name) if self._ike_response_flag(payload) else None
        if route and route.dst == self.name:
            direction = "back"
            logical_route = [route.dst, route.x2, route.x1, route.src]
            idx = 1
        else:
            route = self._get_cached_route(self.name, dst_user)
            if not route:
                if IKE_PRIVACY_OVERLAY and IKE_PRIVACY_INLINE:
                    route = self._start_privacy_inline_route(dst_user)
                else:
                    route = self._build_overlay_route(dst_user)
            direction = "fwd"
            logical_route = [route.src, route.x1, route.x2, route.dst]
            idx = 1

        ike_src_port, ike_dst_port = self._canonical_ike_ports(ike_src_port, ike_dst_port, udp_port)
        if route.privacy:
            if direction == "fwd":
                if route.inline:
                    self._send_priv_inline_ike_fwd(route, payload, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, udp_port)
                else:
                    self._send_priv_ike_fwd(route, payload, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, udp_port)
            else:
                self._send_priv_ike_back(route, payload, ike_src_ip, ike_src_port, ike_dst_ip, ike_dst_port, udp_port)
            return

        # If a logical next hop is this same daemon because roles repeat
        # (for example back path B->B->X->A when X2==B), skip the local hop
        # and send to the first external neighbor.  The skipped role remains
        # in route metadata, so logs and analysis still show the full route.
        while idx < len(logical_route) and logical_route[idx] == self.name:
            idx += 1
        if idx >= len(logical_route):
            raise RuntimeError(
                f"cannot find external first-hop for {direction} route "
                f"{route.src}->{route.x1}->{route.x2}->{route.dst}"
            )
        first_hop = logical_route[idx]

        # Ensure the first hop session exists. It normally does after route construction,
        # but reverse packets on the responder side may need X2 on-demand.
        if first_hop not in self.sessions and not self.ensure_session(first_hop, reason=f"real IKE first-hop {direction}"):
            raise RuntimeError(f"cannot ensure first-hop session to {first_hop}")

        meta = {
            "kind": "ike",
            "conn_id": route.conn_id,
            "src": route.src,
            "dst": route.dst,
            "x1": route.x1,
            "x2": route.x2,
            "idx": idx,
            "dir": direction,
            "phase": "REAL_IKE",
            "ike_src_ip": ike_src_ip,
            "ike_src_port": int(ike_src_port),
            "ike_dst_ip": ike_dst_ip,
            "ike_dst_port": int(ike_dst_port),
            "udp_port": int(udp_port),
        }
        self.link_send(first_hop, T_PROXY_BLOB, payload, meta=meta)
        self.logger.info(
            f"[IKE-OVERLAY] SEND {direction} len={len(payload)} "
            f"{ike_src_ip}:{ike_src_port}->{ike_dst_ip}:{ike_dst_port} "
            f"route={route.src}->{route.x1}->{route.x2}->{route.dst} first={first_hop} CONN={route.conn_id}"
        )

    def deliver_ike_to_local_strongswan(self, payload: bytes, meta: dict):
        """Terminal overlay delivery: inject raw IKE UDP payload into local charon."""
        try:
            route = OverlayRoute(
                conn_id=meta.get("conn_id", ""),
                src=meta.get("src", ""),
                dst=meta.get("dst", ""),
                x1=meta.get("x1", ""),
                x2=meta.get("x2", ""),
                created_at=time.time(),
                privacy=bool(meta.get("privacy", False)),
                ab_pub=meta.get("ab_pub", ""),
                inline=bool(meta.get("inline", False)),
            )
            if route.src and route.dst and ((route.x1 and route.x2) or (route.privacy and route.x2)):
                existing = self._get_cached_route(route.src, route.dst) if route.privacy else None
                # Do not let final reverse delivery on A overwrite the richer
                # initiator route (it has X1 and X2 pub needed for later IKE_AUTH).
                if not (route.privacy and not route.x1 and existing and existing.x1):
                    if route.privacy and not route.ab_pub and existing and existing.ab_pub:
                        route.ab_pub = existing.ab_pub
                    self._cache_route(route)
        except Exception:
            self.logger.exception("[IKE-OVERLAY] failed to cache route from terminal delivery")

        if not self.ike_proxy:
            self.logger.error("[IKE-OVERLAY] IKE proxy is not enabled; cannot inject to strongSwan")
            return
        self.ike_proxy.inject_to_charon(payload, meta)

    # =========================
    # Plaintext ERROR forward
    # =========================

    def send_error_back(self, conn_id: str, src_u: str, x1_u: str, phase: str, code: str, msg: str):
        back_route = [self.name, x1_u, src_u] if self.name != x1_u else [self.name, src_u]
        if len(back_route) < 2:
            return
        nxt = back_route[1]
        payload = err(code, msg, meta={
            "conn_id": conn_id,
            "src": src_u,
            "x1": x1_u,
            "phase": phase,
            "idx": 1,
            "route": back_route
        })
        self.send_peer(nxt, payload)

    def on_error(self, p: dict, peer: Optional[str]):
        code = p.get("code", "ERR")
        msg = p.get("msg", "")
        meta = p.get("meta") or {}
        conn_id = meta.get("conn_id", "")
        self.logger.error(f"[ERROR] code={code} msg='{msg}' from={peer} CONN={conn_id}")

        if code == "SESSION_RESET" and peer:
            bad_sid = str(meta.get("bad_sid", ""))
            with self.lock:
                sess = self.sessions.get(peer)
                if sess and (not bad_sid or sess.sid == bad_sid):
                    self.sessions.pop(peer, None)
                    self.logger.warning(f"[MGMT] dropped stale session to {peer} sid={sess.sid}")
                elif not sess:
                    self.logger.warning(f"[MGMT] session reset from {peer}, no local session present")
                else:
                    self.logger.warning(
                        f"[MGMT] ignored stale reset from {peer}: bad_sid={bad_sid}, current sid={sess.sid}"
                    )
            return

        route = meta.get("route", [])
        idx = int(meta.get("idx", 0))
        if isinstance(route, list) and route and idx < len(route) - 1:
            nxt = route[idx + 1]
            meta2 = dict(meta); meta2["idx"] = idx + 1
            fwd = {"t": T_ERROR, "code": code, "msg": msg, "meta": meta2}
            self.send_peer(nxt, jdump(fwd))
            return

        if conn_id and self._drop_cached_route_by_conn(conn_id, f"overlay error {code}: {msg}", penalize_x1=True):
            return

        if conn_id and conn_id in self.conns:
            st = self.conns[conn_id]
            st.last_error = {"code": code, "msg": msg}
            st.done_event.set()

    # =========================
    # LOCAL_CONNECT + Initiator
    # =========================

    def on_local_connect(self, p: dict, src: Tuple[str, int]):
        if src[0] not in ("127.0.0.1", "::1"):
            self.logger.warning("[LOCAL] reject non-local")
            return

        user = p.get("user")
        password = p.get("pass")
        dst = p.get("dst")
        ike_init_len = int(p.get("ike_init_len", 499))
        ike_auth_len = int(p.get("ike_auth_len", 499))
        retries = int(p.get("retries", 5))

        self.logger.info(
            f"[LOCAL] connect request from={src[0]} user={user} dst={dst} "
            f"ike_init_len={ike_init_len} ike_auth_len={ike_auth_len} retries={retries}"
        )

        if user != self.name:
            self.sock.sendto(err("BAD_SRC", "LOCAL_CONNECT user must equal daemon name"), src)
            return
        if user not in USERS or USERS[user]["password"] != password:
            self.sock.sendto(err("AUTH_FAIL", "bad user/password"), src)
            return
        if dst not in USERS:
            self.sock.sendto(err("BAD_DST", "unknown dst"), src)
            return

        # Dissertation mode: A excludes only itself; X1 may be B.
        cand_x1 = [u for u in ACTIVE_USERS if u != user]
        if not cand_x1:
            self.sock.sendto(err("NO_X1_CAND", "no X1 candidates"), src)
            return
        x1 = random.choice(cand_x1)

        conn_id = secrets.token_hex(8)

        ok_ev = threading.Event()
        done_ev = threading.Event()
        with self.lock:
            self.okx2_ev[conn_id] = ok_ev
            self.okx2_data.pop(conn_id, None)
            self.okx2_x2name.pop(conn_id, None)

        st = ConnState(
            conn_id=conn_id,
            src=user, dst=dst,
            x1=x1, x2="",
            ike_init_len=ike_init_len,
            ike_auth_len=ike_auth_len,
            retries_left=retries,
            okx2_event=ok_ev,
            done_event=done_ev,
        )
        self.conns[conn_id] = st

        th = threading.Thread(target=self.run_connection, args=(st,), daemon=True)
        th.start()

        self.sock.sendto(jdump({"ok": True, "conn_id": conn_id, "x1": x1, "msg": "started"}), src)
        self.logger.info(f"[ROLE] A={user} selected X1={x1} for DST={dst} CONN={conn_id}")

    def run_connection(self, st: ConnState):
        while st.retries_left >= 0:
            st.done_event.clear()
            st.okx2_event.clear()
            st.last_error = None

            # Ensure A<->X1
            if st.x1 not in self.sessions and not self.ensure_session(st.x1, reason=f"A->X1 CONN={st.conn_id}"):
                self.logger.error(f"[CONN {st.conn_id}] cannot establish to X1={st.x1}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            i1 = f"CONN={st.conn_id}|REQ={st.src}|DST={st.dst}".encode().ljust(128, b"\x00")
            self.link_send(st.x1, T_I1, i1)
            self.logger.info(f"[CONN {st.conn_id}] I1 sent to X1={st.x1} (X1 picks X2)")

            # Wait OKX2 or ERROR
            okx2_timeout = UDP_TIMEOUT_S * 6
            deadline = time.monotonic() + okx2_timeout
            while time.monotonic() < deadline:
                if st.okx2_event.wait(0.1):
                    break
                if st.done_event.is_set():
                    self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                    st.retries_left -= 1
                    st.x1 = self._pick_new_x1(st.src, st.dst)
                    break

            if st.done_event.is_set():
                continue

            if not st.okx2_event.is_set():
                self.logger.error(f"[CONN {st.conn_id}] timeout waiting OKX2")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            with self.lock:
                ok = self.okx2_data.get(st.conn_id)
                x2 = self.okx2_x2name.get(st.conn_id, "")

            if not ok or not x2:
                self.logger.error(f"[CONN {st.conn_id}] OKX2 missing data")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            st.x2 = x2
            self.logger.info(f"[CONN {st.conn_id}] got OKX2, chosen X2={st.x2}, ok_len={len(ok)}")

            init_payload = self.make_container(st.dst, ike_len=st.ike_init_len)
            auth_payload = self.make_container(st.dst, ike_len=st.ike_auth_len)

            meta_base = {"conn_id": st.conn_id, "src": st.src, "dst": st.dst, "x1": st.x1, "x2": st.x2}
            meta_init = dict(meta_base); meta_init.update({"idx": 1, "dir": "fwd", "phase": "IKE_SA_INIT"})
            meta_auth = dict(meta_base); meta_auth.update({"idx": 1, "dir": "fwd", "phase": "IKE_AUTH"})

            try:
                self.link_send(st.x1, T_PROXY_BLOB, init_payload, meta=meta_init)
                self.link_send(st.x1, T_PROXY_BLOB, auth_payload, meta=meta_auth)
            except Exception as e:
                self.logger.error(f"[CONN {st.conn_id}] send proxy fail: {e}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            # if an ERROR arrives, done_event is set
            if st.done_event.wait(UDP_TIMEOUT_S * 8):
                self.logger.warning(f"[CONN {st.conn_id}] FAIL {st.last_error}, retry_left={st.retries_left}")
                st.retries_left -= 1
                st.x1 = self._pick_new_x1(st.src, st.dst)
                continue

            self.logger.info(f"[CONN {st.conn_id}] SUCCESS: proxied INIT/AUTH; далее прямой ESP (вне overlay)")
            return

        self.logger.error(f"[CONN {st.conn_id}] give up (retries exhausted)")

    def _pick_new_x1(self, src: str, dst: str) -> str:
        cand = [u for u in ACTIVE_USERS if u != src]
        return random.choice(cand) if cand else src

    def make_container(self, dst_user: str, ike_len: int) -> bytes:
        return secrets.token_bytes(4) + secrets.token_bytes(2) + secrets.token_bytes(I3_LEN) + secrets.token_bytes(ike_len)

    # =========================
    # X1 route selection
    # =========================

    def _try_route_x2(self, conn_id: str, req: str, dst: str, cand_x2: List[str]):
        cand_x2 = self._ordered_route_candidates(cand_x2, "IKE_DEBUG_FORCE_X2", "X2")
        for x2 in cand_x2:
            self.logger.info(f"[I1] X1={self.name} try X2={x2} for REQ={req} DST={dst} CONN={conn_id}")

            if not self.ensure_session(x2, reason=f"X1->X2 CONN={conn_id} REQ={req} DST={dst}"):
                self.logger.warning(f"[I1] cannot establish session to X2={x2}, trying next")
                self._mark_route_peer_bad(x2, f"cannot ensure session to X2={x2}")
                continue

            i2 = f"CONN={conn_id}|REQ={req}|DST={dst}|X2={x2}".encode().ljust(128, b"\x00")
            self.link_send(x2, T_I2, i2)
            self.logger.info(f"[I1] choose X2={x2}; -> I2 to {x2} for REQ={req}, DST={dst} CONN={conn_id}")
            return

        self.logger.error("[I1] cannot establish session to any X2 candidate")
        self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_SESSION_X2", msg="cannot ensure any X2")

    def _try_route_x2_priv(self, conn_id: str, req: str, cand_x2: List[str]):
        cand_x2 = self._ordered_route_candidates(cand_x2, "IKE_DEBUG_FORCE_X2", "X2")
        for x2 in cand_x2:
            self.logger.info(f"[I1/PRIV] X1={self.name} try X2={x2} for REQ={req}; DST hidden; CONN={conn_id}")

            if not self.ensure_session(x2, reason=f"PRIV X1->X2 CONN={conn_id} REQ={req}"):
                self.logger.warning(f"[I1/PRIV] cannot establish session to X2={x2}, trying next")
                self._mark_route_peer_bad(x2, f"cannot ensure session to X2={x2}")
                continue

            with self.lock:
                self.priv_x1_state[conn_id] = {
                    "req": req,
                    "x2": x2,
                    "created_at": time.time(),
                }

            i2 = f"CONN={conn_id}|MODE=PRIV|X2={x2}".encode().ljust(128, b"\x00")
            self.link_send(x2, T_I2, i2)
            self.logger.info(f"[I1/PRIV] choose X2={x2}; -> I2 to {x2}; REQ/DST hidden from X2; CONN={conn_id}")
            return

        self.logger.error("[I1/PRIV] cannot establish session to any X2 candidate")
        self.send_error_back(conn_id, req, self.name, phase="OKX2", code="NO_SESSION_X2", msg="cannot ensure any X2")

    # =========================
    # Loop
    # =========================

    def serve_forever(self):
        self.logger.info(f"Daemon started as {self.name} on UDP/{USERS[self.name]['port']}")
        if IKE_PROXY_ENABLED and self.ike_proxy is None:
            self.start_ike_proxy()
        if PRECONNECT_ENABLED and self.preconnect_thread is None:
            self.preconnect_thread = threading.Thread(target=self._preconnect_loop, daemon=True)
            self.preconnect_thread.start()

        while self.running:
            got = self.recv_one()
            if not got:
                continue
            data, src = got
            self.handle_packet(data, src)

    def stop(self):
        self.running = False
        if self.ike_proxy:
            try:
                self.ike_proxy.stop()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _preconnect_loop(self):
        time.sleep(random.uniform(0.2, 0.8))
        while self.running:
            peers = [u for u in ACTIVE_USERS if u != self.name]
            random.shuffle(peers)
            for peer in peers:
                with self.lock:
                    has_session = peer in self.sessions or peer in self.ensure_inflight
                    cooling_down = self.route_cooldowns.get(peer, 0.0) > time.time()
                if has_session:
                    continue
                if cooling_down:
                    continue
                if not self.ensure_session(peer, reason="preconnect"):
                    self._mark_route_peer_bad(peer, "preconnect ensure_session failed")
                time.sleep(0.05)
            time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, choices=list(USERS.keys()))
    ap.add_argument("--ike-proxy", action="store_true", help="capture real strongSwan IKE UDP packets and move them through overlay")
    ap.add_argument("--ike-default-dst", choices=list(USERS.keys()), default="",
                    help="fallback peer user for local nft/iptables REDIRECT when original destination is seen as 127.0.0.1")
    args = ap.parse_args()

    if args.ike_default_dst:
        os.environ["IKE_PROXY_DEFAULT_DST_USER"] = args.ike_default_dst

    d = NodeDaemon(args.name)
    if args.ike_proxy:
        d.start_ike_proxy()
    try:
        d.serve_forever()
    except KeyboardInterrupt:
        d.stop()


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""
ike_proxy.py

Linux UDP IKE capture/inject adapter for the hybrid overlay prototype.

What it does:
- receives real UDP/500 and UDP/4500 IKE datagrams redirected by iptables/nftables
  to local high ports;
- passes the raw UDP payload to NodeDaemon.send_ike_datagram(...), which transports
  it through the encrypted overlay;
- injects received overlay IKE datagrams into the local strongSwan/charon UDP socket
  while preserving the apparent remote source IP/port by using IP_TRANSPARENT.

This module intentionally does NOT transport ESP. ESP must be installed by strongSwan
as CHILD_SA/XFRM state and then flow directly between the endpoints.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, TYPE_CHECKING

from config import (
    USERS,
    IKE_CAPTURE_BIND,
    IKE_CAPTURE_PORTS,
    IKE_CAPTURE_USER_PORTS,
    IKE_CHARON_HOST,
    IKE_CHARON_PORTS,
    IKE_PROXY_DEFAULT_DST_USER,
    IKE_SOCKET_MARK,
    IKE_TRANSPARENT_INJECT_REQUIRED,
)

if TYPE_CHECKING:  # pragma: no cover
    from node_daemon import NodeDaemon

# Linux constants that are not exposed by Python on all distributions.
SOL_IP = getattr(socket, "SOL_IP", socket.IPPROTO_IP)
IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)
IP_FREEBIND = getattr(socket, "IP_FREEBIND", 15)
IP_RECVORIGDSTADDR = getattr(socket, "IP_RECVORIGDSTADDR", 20)
SO_MARK = getattr(socket, "SO_MARK", 36)


@dataclass(frozen=True)
class CapturedIkePacket:
    payload: bytes
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    udp_port: int
    dst_user_hint: Optional[str] = None


def _capture_specs():
    specs = []
    seen_ports = set()
    for ike_port, capture_port in sorted(IKE_CAPTURE_PORTS.items()):
        port = int(capture_port)
        if port not in seen_ports:
            specs.append((int(ike_port), port, None))
            seen_ports.add(port)
    for ike_port, user_ports in sorted(IKE_CAPTURE_USER_PORTS.items()):
        for user, capture_port in sorted(user_ports.items()):
            port = int(capture_port)
            if port not in seen_ports:
                specs.append((int(ike_port), port, str(user)))
                seen_ports.add(port)
    return specs


def _all_capture_ports():
    return {capture_port for _ike_port, capture_port, _user in _capture_specs()}


def _reverse_capture_ports():
    return {capture_port: ike_port for ike_port, capture_port, _user in _capture_specs()}


def is_ike_payload(udp_port: int, payload: bytes) -> bool:
    """Return True for IKE payloads.

    UDP/500 is IKE. UDP/4500 can carry either IKE with the 4-byte Non-ESP Marker
    or ESP-in-UDP with a non-zero SPI. We only move IKE through the overlay.
    """
    if udp_port == 500:
        return True
    if udp_port == 4500:
        return len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00"
    return False


class IkeProxy:
    def __init__(self, daemon: "NodeDaemon"):
        self.daemon = daemon
        self.logger = daemon.logger
        self.running = False
        self.threads = []
        self.sockets = []
        self.capture_sockets: Dict[Tuple[int, Optional[str]], socket.socket] = {}

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        specs = _capture_specs()
        for ike_port, capture_port, dst_user_hint in specs:
            t = threading.Thread(
                target=self._capture_loop,
                args=(int(ike_port), int(capture_port), dst_user_hint),
                daemon=True,
                name=f"ike-capture-{ike_port}-{dst_user_hint or capture_port}",
            )
            t.start()
            self.threads.append(t)
        default_dst_user = (
            os.environ.get("IKE_PROXY_DEFAULT_DST_USER", "").strip()
            or str(IKE_PROXY_DEFAULT_DST_USER or "").strip()
        )
        self.logger.info(
            f"[IKE-PROXY] started capture specs={specs} "
            f"charon={IKE_CHARON_HOST}:{IKE_CHARON_PORTS} mark={hex(IKE_SOCKET_MARK)} "
            f"default_dst_user={default_dst_user or '-'}"
        )

    def stop(self) -> None:
        self.running = False
        for s in list(self.sockets):
            try:
                s.close()
            except OSError:
                pass

    def _make_capture_socket(self, capture_port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Needed when packets are redirected transparently and we want original dst.
        try:
            s.setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
        except OSError as e:
            self.logger.warning(f"[IKE-PROXY] IP_RECVORIGDSTADDR unavailable: {e}")
        s.bind((IKE_CAPTURE_BIND, capture_port))
        s.settimeout(0.5)
        self.sockets.append(s)
        return s

    def _capture_loop(self, ike_port: int, capture_port: int, dst_user_hint: Optional[str]) -> None:
        sock = self._make_capture_socket(capture_port)
        self.capture_sockets[(int(ike_port), dst_user_hint)] = sock
        hint = f" dst_user_hint={dst_user_hint}" if dst_user_hint else ""
        self.logger.info(f"[IKE-PROXY] listening {IKE_CAPTURE_BIND}:{capture_port} for UDP/{ike_port}{hint}")
        while self.running:
            try:
                pkt = self._recv_captured(sock, ike_port, dst_user_hint)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    self.logger.exception("[IKE-PROXY] capture socket failed")
                return
            except Exception:
                self.logger.exception("[IKE-PROXY] capture error")
                continue

            if not pkt:
                continue

            if not is_ike_payload(pkt.udp_port, pkt.payload):
                # ESP-in-UDP must not be redirected here. If it is, rules are wrong.
                self.logger.warning(
                    f"[IKE-PROXY] DROP non-IKE UDP/{pkt.udp_port} len={len(pkt.payload)} "
                    f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}. "
                    "Fix firewall rules so ESP/NAT-T bypasses the proxy."
                )
                continue

            dst_user = self.daemon.user_by_ip(pkt.dst_ip)
            if not dst_user and pkt.dst_user_hint:
                if pkt.dst_user_hint not in USERS:
                    self.logger.error(
                        f"[IKE-PROXY] invalid dst_user_hint={pkt.dst_user_hint!r}; "
                        f"known users={list(USERS.keys())}"
                    )
                    continue
                dst_user = pkt.dst_user_hint
                self.logger.info(
                    f"[IKE-PROXY] using port hint dst_user={dst_user} "
                    f"for capture_port={pkt.dst_port} captured dst_ip={pkt.dst_ip}"
                )

            # nft/iptables REDIRECT on local OUTPUT often makes the proxy see the
            # destination as 127.0.0.1 instead of the real peer address.  In a
            # two-endpoint lab the intended peer is unambiguous, so allow an
            # environment/config fallback.  This is intentionally read at packet
            # time, not only at import time, so `export IKE_PROXY_DEFAULT_DST_USER=...`
            # and the CLI wrapper in node_daemon.py both work reliably.
            default_dst_user = (
                os.environ.get("IKE_PROXY_DEFAULT_DST_USER", "").strip()
                or str(IKE_PROXY_DEFAULT_DST_USER or "").strip()
            )
            if not dst_user and default_dst_user:
                if default_dst_user not in USERS:
                    self.logger.error(
                        f"[IKE-PROXY] invalid IKE_PROXY_DEFAULT_DST_USER={default_dst_user!r}; "
                        f"known users={list(USERS.keys())}"
                    )
                    continue
                dst_user = default_dst_user
                self.logger.info(
                    f"[IKE-PROXY] using fallback dst_user={dst_user} for captured dst_ip={pkt.dst_ip}"
                )

            if not dst_user:
                self.logger.error(
                    f"[IKE-PROXY] cannot map dst_ip={pkt.dst_ip} to USERS; "
                    "set IKE_PROXY_DEFAULT_DST_USER or run node_daemon.py with --ike-default-dst <User>"
                )
                continue
            if dst_user == self.daemon.name:
                self.logger.debug(
                    f"[IKE-PROXY] captured local-to-local packet ignored "
                    f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}"
                )
                continue

            src_ip = pkt.src_ip
            if src_ip.startswith("127.") or src_ip == "0.0.0.0":
                # With some REDIRECT setups recvmsg reports loopback as source.
                # For remote charon injection we need the underlay identity of this node.
                src_ip = USERS[self.daemon.name]["ip"]

            # nft REDIRECT may expose a transient local port in recvmsg().
            # For strongSwan/IKE semantics we must preserve the canonical IKE source port,
            # otherwise the peer learns a bogus NAT-T port and ESP-in-UDP is sent to it.
            src_port = int(pkt.src_port)
            if int(pkt.udp_port) in (500, 4500):
                if str(pkt.dst_ip).startswith("127.") or int(pkt.dst_port) in _all_capture_ports():
                    src_port = int(pkt.udp_port)
                elif src_ip == USERS[self.daemon.name]["ip"] and src_port not in (500, 4500):
                    src_port = int(pkt.udp_port)

            self.logger.info(
                f"[IKE-PROXY] CAPTURE UDP/{pkt.udp_port} len={len(pkt.payload)} "
                f"{src_ip}:{src_port}->{pkt.dst_ip}:{pkt.dst_port} dst_user={dst_user}"
            )
            try:
                self.daemon.send_ike_datagram(
                    dst_user=dst_user,
                    ike_src_ip=src_ip,
                    ike_src_port=int(pkt.udp_port),
                    ike_dst_ip=pkt.dst_ip,
                    ike_dst_port=pkt.dst_port,
                    payload=pkt.payload,
                    udp_port=pkt.udp_port,
                )
            except Exception:
                self.logger.exception("[IKE-PROXY] failed to send captured IKE through overlay")

    def _recv_captured(
        self,
        sock: socket.socket,
        default_ike_port: int,
        dst_user_hint: Optional[str],
    ) -> Optional[CapturedIkePacket]:
        data, ancdata, _flags, addr = sock.recvmsg(65535, 1024)
        src_ip, src_port = addr[0], int(addr[1])
        orig_dst: Optional[Tuple[str, int]] = None
        for level, ctype, cdata in ancdata:
            if level == SOL_IP and ctype == IP_RECVORIGDSTADDR and len(cdata) >= 8:
                # struct sockaddr_in: family(2), port(2, network order), addr(4)
                port = struct.unpack_from("!H", cdata, 2)[0]
                ip = socket.inet_ntoa(cdata[4:8])
                orig_dst = (ip, int(port))
                break
        if orig_dst is None:
            # Fallback only keeps the IKE port. Destination IP is intentionally unknown;
            # dst-user mapping then uses IKE_PROXY_DEFAULT_DST_USER for simple two-node labs.
            orig_dst = ("0.0.0.0", default_ike_port)
        return CapturedIkePacket(
            payload=data,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=orig_dst[0],
            dst_port=orig_dst[1],
            udp_port=default_ike_port,
            dst_user_hint=dst_user_hint,
        )

    @staticmethod
    def _ip_checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
            total = (total & 0xffff) + (total >> 16)
        return (~total) & 0xffff

    def _raw_inject_ipv4_udp(self, payload: bytes, remote_ip: str, remote_port: int, local_port: int) -> None:
        local_ip = USERS[self.daemon.name]["ip"]

        src_b = socket.inet_aton(remote_ip)
        dst_b = socket.inet_aton(local_ip)

        udp_len = 8 + len(payload)
        ip_len = 20 + udp_len

        ip_header0 = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,                       # IPv4, IHL=5
            0,                          # TOS
            ip_len,
            os.getpid() & 0xffff,        # IP ID
            0,                          # flags/fragment offset
            64,                         # TTL
            socket.IPPROTO_UDP,
            0,                          # checksum placeholder
            src_b,
            dst_b,
        )
        ip_sum = self._ip_checksum(ip_header0)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_len,
            os.getpid() & 0xffff,
            0,
            64,
            socket.IPPROTO_UDP,
            ip_sum,
            src_b,
            dst_b,
        )

        # UDP checksum 0 is valid for IPv4 and avoids pseudo-header complexity.
        udp_header = struct.pack("!HHHH", int(remote_port), int(local_port), udp_len, 0)
        packet = ip_header + udp_header + payload

        rs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            try:
                rs.setsockopt(socket.SOL_SOCKET, SO_MARK, int(IKE_SOCKET_MARK))
            except OSError as e:
                self.logger.warning(f"[IKE-PROXY] raw socket cannot set SO_MARK={hex(IKE_SOCKET_MARK)}: {e}")

            try:
                rs.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except OSError:
                pass

            rs.sendto(packet, (local_ip, int(local_port)))
            self.logger.info(
                f"[IKE-PROXY] RAW-INJECT len={len(payload)} "
                f"as {remote_ip}:{remote_port} -> local {local_ip}:{local_port}"
            )
        finally:
            try:
                rs.close()
            except OSError:
                pass

    def _sidecar_udp_inject(self, payload: bytes, remote_ip: str, remote_port: int, local_port: int) -> None:
        """Send IKE to an off-host endpoint through a router NAT helper.

        The sidecar is not the IPsec endpoint. It sends from the per-peer capture
        port, then the adjacent router rewrites the source to remote_ip:remote_port
        before forwarding to the real endpoint. The router's conntrack sends the
        endpoint reply back to the same capture socket, where normal overlay
        handling picks it up.
        """
        local_ip = USERS[self.daemon.name]["ip"]
        remote_user = self.daemon.user_by_ip(remote_ip)
        if not remote_user:
            self.logger.error(f"[IKE-PROXY] sidecar cannot map remote_ip={remote_ip} to USERS")
            return

        capture_port = int(IKE_CAPTURE_USER_PORTS.get(int(local_port), {}).get(remote_user, 0))
        if not capture_port:
            self.logger.error(
                f"[IKE-PROXY] sidecar has no capture port for UDP/{local_port} remote_user={remote_user}"
            )
            return

        sock = self.capture_sockets.get((int(local_port), remote_user))
        if sock is None:
            self.logger.error(
                f"[IKE-PROXY] sidecar capture socket missing for UDP/{local_port} remote_user={remote_user}"
            )
            return

        sock.sendto(payload, (local_ip, int(local_port)))
        self.logger.info(
            f"[IKE-PROXY] SIDECAR-INJECT len={len(payload)} "
            f"from capture :{capture_port} via router-nat as {remote_ip}:{remote_port} "
            f"-> endpoint {local_ip}:{local_port}"
        )

    def inject_to_charon(self, payload: bytes, meta: Dict[str, object]) -> None:
        """Inject an overlay-delivered IKE UDP payload into local strongSwan/charon.

        This version avoids binding a UDP socket to remote_ip:500 because local charon
        usually already owns 0.0.0.0:500. Instead it crafts a raw IPv4/UDP packet
        with the preserved peer source and the local node IP as destination.
        """
        remote_ip = str(meta["ike_src_ip"])
        remote_port = int(meta["ike_src_port"])

        # IMPORTANT: with nft REDIRECT, ike_dst_port may be 15000/15001.
        # The real IKE port is stored separately as udp_port.
        local_ike_port = int(meta.get("udp_port") or meta.get("ike_dst_port") or 500)

        # Extra safety if an old meta record carried capture ports instead of IKE ports.
        local_ike_port = _reverse_capture_ports().get(local_ike_port, local_ike_port)

        if local_ike_port == 4500 and not is_ike_payload(4500, payload):
            self.logger.warning("[IKE-PROXY] refusing to inject non-IKE UDP/4500 payload")
            return

        if USERS[self.daemon.name].get("sidecar_inject"):
            self._sidecar_udp_inject(
                payload=payload,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=local_ike_port,
            )
            return

        self._raw_inject_ipv4_udp(
            payload=payload,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_ike_port,
        )

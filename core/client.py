# -*- coding: utf-8 -*-

import argparse
import socket
from config import USERS, UDP_TIMEOUT_S
from protocol import jdump, jload, T_LOCAL_CONNECT, T_ERROR

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--me", required=True, choices=list(USERS.keys()))
    ap.add_argument("--pass", required=True, dest="password")
    ap.add_argument("--dst", required=True, choices=list(USERS.keys()))
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--ike-len", type=int, default=499)
    args = ap.parse_args()

    # client sends LOCAL_CONNECT to localhost daemon
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT_S)

    port = USERS[args.me]["port"]
    req = {
        "t": T_LOCAL_CONNECT,
        "user": args.me,
        "pass": args.password,
        "dst": args.dst,
        "retries": args.retries,
        "ike_init_len": args.ike_len,
        "ike_auth_len": args.ike_len,
    }

    sock.sendto(jdump(req), ("127.0.0.1", port))
    resp, _ = sock.recvfrom(65535)
    r = jload(resp)

    if r.get("t") == T_ERROR:
        print("ERROR:", r.get("code"), r.get("msg"))
    else:
        print("OK:", r)

if __name__ == "__main__":
    main()
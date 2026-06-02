# -*- coding: utf-8 -*-

import json
from typing import Any, Dict

PROTOCOL_VERSION = 1

def jdump(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def jload(b: bytes) -> Dict[str, Any]:
    return json.loads(b.decode("utf-8"))

# mgmt handshake (4-step)
T_MGMT_INIT      = "MGMT_INIT"
T_MGMT_INIT_RESP = "MGMT_INIT_RESP"
T_MGMT_AUTH      = "MGMT_AUTH"
T_MGMT_AUTH_RESP = "MGMT_AUTH_RESP"

# instruction flow
T_I1   = "I1"       # A->X1 (Enc_KD_AX1)
T_I2   = "I2"       # X1->X2 (Enc_KD_X1X2)
T_OKX2 = "OKX2"     # X2->X1 (Enc_KD_X1X2) then X1->A (Enc_KD_AX1)

# proxy
T_PROXY_BLOB = "PROXY_BLOB"

# privacy-preserving/on-demand proxy path
T_PRIV_FWD = "PRIV_FWD"              # A->X1->X2, X1 sees only X2 and opaque X2 bundle
T_PRIV_DELIVER = "PRIV_DELIVER"      # X2->B, B receives IKE + sealed initiator locator
T_PRIV_BACK = "PRIV_BACK"            # B->X2->X1->A, reverse IKE over stored local hop state
T_PRIV_BKEY_REQ = "PRIV_BKEY_REQ"    # X2->B asks B for an ephemeral key for X1-B locator seal
T_PRIV_BKEY_RESP = "PRIV_BKEY_RESP"  # B->X2->X1 carries B public key without exposing A locator
T_PRIV_X1B_SEAL = "PRIV_X1B_SEAL"    # X1->X2 carries A locator encrypted for B
T_PRIV_INLINE_START = "PRIV_INLINE_START"  # A->X1 carries first IKE packet before X2 is ready
T_PRIV_INLINE_X2 = "PRIV_INLINE_X2"        # X1->X2 forwards the selected sealed A->X2 capsule

# local control
T_LOCAL_CONNECT = "LOCAL_CONNECT"

# error (plaintext)
T_ERROR = "ERROR"

def err(code: str, msg: str, meta: dict = None) -> bytes:
    return jdump({"v": PROTOCOL_VERSION, "t": T_ERROR, "code": code, "msg": msg, "meta": meta or {}})

# -*- coding: utf-8 -*-

import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aesgcm_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(key32)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, aad)  # includes tag
    return nonce, ct


def aesgcm_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aes = AESGCM(key32)
    return aes.decrypt(nonce, ciphertext, aad)


def xpub_bytes(pub: x25519.X25519PublicKey) -> bytes:
    if hasattr(pub, "public_bytes_raw"):
        return pub.public_bytes_raw()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def xpub_from_bytes(b: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b)


@dataclass
class HandshakeState:
    priv: x25519.X25519PrivateKey
    pub: bytes
    nonce16: bytes

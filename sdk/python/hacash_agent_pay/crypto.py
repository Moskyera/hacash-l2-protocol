"""Hacash L1-compatible keys (private keys never leave the agent)."""

from __future__ import annotations

import hashlib

import base58
from ecdsa import SECP256k1, SigningKey, VerifyingKey, util


def _sha2(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def _hex(b: bytes) -> str:
    return b.hex()


def _unhex(s: str) -> bytes:
    s = s[2:] if s.startswith(("0x", "0X")) else s
    return bytes.fromhex(s)


class HacashKey:
    """Same algorithms as fullnode Account / hub hacash_keys."""

    def __init__(self, private_key_32: bytes):
        if len(private_key_32) != 32:
            raise ValueError("private key must be 32 bytes")
        if private_key_32[:4] == b"\xff\xff\xff\xff":
            raise ValueError("secret_key not supported; try a different one")
        self._sk = SigningKey.from_string(private_key_32, curve=SECP256k1)
        # compressed pubkey 33 bytes
        self.public_key: bytes = self._sk.get_verifying_key().to_string("compressed")
        self.address: str = address_from_pubkey(self.public_key)

    @classmethod
    def from_password(cls, password: str) -> "HacashKey":
        return cls(_sha2(password.encode("utf-8")))

    @classmethod
    def from_private_key_hex(cls, hex_key: str) -> "HacashKey":
        raw = _unhex(hex_key)
        if len(raw) != 32:
            raise ValueError("private key hex must be 32 bytes")
        return cls(raw)

    def sign_hash_hex(self, hash_hex: str) -> str:
        """Sign 32-byte hash → 97-byte Sign hex (pubkey || sig r||s)."""
        msg = _unhex(hash_hex)
        if len(msg) != 32:
            raise ValueError("hash must be 32 bytes")
        # Match libsecp256k1/noble: RFC6979 with HMAC-SHA256 and canonical low-S.
        sig64 = self._sk.sign_digest_deterministic(
            msg,
            hashfunc=hashlib.sha256,
            sigencode=util.sigencode_string_canonize,
        )
        if len(sig64) != 64:
            raise RuntimeError("unexpected signature length")
        return _hex(self.public_key + sig64)

    @staticmethod
    def verify_sign_hex(hash_hex: str, sign_hex: str, expected_address: str) -> bool:
        try:
            msg = _unhex(hash_hex)
            raw = _unhex(sign_hex)
            if len(raw) != 97 or len(msg) != 32:
                return False
            pk = raw[:33]
            sig = raw[33:]
            if address_from_pubkey(pk) != expected_address:
                return False
            vk = VerifyingKey.from_string(pk, curve=SECP256k1)
            return vk.verify_digest(sig, msg, sigdecode=util.sigdecode_string)
        except Exception:
            return False


def address_from_pubkey(pubkey: bytes) -> str:
    body = _ripemd160(_sha2(pubkey))
    payload = bytes([0]) + body
    return base58.b58encode_check(payload).decode("ascii")

def _intent_field(name: str, value: str) -> str:
    return f"{name}_len={len(value.encode('utf-8'))}\n{name}={value}\n"


def build_agent_intent_message(
    *,
    provider_id: str,
    agent_id: str,
    from_addr: str,
    to: str,
    amount_hac: str,
    idempotency_key: str,
    nonce: str,
    expires_unix: int,
    amount_satoshi: int = 0,
    fee_hac: str = "0",
    route: tuple[str, ...] = (),
    invoice_id: str = "",
) -> str:
    """Build the exact domain-separated message expected by the hub."""
    values = {
        "provider_id": provider_id,
        "agent_id": agent_id,
        "from": from_addr,
        "to": to,
        "amount_hac": amount_hac,
        "fee_hac": fee_hac,
        "invoice_id": invoice_id,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
    }
    for name, value in values.items():
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"{name} contains control characters")
    if not 16 <= len(nonce) <= 128:
        raise ValueError("intent nonce must be 16..=128 characters")
    out = "HACASH_AGENT_PAY_INTENT_V1\n"
    for name in ("provider_id", "agent_id", "from", "to", "amount_hac"):
        out += _intent_field(name, values[name])
    out += f"amount_satoshi={amount_satoshi}\n"
    out += _intent_field("fee_hac", fee_hac)
    out += f"route_count={len(route)}\n"
    for index, channel_id in enumerate(route):
        out += _intent_field(f"route_{index}", channel_id)
    for name in ("invoice_id", "idempotency_key", "nonce"):
        out += _intent_field(name, values[name])
    out += f"expires_unix={expires_unix}\n"
    return out


def sign_agent_intent(key: HacashKey, **params) -> dict:
    message = build_agent_intent_message(**params)
    digest = hashlib.sha3_256(message.encode("utf-8")).hexdigest()
    return {
        "nonce": params["nonce"],
        "expires_unix": params["expires_unix"],
        "signature_hex": key.sign_hash_hex(digest),
    }

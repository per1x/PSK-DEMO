"""参与方模块：包含充电桩、中心服务器等实体逻辑。"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from ecdsa import BadSignatureError, NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

from pkg.pkg_module import PKG


CURVE = NIST256p
CURVE_ORDER = CURVE.order
GENERATOR = CURVE.generator


@dataclass
class HandshakeMessage:
    """终端在协商阶段互发的报文，包含身份、公钥材料与签名。"""

    identity: str
    static_public: bytes
    ephemeral_public: bytes
    partial_public: bytes
    signature: bytes

    def to_json(self) -> str:
        # 握手报文统一转成 JSON + Base64，便于通过网络直接传输。
        payload = {
            "identity": self.identity,
            "static_public": base64.b64encode(self.static_public).decode("ascii"),
            "ephemeral_public": base64.b64encode(self.ephemeral_public).decode("ascii"),
            "partial_public": base64.b64encode(self.partial_public).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def from_json(data: str) -> "HandshakeMessage":
        payload = json.loads(data)
        return HandshakeMessage(
            identity=payload["identity"],
            static_public=base64.b64decode(payload["static_public"]),
            ephemeral_public=base64.b64decode(payload["ephemeral_public"]),
            partial_public=base64.b64decode(payload["partial_public"]),
            signature=base64.b64decode(payload["signature"]),
        )


class Participant:
    """充电桩/中心服务器的公共逻辑。"""

    def __init__(self, identity: str, pkg: PKG) -> None:
        self.identity = identity
        self.pkg = pkg

        # 部分私钥来自 PKG，用于体现“无证书”体系里的中心授权。
        self.partial_private = _bytes_to_scalar(pkg.issue_partial_key(identity))
        self.partial_public = _scalar_public_bytes(self.partial_private)

        # 静态私钥由终端本地生成，与部分私钥相加得到完整私钥。
        self._static_private = _random_scalar()
        self.static_public = _scalar_public_bytes(self._static_private)

        self.full_private = _scalar_add(self._static_private, self.partial_private)
        self.full_public = _point_add_bytes(self.static_public, self.partial_public)

        # 瞬时私钥只用于当前会话，提供前向安全性。
        self._ephemeral_private = _random_scalar()
        self._ephemeral_public = _scalar_public_bytes(self._ephemeral_private)
        self.session_key: bytes | None = None

    def build_handshake(self) -> HandshakeMessage:
        # 对握手转录做签名，让对端能校验静态身份与本次瞬时参数未被篡改。
        transcript = self._handshake_transcript(
            self.identity,
            self.static_public,
            self._ephemeral_public,
            self.partial_public,
        )
        signature = _sign_digest(self.full_private, transcript)
        return HandshakeMessage(
            identity=self.identity,
            static_public=self.static_public,
            ephemeral_public=self._ephemeral_public,
            partial_public=self.partial_public,
            signature=signature,
        )

    def derive_session_key(self, peer: HandshakeMessage) -> bytes:
        peer_full_public = _point_add_bytes(peer.static_public, peer.partial_public)
        transcript = self._handshake_transcript(
            peer.identity,
            peer.static_public,
            peer.ephemeral_public,
            peer.partial_public,
        )
        if not _verify_digest(peer_full_public, transcript, peer.signature):
            raise ValueError(f"Signature verification failed for {peer.identity}")

        # 同时混入静态公钥与瞬时公钥贡献，避免退化成单一共享量。
        peer_combined_public = _point_add_bytes(peer.ephemeral_public, peer_full_public)
        local_combined_scalar = _scalar_add(self._ephemeral_private, self.full_private)
        shared_points = [
            _point_multiply_bytes(self._ephemeral_private, peer.ephemeral_public),
            _point_multiply_bytes(self.full_private, peer_full_public),
            _point_multiply_bytes(local_combined_scalar, peer_combined_public),
        ]
        identities = sorted([self.identity.encode("utf-8"), peer.identity.encode("utf-8")])
        kdf_input = (
            b"certless-ecdsa-psk|"
            + identities[0]
            + b"|"
            + identities[1]
            + b"|"
            + self.pkg.master_public
            + b"|"
            + b"".join(shared_points)
        )
        # 用 SHAKE-256 从对称输入中扩展出固定长度的 TLS PSK。
        self.session_key = hashlib.shake_256(kdf_input).digest(32)
        return self.session_key

    def _handshake_transcript(
        self,
        identity: str,
        static_public: bytes,
        ephemeral_public: bytes,
        partial_public: bytes,
    ) -> bytes:
        return hashlib.sha256(
            identity.encode("utf-8")
            + static_public
            + ephemeral_public
            + partial_public
            + self.pkg.master_public
        ).digest()


class ChargingPile(Participant):
    """充电桩客户端角色。"""


class CentralServer(Participant):
    """中心服务器角色。"""


def _mod_scalar(value: int) -> int:
    reduced = value % CURVE_ORDER
    return reduced or 1


def _scalar_add(left: int, right: int) -> int:
    return _mod_scalar(left + right)


def _random_scalar() -> int:
    return _mod_scalar(int.from_bytes(os.urandom(32), "big"))


def _bytes_to_scalar(raw: bytes) -> int:
    return _mod_scalar(int.from_bytes(raw, "big"))


def _point_from_bytes(raw: bytes):
    return VerifyingKey.from_string(raw, curve=CURVE).pubkey.point


def _point_to_bytes(point) -> bytes:
    return VerifyingKey.from_public_point(point, curve=CURVE).to_string("uncompressed")


def _scalar_public_bytes(scalar: int) -> bytes:
    return _point_to_bytes(GENERATOR * _mod_scalar(scalar))


def _point_add_bytes(left: bytes, right: bytes) -> bytes:
    return _point_to_bytes(_point_from_bytes(left) + _point_from_bytes(right))


def _point_multiply_bytes(scalar: int, public_bytes: bytes) -> bytes:
    return _point_to_bytes(_point_from_bytes(public_bytes) * _mod_scalar(scalar))


def _sign_digest(private_scalar: int, digest: bytes) -> bytes:
    """使用完整私钥对握手摘要做确定性签名。"""
    signer = SigningKey.from_secret_exponent(_mod_scalar(private_scalar), curve=CURVE)
    return signer.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=sigencode_string)


def _verify_digest(public_bytes: bytes, digest: bytes, signature: bytes) -> bool:
    """使用对端完整公钥校验握手签名。"""
    verifier = VerifyingKey.from_string(public_bytes, curve=CURVE)
    try:
        return verifier.verify_digest(signature, digest, sigdecode=sigdecode_string)
    except BadSignatureError:
        return False

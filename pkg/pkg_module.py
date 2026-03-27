"""PKG 模块：负责主密钥和部分密钥的生成。"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, hmac
from ecdsa import NIST256p, VerifyingKey


CURVE = NIST256p
CURVE_ORDER = CURVE.order
GENERATOR = CURVE.generator


def sha256_digest(data: bytes) -> bytes:
    """计算 SHA-256，供其他模块复用。"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _mod_scalar(value: int) -> int:
    reduced = value % CURVE_ORDER
    return reduced or 1


def _point_to_bytes(point) -> bytes:
    return VerifyingKey.from_public_point(point, curve=CURVE).to_string("uncompressed")


class PKG:
    """私钥生成中心：为每个身份派发部分私钥。"""

    def __init__(self, name: str = "StateGrid PKG") -> None:
        self.name = name
        # 主密钥只在 PKG 内部保存，对外仅暴露主公钥给业务方校验绑定关系。
        self.master_secret = _mod_scalar(int.from_bytes(os.urandom(32), "big"))
        self.master_public = _point_to_bytes(GENERATOR * self.master_secret)

    def issue_partial_key(self, identity: str) -> bytes:
        """基于主密钥和身份派生部分私钥标量。"""
        # 这里用 HMAC 绑定身份，模拟真实系统里 PKG 对实体身份的授权发放过程。
        signer = hmac.HMAC(self.master_secret.to_bytes(32, "big"), hashes.SHA256())
        signer.update(identity.encode("utf-8"))
        partial_scalar = _mod_scalar(int.from_bytes(signer.finalize(), "big"))
        return partial_scalar.to_bytes(32, "big")

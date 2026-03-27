"""OpenSSL TLS-PSK 传输模块：通过 ctypes 直接调用本机 OpenSSL。"""
from __future__ import annotations

import ctypes
import ctypes.util
import socket
from typing import Final


TLS1_2_VERSION: Final[int] = 0x0303
SSL_CTRL_SET_MIN_PROTO_VERSION: Final[int] = 123
SSL_CTRL_SET_MAX_PROTO_VERSION: Final[int] = 124
SSL_ERROR_SSL: Final[int] = 1
SSL_ERROR_WANT_READ: Final[int] = 2
SSL_ERROR_WANT_WRITE: Final[int] = 3
DEFAULT_PSK_CIPHER: Final[str] = "PSK-AES128-GCM-SHA256"


libssl = ctypes.CDLL(ctypes.util.find_library("ssl"))
libcrypto = ctypes.CDLL(ctypes.util.find_library("crypto"))


PSK_CLIENT_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_uint,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char),
    ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_uint,
)
PSK_SERVER_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_uint,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_uint,
)


libssl.TLS_client_method.restype = ctypes.c_void_p
libssl.TLS_server_method.restype = ctypes.c_void_p
libssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
libssl.SSL_CTX_new.restype = ctypes.c_void_p
libssl.SSL_CTX_free.argtypes = [ctypes.c_void_p]
libssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
libssl.SSL_CTX_ctrl.restype = ctypes.c_long
libssl.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libssl.SSL_CTX_set_cipher_list.restype = ctypes.c_int
libssl.SSL_CTX_set_psk_client_callback.argtypes = [ctypes.c_void_p, PSK_CLIENT_CALLBACK]
libssl.SSL_CTX_set_psk_server_callback.argtypes = [ctypes.c_void_p, PSK_SERVER_CALLBACK]
libssl.SSL_new.argtypes = [ctypes.c_void_p]
libssl.SSL_new.restype = ctypes.c_void_p
libssl.SSL_free.argtypes = [ctypes.c_void_p]
libssl.SSL_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
libssl.SSL_set_fd.restype = ctypes.c_int
libssl.SSL_connect.argtypes = [ctypes.c_void_p]
libssl.SSL_connect.restype = ctypes.c_int
libssl.SSL_accept.argtypes = [ctypes.c_void_p]
libssl.SSL_accept.restype = ctypes.c_int
libssl.SSL_get_error.argtypes = [ctypes.c_void_p, ctypes.c_int]
libssl.SSL_get_error.restype = ctypes.c_int
libssl.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
libssl.SSL_write.restype = ctypes.c_int
libssl.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
libssl.SSL_read.restype = ctypes.c_int
libssl.SSL_shutdown.argtypes = [ctypes.c_void_p]
libssl.SSL_shutdown.restype = ctypes.c_int
libcrypto.ERR_get_error.restype = ctypes.c_ulong
libcrypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]


class TLSPskConnection:
    """基于 OpenSSL TLS-PSK 的阻塞式连接封装。"""

    def __init__(
        self,
        sock: socket.socket,
        *,
        server_side: bool,
        psk_identity: str,
        psk: bytes,
        expected_identity: str | None = None,
        cipher: str = DEFAULT_PSK_CIPHER,
    ) -> None:
        self.sock = sock
        self.server_side = server_side
        self.psk_identity = psk_identity.encode("utf-8")
        self.expected_identity = expected_identity.encode("utf-8") if expected_identity else None
        self.psk = psk
        method = libssl.TLS_server_method() if server_side else libssl.TLS_client_method()
        self.ctx = libssl.SSL_CTX_new(method)
        if not self.ctx:
            raise RuntimeError("SSL_CTX_new failed")

        self._client_cb = None
        self._server_cb = None
        self._identity_buffer = ctypes.create_string_buffer(self.psk_identity + b"\x00")

        # PSK 套件主要在 TLS 1.2 下使用，这里直接固定协议版本与密码套件。
        self._set_tls12_only()
        self._set_cipher_list(cipher)
        self._install_psk_callback()

        self.ssl = libssl.SSL_new(self.ctx)
        if not self.ssl:
            self.close()
            raise RuntimeError("SSL_new failed")
        if libssl.SSL_set_fd(self.ssl, sock.fileno()) != 1:
            self.close()
            raise RuntimeError("SSL_set_fd failed")

    def handshake(self) -> None:
        """执行 TLS 握手；客户端和服务端分别走 connect/accept。"""
        result = libssl.SSL_accept(self.ssl) if self.server_side else libssl.SSL_connect(self.ssl)
        if result != 1:
            self._raise_ssl_error(result, "TLS PSK handshake failed")

    def sendall(self, data: bytes) -> None:
        """模仿 socket.sendall，直到完整写入 TLS record 流。"""
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            chunk = (ctypes.c_ubyte * (len(view) - sent)).from_buffer_copy(view[sent:])
            written = libssl.SSL_write(self.ssl, chunk, len(view) - sent)
            if written <= 0:
                self._raise_ssl_error(written, "SSL_write failed")
            sent += written

    def recv_exact(self, num_bytes: int) -> bytes:
        """阻塞读取固定长度的 TLS 明文数据。"""
        chunks = bytearray()
        while len(chunks) < num_bytes:
            to_read = num_bytes - len(chunks)
            buf = ctypes.create_string_buffer(to_read)
            received = libssl.SSL_read(self.ssl, buf, to_read)
            if received <= 0:
                self._raise_ssl_error(received, "SSL_read failed")
            chunks.extend(buf.raw[:received])
        return bytes(chunks)

    def close(self) -> None:
        """释放 OpenSSL 连接与上下文，避免泄露本地句柄。"""
        if getattr(self, "ssl", None):
            try:
                libssl.SSL_shutdown(self.ssl)
            finally:
                libssl.SSL_free(self.ssl)
                self.ssl = None
        if getattr(self, "ctx", None):
            libssl.SSL_CTX_free(self.ctx)
            self.ctx = None

    def _set_tls12_only(self) -> None:
        for ctrl in (SSL_CTRL_SET_MIN_PROTO_VERSION, SSL_CTRL_SET_MAX_PROTO_VERSION):
            if libssl.SSL_CTX_ctrl(self.ctx, ctrl, TLS1_2_VERSION, None) != 1:
                raise RuntimeError("Failed to pin TLS 1.2 for PSK mode")

    def _set_cipher_list(self, cipher: str) -> None:
        if libssl.SSL_CTX_set_cipher_list(self.ctx, cipher.encode("ascii")) != 1:
            raise RuntimeError(f"Failed to set cipher list: {cipher}")

    def _install_psk_callback(self) -> None:
        if self.server_side:
            @PSK_SERVER_CALLBACK
            def server_cb(_ssl: int, identity: bytes | None, psk_buf: ctypes.Array, max_len: int) -> int:
                # 服务端在回调里校验客户端身份，并把协商好的 PSK 交给 OpenSSL。
                if identity is None:
                    return 0
                if self.expected_identity and identity != self.expected_identity:
                    return 0
                if len(self.psk) > max_len:
                    return 0
                ctypes.memmove(psk_buf, self.psk, len(self.psk))
                return len(self.psk)

            self._server_cb = server_cb
            libssl.SSL_CTX_set_psk_server_callback(self.ctx, self._server_cb)
            return

        @PSK_CLIENT_CALLBACK
        def client_cb(
            _ssl: int,
            _hint: bytes | None,
            identity_buf: ctypes.Array,
            max_identity_len: int,
            psk_buf: ctypes.Array,
            max_psk_len: int,
        ) -> int:
            # 客户端在回调里同时提供 identity 和 PSK，供 OpenSSL 发起握手。
            if len(self.psk_identity) + 1 > max_identity_len or len(self.psk) > max_psk_len:
                return 0
            ctypes.memmove(identity_buf, self._identity_buffer, len(self.psk_identity) + 1)
            ctypes.memmove(psk_buf, self.psk, len(self.psk))
            return len(self.psk)

        self._client_cb = client_cb
        libssl.SSL_CTX_set_psk_client_callback(self.ctx, self._client_cb)

    def _raise_ssl_error(self, result: int, prefix: str) -> None:
        error = libssl.SSL_get_error(self.ssl, result)
        if error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            raise RuntimeError(f"{prefix}: unexpected non-blocking state {error}")
        openssl_error = self._consume_openssl_error()
        raise RuntimeError(f"{prefix}: ssl_error={error}, openssl={openssl_error}")

    @staticmethod
    def _consume_openssl_error() -> str:
        err = libcrypto.ERR_get_error()
        if err == 0:
            return "none"
        buf = ctypes.create_string_buffer(256)
        libcrypto.ERR_error_string_n(err, buf, len(buf))
        return buf.value.decode("utf-8", errors="replace")

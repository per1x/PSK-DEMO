"""中心服务器侧逻辑：负责握手校验、TLS-PSK 建联与业务响应。"""
from __future__ import annotations

import socket
import threading

from business.participants import CentralServer, HandshakeMessage
from pkg.pkg_module import PKG
from utils.protocol_utils import HOST, PORT, recv_frame, recv_tls_frame, send_frame, send_tls_frame
from utils.tls_psk_module import TLSPskConnection


def run_server(pkg: PKG, ready: threading.Event) -> None:
    """启动中心服务器，等待充电桩连接并处理一次完整请求。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(1)
        ready.set()

        conn, addr = listener.accept()
        with conn:
            print(f"[Server] Connection from {addr}")
            central = CentralServer("central-server", pkg)

            # 第一阶段：明文交换无证书握手报文，仅用于协商出 TLS 的 PSK。
            pile_handshake = HandshakeMessage.from_json(recv_frame(conn).decode("utf-8"))
            server_handshake = central.build_handshake()
            send_frame(conn, server_handshake.to_json().encode("utf-8"))

            server_psk = central.derive_session_key(pile_handshake)
            print(f"[Server] Derived TLS PSK: {server_psk.hex()}")

            # 第二阶段：将同一条 TCP 连接升级成 TLS-PSK，后续业务只走 TLS。
            tls_conn = TLSPskConnection(
                conn,
                server_side=True,
                psk_identity=central.identity,
                expected_identity=pile_handshake.identity,
                psk=server_psk,
            )
            try:
                tls_conn.handshake()
                request_text = recv_tls_frame(tls_conn).decode("utf-8")
                print("[Server] Decrypted HTTP request via TLS:")
                print(request_text)

                body = (
                    '{"status":"accepted","sessionKey":"'
                    + server_psk.hex()
                    + '","nextAction":"Begin charging within 120s"}'
                )
                http_response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                    + body
                )
                send_tls_frame(tls_conn, http_response.encode("utf-8"))
                print("[Server] HTTPS response sent over TLS-PSK.")
            finally:
                tls_conn.close()

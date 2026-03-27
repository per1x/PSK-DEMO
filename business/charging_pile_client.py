"""充电桩侧逻辑：负责发起握手、升级 TLS-PSK 并发送业务请求。"""
from __future__ import annotations

import socket

from business.participants import ChargingPile, HandshakeMessage
from pkg.pkg_module import PKG
from utils.protocol_utils import HOST, PORT, recv_frame, recv_tls_frame, send_frame, send_tls_frame
from utils.tls_psk_module import TLSPskConnection


def run_client(pkg: PKG) -> None:
    """启动充电桩客户端，完成一次握手和业务请求。"""
    pile = ChargingPile("charger-001", pkg)
    with socket.create_connection((HOST, PORT)) as sock:
        # 第一阶段：先通过明文帧交换无证书握手数据。
        pile_handshake = pile.build_handshake()
        send_frame(sock, pile_handshake.to_json().encode("utf-8"))

        server_handshake = HandshakeMessage.from_json(recv_frame(sock).decode("utf-8"))
        pile_psk = pile.derive_session_key(server_handshake)
        print(f"[Pile] Derived TLS PSK: {pile_psk.hex()}")

        # 第二阶段：使用协商出的 PSK 将连接提升为 TLS，并发送 HTTP 业务报文。
        tls_conn = TLSPskConnection(
            sock,
            server_side=False,
            psk_identity=pile.identity,
            expected_identity=server_handshake.identity,
            psk=pile_psk,
        )
        try:
            tls_conn.handshake()
            body = '{"pileId":"charger-001","vehicleId":"EV-8848","kWh":35}'
            http_request = (
                "POST /start-charging HTTP/1.1\r\n"
                "Host: central.server\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                + body
            )
            send_tls_frame(tls_conn, http_request.encode("utf-8"))
            print("[Pile] HTTPS request transmitted over TLS-PSK.")

            response_text = recv_tls_frame(tls_conn).decode("utf-8")
            print("[Pile] Decrypted HTTPS response via TLS:")
            print(response_text)
        finally:
            tls_conn.close()

"""协议辅助模块：封装握手帧与 TLS 业务帧的收发。"""
from __future__ import annotations

import socket
import struct

from utils.tls_psk_module import TLSPskConnection


HOST = "127.0.0.1"
PORT = 9443


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """发送明文长度前缀帧，用于 TLS 建联前的无证书握手。"""
    data = struct.pack("!I", len(payload)) + payload
    sent = 0
    while sent < len(data):
        written = sock.send(data[sent:])
        if written == 0:
            raise ConnectionError("Connection closed while sending handshake frame")
        sent += written


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """阻塞读取指定字节数；若对端提前断开则直接报错。"""
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    """读取单个明文长度前缀帧。"""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    return recv_exact(sock, length)


def send_tls_frame(conn: TLSPskConnection, payload: bytes) -> None:
    """在 TLS 通道内继续复用长度前缀帧，方便示例代码处理业务消息。"""
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_tls_frame(conn: TLSPskConnection) -> bytes:
    """读取 TLS 通道内的单个业务帧。"""
    header = conn.recv_exact(4)
    (length,) = struct.unpack("!I", header)
    return conn.recv_exact(length)

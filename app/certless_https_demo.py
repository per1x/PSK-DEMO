"""本地演示入口：串起充电桩与中心服务器的完整交互流程。"""
from __future__ import annotations

import threading
import time

from business.central_server_app import run_server
from business.charging_pile_client import run_client
from pkg.pkg_module import PKG


def simulate_https_exchange() -> None:
    """以线程方式同时启动服务器和充电桩，方便本地一键演示。"""
    pkg = PKG()
    print(f"[PKG] Master public key: {pkg.master_public.hex()}")
    ready = threading.Event()
    server_thread = threading.Thread(target=run_server, args=(pkg, ready), daemon=True)
    server_thread.start()
    ready.wait()
    # 给服务端一点时间进入 accept，避免客户端过早连接。
    time.sleep(0.1)
    run_client(pkg)
    server_thread.join(timeout=1)


if __name__ == "__main__":
    simulate_https_exchange()

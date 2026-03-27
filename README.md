# PSK-DEMO

基于 Python 的无证书握手与 TLS-PSK 通信演示项目。示例场景是充电桩与中心服务器先完成无证书身份协商，再把同一条 TCP 连接升级为 TLS 1.2 PSK 通道，最后在加密通道里传输 HTTP 业务报文。

## 目录结构

```text
.
├── app/         # 应用入口
├── business/    # 业务角色与业务流程
├── pkg/         # PKG 私钥生成中心相关实现
└── utils/       # 协议与 TLS-PSK 工具层
```

## 主要流程

1. `PKG` 为参与方基于身份派发部分私钥。
2. 充电桩和中心服务器交换无证书握手报文。
3. 双方校验签名并导出同一份会话密钥。
4. 会话密钥被作为 TLS-PSK 的预共享密钥。
5. 后续 HTTP 请求与响应都通过 TLS 加密通道传输。

## 运行环境

- Python 3.12+
- OpenSSL 动态库可用
- 依赖包见 `requirements.txt`

## 安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## 运行演示

```bash
python3 -m app.certless_https_demo
```

运行成功后，你会看到：

- PKG 主公钥输出
- 客户端与服务端分别导出的相同 TLS PSK
- TLS 通道内解密后的 HTTP 请求与响应

## GitHub Actions

仓库内置了一个最小 CI：

- 安装依赖
- 校验源码可编译
- 执行一次本地端到端演示

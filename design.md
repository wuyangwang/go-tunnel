# GoTunnel 设计文档

## 1. 项目简介

GoTunnel 是一个基于 Go 实现的轻量级 TCP 反向代理隧道工具。

用于解决手机和 PC 不在同一个局域网时，手机无法直接访问 PC 上 Charles 代理的问题。

通过 VPS 建立中转连接，让手机的 HTTP/HTTPS 代理流量最终进入 PC 上的 Charles。

## 2. 技术架构

- 开发语言：Go
- Server 系统：Linux
- Client 系统：Windows
- 通信协议：TCP + TLS
- 多路复用：yamux
- 编译目标：跨平台独立二进制文件

## 3. 网络架构

```text
Android 手机
    |
    | HTTP Proxy
    |
    v
VPS 公网 IP:4567
    |
    | GoTunnel Server
    |
    | TCP 隧道
    |
    v
Windows GoTunnel Client
    |
    | TCP
    |
    v
127.0.0.1:8890
    |
    v
Charles Proxy
```

## 4. 端口定义

| 端口 | 默认值 | 用途 |
|---|---:|---|
| Server Port | 4567 | VPS 服务端监听端口 |
| Client Port | 8890 | PC 本地 Charles 代理端口 |

说明：
- 手机代理地址填写 VPS 公网 IP。
- 手机代理端口填写 4567。
- PC Client 将流量转发到本地 Charles 的 8890 端口。
- Charles 需要开启对应端口的 HTTP Proxy 监听。

## 5. 工作流程

### 5.1 建立连接

1. VPS 启动 GoTunnel Server，监听 4567。
2. Windows 启动 GoTunnel Client。
3. Client 主动连接 VPS Server。
4. Server 保存 Client 的连接状态。
5. 建立 yamux 多路复用会话，等待代理请求。

### 5.2 转发请求

1. 手机将 HTTP 代理设置为 VPS 公网 IP:4567。
2. 手机向 VPS 发起代理连接。
3. Server 接收请求，通过 yamux 创建独立数据流。
4. Client 接收数据流。
5. Client 连接本地 Charles：127.0.0.1:8890。
6. 双向转发 TCP 数据。
7. Charles 返回的数据通过隧道返回手机。

### 5.3 连接断开

- Client 断开时，Server 清理对应会话。
- Client 自动尝试重新连接。
- 重连后重新建立 yamux 会话。
- 不保留断线期间的请求。

## 6. 模块划分

### 6.1 Server（Linux）

主要职责：

- TCP 监听。
- 接受 Client 连接。
- 管理 Client 会话。
- 接收手机代理连接。
- 通过 yamux 转发数据。
- 处理连接断开和资源清理。

不需要数据库、管理后台或 Web 界面。

### 6.2 Client（Windows）

主要职责：

- 主动连接 VPS。
- 建立 yamux 会话。
- 接收 Server 分配的数据流。
- 为每个数据流连接本地 Charles。
- 双向转发 TCP 数据。
- 断线自动重连。

不需要 GUI，直接运行命令行程序即可。

## 7. 命令行参数

不使用配置文件，只提供必要的命令行参数。

### Server

```bash
./gotunnel-server
```

默认监听：

```text
0.0.0.0:4567
```

修改端口：

```bash
./gotunnel-server -port 5000
```

### Client

```powershell
gotunnel-client.exe -server YOUR_VPS_IP:4567
```

默认 Charles 地址：

```text
127.0.0.1:8890
```

修改 Charles 端口：

```powershell
gotunnel-client.exe -server YOUR_VPS_IP:4567 -port 9000
```

## 8. 项目目录

```text
gotunnel/
├── cmd/
│   ├── server/
│   │   └── main.go
│   └── client/
│       └── main.go
│
├── internal/
│   ├── protocol/
│   │   └── protocol.go
│   ├── server/
│   │   └── server.go
│   ├── client/
│   │   └── client.go
│   └── tunnel/
│       └── tunnel.go
│
├── go.mod
└── README.md
```

## 9. 安全要求

- 使用 TLS 加密通信。
- Client 和 Server 建立连接时进行身份认证。
- Server 只接受授权 Client。
- 限制单个会话的连接数量，避免资源耗尽。
- 不允许将 Client 的本地 Charles 端口暴露到公网。

## 10. 开发阶段

第一阶段只实现核心功能：

1. Server 和 Client 建立连接。
2. yamux 多路复用。
3. 手机代理请求通过 VPS 转发。
4. Client 转发到 Charles。
5. HTTP 和 HTTPS CONNECT 请求正常工作。
6. 支持断线重连。

暂不实现：

- GUI。
- 多设备管理。
- 用户管理系统。
- 文件传输。
- 虚拟局域网。
- 自动 NAT 穿透。
- 配置文件。
- Web 管理后台。

## 11. 验收标准

- Linux VPS 可以独立运行 Server。
- Windows 无需安装 Go 环境即可运行 Client。
- 手机和 PC 可以处于完全不同的网络。
- 手机能够通过 VPS 访问 PC 上的 Charles。
- Charles 能正常显示 HTTP 请求。
- HTTPS 在手机信任 Charles 根证书且目标 App 允许代理解密的情况下能够正常抓取。
- 多个请求可以通过同一条隧道并发转发。
- 网络短暂断开后 Client 可以自动重连。

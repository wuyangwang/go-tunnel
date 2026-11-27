# GoTunnel

轻量级 TCP 反向代理隧道。解决手机与 PC 不在同一局域网时，手机无法访问 PC 上
Charles 代理的问题：通过一台 VPS 中转，把手机的 HTTP/HTTPS 代理流量送进 PC 上的
Charles。

```text
Android 手机
    | HTTP Proxy
    v
VPS 公网 IP:4567
    | GoTunnel Server
    | TCP + TLS + yamux 隧道
    v
Windows GoTunnel Client
    | TCP
    v
127.0.0.1:8890 (Charles Proxy)
```

## 技术架构

- 语言：Go
- Server：Linux（VPS），跨平台独立二进制
- Client：Windows（也可在 Linux/macOS 运行），跨平台独立二进制
- 通信：TCP + TLS（双向认证 / mutual TLS）
- 多路复用：[yamux](https://github.com/hashicorp/yamux)
- **同一端口复用**：`4567` 既接收 GoTunnel Client 的 TLS 隧道连接，也接收手机的
  明文 HTTP 代理连接（服务端通过 TLS ClientHello 首字节区分）

## 端口

| 端口 | 默认值 | 用途 |
|---|---:|---|
| Server Port | 4567 | VPS 服务端监听；手机代理端口也填这个 |
| Client Port | 8890 | PC 本地 Charles 代理端口 |

## 安全要求落地

- **TLS 加密**：client 与 server 之间 TLS 1.2+。
- **双向身份认证**：server 要求 client 出示由私有 CA 签发的证书；client 校验
  server 证书链（可用 `-server-name` 加强主机名校验）。**Server 只接受授权 Client。**
- **附加 token**（可选）：`-token` / 环境变量 `GOTUNNEL_TOKEN`，在 TLS 之上再做一次
  共享密钥认证（`crypto/subtle` 常量时间比较）。
- **连接数限制**：`-max-streams`（默认 256），原子预留，限制单个会话并发转发连接数，防止资源耗尽。
- **Client 不监听任何端口**：client 只主动向外连接 VPS，转发目标固定为本机
  `127.0.0.1` 上的 Charles，本地代理端口不会暴露到公网。

**凭证优先级**（高到低）：
`显式 -cert/-key/-ca` > `go:embed 内嵌证书` > `磁盘 certs/` > `-token 派生` > `certs/ 自动生成`。

## 证书与 TLS

不使用配置文件。你**不需要提供任何私有证书**，也不需要向任何 CA 申请。下面三种方式任选，
按上面优先级组合；默认仍是「**TLS 加密 + 双向认证 + 只接受授权 client**」，并非关闭 TLS。

### 1) 默认：自签名私有 CA 自动生成 + `certs/`

首次启动 server，如果 `certs/` 下没有证书，**自动生成自签名私有 CA + server 证书 +
client 证书**（已存在的不覆盖，私钥 `0600`）：

```text
certs/ca.pem  certs/ca-key.pem
certs/server.pem  certs/server-key.pem
certs/client.pem  certs/client-key.pem
```

- client 信任的**不是公共 PKI**，而是这个**本地生成的私有 CA**，自签名完全足够。
- 把 `certs/ca.pem`、`certs/client.pem`、`certs/client-key.pem` 复制到 PC 的 `certs/`
  目录（与 `gotunnel-client.exe` 同级）。`ca-key.pem` 仅用于签发，请妥善保管、不要复制到 client。
- `-init-certs DIR` 仅生成证书后退出；`-san` 为生成的 server 证书追加 DNS 名/IP；
  `-cert/-key/-ca` 指向自己的证书文件。
- 已有 `certs/` + `-token X` → 仍用证书 + 额外 token 校验（向后兼容）。

### 2) 把一切化简为一个 token：`-token`（单用户最简单）

**两边都给同一个 `-token`，且没有任何证书**：server 和 client 的 TLS 证书
（CA + 双向 keypair，ed25519）在**内存中从该 token 确定性派生**，**不需要额外开关**，
token 一传就自动生效：

```bash
# VPS
./gotunnel-server -token my-secret
# PC
gotunnel-client.exe -server YOUR_VPS_IP:4567 -token my-secret
```

- **不要任何外部文件、二进制里不放任何私钥、不要构建时生成、不复制任何东西**。
- **TLS 加密 + 双向认证仍然开启**。证书运行时派生，什么都不存盘。
- 授权退化为「**知道 token 即已授权**」：能连的 client 必须拿到同一个 token；不知道 token
  的人无法派生 client key、无法通过双向 TLS，也无法解密。`-token` 同时还做应用层 token 校验。
- 取一个足够长的随机 token（如 `openssl rand -hex 32`）。token 泄露 = 完全暴露，请当密码保管。
- **仍要求一个共享秘密（token）传给两边**，只是它不再是「证书/私钥文件」。双向 TLS 的本质
  始终是「总得有一个共享秘密或私钥传给 client」；上面各模式只是秘密的不同存放方式
  （文件 / bin 内嵌 / 运行时派生 / token），任一都能满足「无外部证书 + TLS + 授权」。

### 3) 把证书打包进二进制（`go:embed`，自包含单文件，可选）

默认仍是「server 首启自动生成 `certs/` + 复制 3 个文件到 client」。想要**不需要运行时
`certs/`、不需要复制任何文件的单文件二进制**，可在构建前生成证书并 `go:embed` 打进二进制：

```bash
# 1) 生成自签名 CA + server/client 证书到 embed 目录
go run ./cmd/gencerts -dir internal/tlsutil/embedded
# 或 go generate ./internal/tlsutil

# 2) 正常构建即可，生成的 PEM 自动打包进二进制
go build ./cmd/server
go build ./cmd/client            # Windows: GOOS=windows go build -o gotunnel-client.exe ./cmd/client

# 或一条命令：make selfcontained
```

- 生成的 `*.pem` 已 `.gitignore`，**不提交**。
- `gencerts` 也可单独用：`go run ./cmd/gencerts -dir DIR -san ...`（构建后 `gencerts -dir DIR`）。

**安全提醒（重要）**：这会把 **CA / server / client 私钥塞进你构建的二进制**。**任何拿到这个
bin 的人都能提取私钥**，并作为已授权 client 连上你的 server。只在**你自己本地构建、自己掌控
分发**的场景用；**不能用于公开 release / 多人共享的二进制**。本项目的 CI Release 故意**不**
内嵌任何密钥，发布产物仍走运行时自动生成 / `-token`。如果既不想放私钥在 bin、又不想要文件，
用方式 2（`-token` 派生）。

## 构建

```bash
go build ./cmd/server   # gotunnel-server
go build ./cmd/client   # gotunnel-client
```

跨平台静态编译：

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o gotunnel-server       ./cmd/server
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o gotunnel-client.exe   ./cmd/client
```

或 `make build` / `make selfcontained`。

## 使用

### Server（Linux VPS）

```bash
./gotunnel-server                 # 默认监听 0.0.0.0:4567
./gotunnel-server -port 5000      # 修改端口
./gotunnel-server -max-streams 512
./gotunnel-server -token my-secret
```

### Client（Windows PC）

```powershell
gotunnel-client.exe -server YOUR_VPS_IP:4567
gotunnel-client.exe -server YOUR_VPS_IP:4567 -port 9000   # Charles 改用 9000
```

- 默认转发到 `127.0.0.1:8890`（Charles）。
- `-local host:port` 可覆盖完整本地地址。
- 断线自动重连（`-reconnect-delay`，默认 1s），重连后重建 yamux 会话，不保留断线期间的请求。
- Charles 需在对应端口开启 HTTP Proxy 监听。

### 手机

HTTP 代理填 VPS 公网 IP，端口填 `4567`。HTTPS 抓包需在手机信任 Charles 根证书，
且目标 App 允许代理解密。

## CI 与 Release 发布

**一个工作流** `.github/workflows/workflow.yml`：**push 到 `master` 时触发**。

- `test`（ubuntu/windows/macos 三平台：`go vet`、`gofmt` 检查、`go test ./...`、`go build`）；
- `test-race`（`-race`）；
- **server 与 client 分开发布**：`release-server` + `release-client` 两个 job，
  都 **`needs` 等 `test` + `test-race` 通过后**自动发布。
- 仅 `release-*` job 有 `contents: write`，其余 `contents: read`；无 `pull_request` 触发。

**Release**：测试 → `CGO_ENABLED=0` 交叉编译（linux/darwin/windows × amd64/arm64，共 6 平台）→
**裸二进制（不打 tar.gz/zip）** → 各自 `SHA256SUMS` → **两个独立 GitHub Release**。
**GitHub Release tag 必须唯一**，故 server `server-v0.0.N`、client `client-v0.0.N`
（同一个 `N = ${GITHUB_RUN_NUMBER}`），`gh release create ... --target ${GITHUB_SHA}` +
自动变更说明。**每次 push master 都会发布两个 Release**，无需手动打 tag。
产物命名：`gotunnel-server_<os>_<arch>[.exe]`、`gotunnel-client_<os>_<arch>[.exe]`
（Windows 带 `.exe`，每个 Release 只含自己那半）。**发布产物不内嵌任何密钥。**

## 项目结构

```text
gotunnel/
├── cmd/
│   ├── server/main.go      # gotunnel-server 入口
│   ├── client/main.go      # gotunnel-client 入口
│   └── gencerts/main.go    # 证书生成工具（也用于 go:embed 打包）
├── internal/
│   ├── protocol/           # 版本、端口常量、TLS 探测、认证握手、BufferedConn
│   ├── server/             # 监听、协议分流、会话管理、流数限制、转发
│   ├── client/             # 主动连接、TLS+认证、yamux、本地转发、自动重连
│   ├── tunnel/             # 双向转发 + 半关闭传播
│   └── tlsutil/            # mutual TLS + 私有 CA/证书生成 + 内嵌 + token 派生
├── .github/workflows/      # CI + Release
├── Makefile                # build / test / selfcontained
├── go.mod
└── README.md
```

## 连接生命周期

1. VPS 启动 server，监听 4567。
2. PC 启动 client，主动连接 VPS，mutual TLS + 认证，建立 yamux 会话；server 记录
   当前会话（新授权 client 会替换旧会话）。
3. 手机连接 VPS:4567，server 为每个代理连接新开一条 yamux stream。
4. client 收到 stream，连接本地 Charles 127.0.0.1:8890，双向转发；HTTP 与 HTTPS
   CONNECT 均为透传字节，正常工作；多个请求并发复用同一条隧道。
5. client 断开：server 清理会话；client 自动重连并重建会话；断线期间的请求不保留。

## 测试

```bash
go test ./...
```

含单元测试与端到端测试（真实 TLS + yamux + 本地 echo 目标 + 手机模拟连接、并发、
CONNECT 透传、token 拒绝、token 派生 TLS、无会话丢弃、`max-streams`）。

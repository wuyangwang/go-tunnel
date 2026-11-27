# GoTunnel

轻量级 TCP 反向代理隧道。把手机的 HTTP/HTTPS 代理流量经 VPS 转发到 PC 上的 Charles，
用于手机抓包；**不启动 client / Charles 时手机也能正常上网**（自动降级直连）。

```text
手机 → VPS:4567 → (隧道 → PC Charles) 或 (直连上网)
```

## 使用

### 1. VPS 启动 server

```bash
./gotunnel-server -token my-secret
```

默认监听 `0.0.0.0:4567`。`-token` 只用于 client 认证；没证书也没关系，证书从 token 在内存派生。
如需抓包，再在 PC 启动 client（下面第 2 步）。只用手机上网时不启动 client 即可。

### 2. PC 启动 client（需要抓包时）

```powershell
gotunnel-client.exe -server VPS公网IP:4567 -token my-secret
```

默认转发到本机 Charles `127.0.0.1:8890`（端口不同加 `-port 8888`）。
手机和 PC 不在同一局域网也能用。

### 3. 手机

Wi-Fi 代理：主机名填 **VPS 公网 IP**，端口填 **4567**。不需要用户名/密码。

> 注意：Android 的 Wi-Fi 代理只对当前 Wi-Fi 生效；用流量时无效。

抓 HTTPS 还需：Charles 开启 SSL Proxying（`*:443`）、手机安装并信任 Charles 根证书
（`chls.pro/ssl`）、App 允许代理解密。

## 后台运行（server / client 都支持）

```bash
gotunnel-server  start -token my-secret
gotunnel-server  status
gotunnel-server  log -f
gotunnel-server  stop

gotunnel-client.exe start -server VPS公网IP:4567 -token my-secret
gotunnel-client.exe log -f
gotunnel-client.exe stop
```

PID / 日志在 `~/.gotunnel/gotunnel-{server,client}.{pid,log}`。

## 流量走向

| 情况 | 走向 | 能否抓包 |
|---|---|---|
| client + Charles 都开 | VPS → 隧道 → Charles | 能 |
| client 开、Charles 没开 | client 直连目标（PC 出口） | 不能 |
| client 没开 | server 直连目标（VPS 出口） | 不能 |

降级支持 HTTP 和 HTTPS CONNECT，手机始终能上网，只是那条流量抓不到包。

**安全提示**：client 没开时 server 是**开放代理**，任何能连到 `VPS:4567` 的人都能使用。
建议用 VPS 防火墙限制来源 IP，或用完即关。

## 构建 / 测试

```bash
go build ./cmd/server
go build ./cmd/client
go test ./...
```

## CI / Release

push 到 `master` 自动跑 CI（vet / gofmt / test / race），通过后自动发布一个 Release，
包含 4 个独立二进制（linux-amd64、windows-amd64 各 server/client）和 `SHA256SUMS`，
无压缩包，不内嵌密钥。

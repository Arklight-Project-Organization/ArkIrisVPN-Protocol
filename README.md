# ArkIris VPN

ArkIris VPN 是一个基于 Rust 的点对点 VPN / 隧道程序，通过 UDP 建立加密隧道并创建 `arkiris0` 虚拟网络接口。

如果希望使用更直观的终端界面，可配合独立的 **ArkIrisVPN-TUI 启动器**：

- https://github.com/Arklight-Project-Organization/ArkIrisVPN-TUI

> 本 README 面向普通用户。开发者内部实现细节不在本文展开。

## 目录

- [功能概览](#功能概览)
- [准备工作](#准备工作)
- [快速开始](#快速开始)
- [密钥与 PSK](#密钥与-psk)
- [TUI 启动器](#tui-启动器)
- [常用配置](#常用配置)
- [启动后的网络](#启动后的网络)
- [常见问题](#常见问题)
- [安全建议](#安全建议)

## 功能概览

- UDP VPN / 隧道
- Client / Server 模式
- TUN 虚拟网络接口
- IPv4 / IPv6 隧道地址池
- PSK 预共享密钥
- 客户端静态密钥认证
- BBR / CUBIC 拥塞控制
- 可选 FEC、LDT、带宽限制与 pacing
- ACL、日志、状态文件和监控端口
- 可选内置 TUI
- 独立 ArkIrisVPN-TUI 启动器

## 准备工作

如果已经编译完成，可以运行：

```powershell
.\arkiris.exe --help
```

Server 默认监听：

```text
UDP 13250
```

默认 VPN 网段：

```text
IPv4: 10.9.0.0/24
IPv6: fd00:9::/64
```

Server 必须能够被 Client 通过 UDP 访问。如果 Server 位于 NAT 后，需要正确配置 UDP 端口转发。

## 快速开始

### Server

Server 需要自己的静态私钥、PSK，以及允许连接的 Client 公钥：

```powershell
.\arkiris.exe `
  --mode server `
  --bind 0.0.0.0:13250 `
  --psk YOUR_PSK_HEX `
  --static-secret SERVER_STATIC_PRIVATE_KEY `
  --allowed-clients CLIENT_STATIC_PUBLIC_KEY
```

服务器防火墙需要允许 UDP `13250`（如果修改了 `--bind`，则开放对应端口）。

### Client

Client 需要自己的静态私钥、Server 静态公钥、相同的 PSK，以及 Server 地址：

```powershell
.\arkiris.exe `
  --mode client `
  --bind 0.0.0.0:0 `
  --peer SERVER_IP:13250 `
  --psk YOUR_PSK_HEX `
  --static-secret CLIENT_STATIC_PRIVATE_KEY `
  --peer-static-public SERVER_STATIC_PUBLIC_KEY
```

例如：

```text
--peer 203.0.113.10:13250
```

`203.0.113.10` 只是文档示例地址，请替换成实际 Server 地址。

## 密钥与 PSK

### 静态密钥

每台设备都有自己的静态密钥对：

```text
Server:  Static Private Key + Static Public Key
Client:  Static Private Key + Static Public Key
```

Server 配置：

```text
--static-secret SERVER_PRIVATE_KEY
--allowed-clients CLIENT_PUBLIC_KEY
```

Client 配置：

```text
--static-secret CLIENT_PRIVATE_KEY
--peer-static-public SERVER_PUBLIC_KEY
```

**私钥不要分享、提交到 Git 或放进公开截图。**

### PSK

Client 与 Server 必须使用完全相同的 PSK。

程序要求 PSK 解码后至少为 **32 字节**，因此十六进制形式至少需要 **64 个 hex 字符**。

也可以使用环境变量：

```powershell
$env:ARKIRIS_PSK="YOUR_PSK_HEX"
```

然后不再传 `--psk`。

> README 中的密钥均为占位符，不要直接拿示例值用于真实部署。

## TUI 启动器

ArkIris 本体可以直接使用命令行运行；如果不希望每次手动输入一长串参数，可以使用独立的 **ArkIrisVPN-TUI**。

项目地址：

https://github.com/Arklight-Project-Organization/ArkIrisVPN-TUI

推荐使用方式：

```text
ArkIrisVPN-TUI
      |
      +-- 配置 / 选择连接
      |
      +-- Client -> ArkIris
      |
      `-- Server -> ArkIris
```

TUI 是独立项目，因此它自己的安装、界面和快捷键说明以其 README 为准。

## 常用配置

### 禁用内置 TUI

服务器、脚本或后台运行时可以使用：

```text
--no-tui
```

### 修改 VPN 网段

```text
--subnet4 10.10.0.0/24
--subnet6 fd00:10::/64
```

Client 和 Server 应保持一致。

### 修改 MTU

默认：

```text
--mtu 1420
```

遇到封装、分片或部分网络环境的问题，可以尝试：

```text
--mtu 1400
```

允许范围为 `576-1500`。

### 拥塞控制

默认：

```text
--cc bbr
```

也可以：

```text
--cc cubic
```

### 带宽限制

例如：

```text
--rate-limit-mbps 100
--rate-burst-seconds 1
```

### 日志

```text
--log-file arikiris.log
--log-level info
```

### 多客户端

Server 可以用逗号分隔多个 Client 公钥：

```text
--allowed-clients CLIENT_PUBLIC_KEY_1,CLIENT_PUBLIC_KEY_2,CLIENT_PUBLIC_KEY_3
```

建议每个 Client 使用自己的静态密钥对，不要让多台设备共用同一个 Client 私钥。

### 状态文件

默认：

```text
arkiris_state.json
```

可以修改：

```text
--state-file my-arkiris-state.json
```

## 启动后的网络

成功启动后，程序会创建：

```text
arkiris0
```

默认 VPN 网络：

```text
10.9.0.0/24
fd00:9::/64
```

Windows 可以使用：

```powershell
ipconfig
```

或：

```powershell
Get-NetAdapter
```

检查虚拟网络接口。

## 高级选项

ArkIris 还支持：

- LDT：`--ldt`、`--ldt-max-packet`
- FEC：`--fec`
- Pacing：`--pacing-mbps`
- Jitter：`--jitter`
- ACL：`--acl`
- 监控：`--monitor-port`
- 后台运行：`--daemonize`
- TUI 主题：`--tui-theme`
- TUI 刷新间隔：`--tui-refresh-ms`

普通用户建议先保持默认值，确认基础连接正常后再调整高级参数。

## 常见问题

### Client 无法连接 Server

依次检查：

1. `--peer` 是否填写正确。
2. Server 是否正在运行。
3. UDP 监听端口是否开放。
4. NAT / 路由器是否正确转发 UDP。
5. Client 与 Server 的 PSK 是否完全一致。
6. Client 公钥是否已经加入 Server 的 `--allowed-clients`。
7. Client 的 `--peer-static-public` 是否为正确的 Server 公钥。

### Server 启动时报密钥错误

Server 必须提供：

- `--static-secret`
- 至少一个 `--allowed-clients`

### Client 启动时报密钥错误

Client 必须提供：

- `--static-secret`
- `--peer-static-public`

### PSK 错误

PSK 必须是合法十六进制字符串，并且解码后至少为 32 字节。

### `arkiris0` 没有出现

请检查：

- 当前用户是否具有创建/配置虚拟网络接口的权限
- 操作系统是否具备所需 TUN 支持
- 所需网络驱动/组件是否正确安装
- 日志中是否存在 TUN 初始化错误

### 能连接但网络访问异常

优先检查：

1. MTU
2. 路由
3. 防火墙
4. NAT / IP forwarding
5. VPN 子网是否与本地网络冲突

可以先尝试：

```text
--mtu 1400
```

## 安全建议

不要公开以下内容：

```text
Server Static Private Key
Client Static Private Key
PSK
```

不要把它们提交到 Git 仓库、公开 Issue、聊天群或截图中。

Server 建议通过 `--allowed-clients` 明确限制允许连接的 Client。

## 最小配置总结

### Server

```powershell
.\arkiris.exe `
  --mode server `
  --bind 0.0.0.0:13250 `
  --psk YOUR_PSK `
  --static-secret SERVER_PRIVATE_KEY `
  --allowed-clients CLIENT_PUBLIC_KEY
```

### Client

```powershell
.\arkiris.exe `
  --mode client `
  --bind 0.0.0.0:0 `
  --peer SERVER_IP:13250 `
  --psk YOUR_PSK `
  --static-secret CLIENT_PRIVATE_KEY `
  --peer-static-public SERVER_PUBLIC_KEY
```

## 推荐使用流程

```text
准备 Server
    |
    v
准备 Client
    |
    v
生成 / 准备双方静态密钥
    |
    v
设置相同 PSK
    |
    v
Server 配置 allowed-clients
    |
    v
开放 Server UDP 端口
    |
    v
启动 Server
    |
    v
启动 Client
    |
    v
检查 arikiris0
    |
    v
测试 VPN 内部网络
    |
    v
需要时再调整 MTU / FEC / CC 等高级参数
```

如果希望通过终端界面管理 ArkIris，请使用：

https://github.com/Arklight-Project-Organization/ArkIrisVPN-TUI

## 命令帮助

以程序自身帮助为准：

```powershell
.\arkiris.exe --help
```

查看 benchmark 子命令：

```powershell
.\arkiris.exe bench --help
```

## 项目

- ArkIrisVPN-TUI：https://github.com/Arklight-Project-Organization/ArkIrisVPN-TUI

报告问题时建议提供：

- 操作系统
- ArkIris 版本 / commit
- 启动参数（删除 PSK 和私钥）
- 相关日志
- 网络拓扑

**请不要在 Issue、日志或截图中公开 PSK、私钥等敏感信息。**

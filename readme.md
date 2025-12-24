# 勒索软件模拟器 (Ransomware Simulator)

[![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！

## 项目概述
这是一个用于红队演练和防御研究的勒索软件模拟器，模拟真实勒索软件的行为模式，包括文件加密、勒索信生成、C2通信等关键攻击链环节。项目遵循MIT许可证，旨在帮助安全团队测试防御方案和进行安全意识培训。

**当前版本**: v2.7-Beta

## 主要功能
- 🔒 **文件加密系统**
  - 使用RSA-2048 + AES-256混合加密
  - 支持多平台文件操作（Windows/Linux/macOS）
  - 并发加密处理（多worker支持）
- 📜 **勒索信生成**
  - 多语言勒索模板（中/英文）
  - 桌面勒索信投放
  - 自定义勒索信内容
- ⚙️ **攻击链模拟**
  - 持久化机制（互斥锁）
  - 防御规避技术（进程终止、日志清除）
  - C2心跳通信
- 🛡️ **安全模式**
  - 演习模式（dry-run）避免实际破坏
  - 文件操作日志记录

## 技术架构
```
├── decryptor.go         # 解密工具
├── go.mod                # Go模块依赖
├── go.sum               # Go依赖校验
├── LICENSE              # MIT许可证
├── ransom_simulator.go  # 主程序
├── readme.md            # 项目文档
└── workers/             # C2服务器组件
    ├── bad-c2-server.js  # Cloudflare Worker实现的C2服务器
    └── rsauuid.js    # RSA 密钥接口
```

## 安装与使用

### 预编译二进制
从[Releases页面](https://github.com/yangzifun/ransom_simulator/releases)下载对应平台的二进制文件：
```bash
# Windows
ransom_simulator.exe [参数]

# Linux/MacOS
./ransom_simulator_linux [参数]
```

### 从源码编译

#### 3.1. 先决条件
- 安装 **Go 编程语言** (版本 1.18 或更高)。

#### 3.2. 编译步骤
假设您已将 `main.go` (以及 `decryptor.go`) 文件放置在您的工作目录下。

| **目标平台**              | **命令**                                                     | **输出文件示例**                                         |
| :------------------------ | :----------------------------------------------------------- | :------------------------------------------------------- |
| **Linux (64位)**          | GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator_linux ransom_simulator.go<br/>CGO_ENABLED=0 go build -o ransom_simulator_linux_static ransom_simulator.go | ransom_simulator_linux<br/>ransom_simulator_linux_static |
| **Windows (64位)**        | GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator.exe ransom_simulator.go | ransom_simulator.exe                                     |
| **macOS (Intel)**         | GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator_macos_intel ransom_simulator.go | ransom_simulator_macos_intel                             |
| **macOS (Apple Silicon)** | GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ransom_simulator_macos_arm ransom_simulator.go | ransom_simulator_macos_arm                               |

> 提示：`-ldflags="-s -w"` 是一个可选参数，用于移除调试信息，减小最终可执行文件的大小。

### 基本使用
```bash
# 演习模式（不实际加密文件）
./ransom_simulator --dry-run

# 指定工作线程数
./ransom_simulator --workers=8

# 加密特定目录
./ransom_simulator --dir="/path/to/target"

# 加密后删除原文件（危险！）
./ransom_simulator --remove

# 只加密特定扩展名文件
./ransom_simulator --ext=".doc,.pdf"
```

### 使用示例 (演练指导)

#### 示例 1: 精准打击 - 加密单个重要文件
目标：测试 DLP 或 EDR 是否能阻止对特定敏感文件（如 passwords.txt）的加密操作。

```bash
# 直接指定文件路径
./ransom_simulator_linux -dir /home/admin/secrets/passwords.txt -remove
```
效果：程序将忽略扩展名检查，强制加密该文件并在同级目录下生成勒索信。

#### 示例 2: 区域全灭 - 加密指定目录下的所有内容
目标：模拟针对特定业务目录的毁灭性打击。

```bash
# 指定业务目录，开启8个线程并发加密
./ransom_simulator.exe -dir "C:\Users\Admin\Documents\Projects" -workers 8 -remove
```
效果：该目录下的所有文件（无论后缀是 .txt 还是 .custom）都将被加密。勒索信将投递到该目录及其所有子目录中。

#### 示例 3: 全盘扫描 - 传统勒索模式
目标：模拟传统勒索软件，扫描全盘并只加密特定价值的文档。

```bash
# 不指定 -dir，则自动扫描全盘（或Linux根目录）
# 此时必须依赖内置的扩展名列表或通过 -ext 指定
./ransom_simulator_linux -ext .pdf,.docx,.xlsx -dry-run
```

## 命令行参数详解

| **参数** | **类型** | **状态** | **描述**                                                     | **关键用途**                                     |
| :------- | :------- | :------- | :----------------------------------------------------------- | :----------------------------------------------- |
| -dir     | string   | **推荐** | 指定攻击目标。可以是**目录路径**或**单个文件路径**。多个路径用逗号分隔。**注意：使用此参数时，将忽略 -ext 限制，强制加密目标内所有格式文件。** | **精准打击**：定向加密特定文件或目录，便于测试。 |
| -ext     | string   | 可选     | 指定要加密的文件扩展名（如 .txt,.doc）。**仅在未指定 -dir 时生效**（全盘扫描模式）。 | **范围控制**：在全盘扫描模式下限制文件类型。     |
| -workers | int      | 可选     | 并发 Worker 线程数量 (默认: CPU核心数)。                     | **性能模拟**：测试系统资源消耗和响应延迟。       |
| -dry-run | bool     | 可选     | **演习模式**：只查找、列出目标，不进行加密或破坏性操作。     | **安全测试**：初步验证扫描和检测规则。           |
| -remove  | bool     | 可选     | **[高危]** 加密成功后删除原始文件。                          | **真实模拟**：模拟真实勒索软件的彻底破坏。       |

## 技术细节

### 加密流程
1. **密钥获取**：
   - 尝试连接C2服务器获取RSA公钥和UUID（API：`https://rsa-uuid.api.yangzifun.org`）
   - 失败时使用内置默认密钥（离线模式）
   
2. **文件加密**：
   ```mermaid
   graph TD
     A[生成随机AES-256密钥] --> B[使用AES-GCM加密文件内容]
     B --> C[使用RSA加密AES密钥]
     C --> D[组合输出：加密密钥+Nonce+密文]
   ```

3. **输出格式**：
   - 加密后文件扩展名：`.encrypted`
   - 文件结构：`[RSA加密的AES密钥(256字节)] + [Nonce(12字节)] + [AES-GCM加密内容]`

### C2通信协议
1. **心跳机制**：
   - 定时向C2服务器发送心跳（`https://bad-c2-server.api.yangzifun.org/beacon_check_in`）
   - 收集客户端信息（IP、User-Agent等）
   
2. **C2服务器实现**：
   - 使用Cloudflare Worker（workers/bad-c2-server.js）
   - 日志记录所有连接请求
   - 返回简单的JSON响应

### 互斥锁与持久化
为了模拟真实恶意软件的单实例特性，程序启动时会在临时目录创建 `.lock` 文件。
- **改进机制**：在 v2.5 版本中，程序启动的第一步是**强制尝试删除旧的锁文件**。这意味着您在进行反复的自动化测试时，不再需要手动清理环境，程序会自动重置状态。
- **手动删除**：
  ```bash
  # Linux/MacOS
  rm /tmp/ransom_simulator_instance.lock
  
  # Windows
  del %TEMP%\ransom_simulator_instance.lock
  ```

### 防御规避技术
1. **进程终止**：
   - Windows：结束notepad.exe, winword.exe等进程
   - Linux：结束gedit, vim等进程
   
2. **日志清除**：
   - 模拟清除系统日志和安全日志
   - 实际实现为占位符（需在真实环境中扩展）

### 文件识别

### 模拟的关键攻击阶段 (MITRE ATT&CK®)

| **Tactic (战术)**              | **ID** | **模拟行为**                                                 |
| :----------------------------- | :----- | :----------------------------------------------------------- |
| **执行** (Execution)           | TA0002 | 模拟通过社工手段获取执行权限。                               |
| **防御规避** (Defense Evasion) | TA0005 | 模拟删除卷影副本 (`vssadmin`) 或备份 (`tmutil`) 的行为。     |
| **命令与控制** (C2)            | TA0011 | 模拟向攻击者控制的服务器发送网络信标（Beacon Check-in）。    |
| **发现** (Discovery)           | TA0007 | 扫描文件系统，支持**特定扩展名筛选**或**指定路径的全量扫描**。 |
| **影响** (Impact)              | TA0040 | **核心载荷**：使用 AES-256 + RSA-2048 混合加密算法对目标文件进行加密。**全覆盖勒索信**：在每个包含加密文件的目录中投放勒索信。 |

默认加密扩展类型包括：
```
文档: .doc, .docx, .pdf, .xls, .xlsx, .ppt, .pptx
图片: .jpg, .jpeg, .png, .gif, .bmp
压缩文件: .zip, .rar, .7z, .tar
数据库: .sql, .db, .mdb
代码: .go, .json
```

## 解密流程
1. 访问解密门户：https://encrypt.yangzifun.org/
2. 输入加密时生成的UUID
3. 下载解密工具：
   ```bash
   # 解密单个文件
   decryptor -key=UUID -file=加密文件.encrypted
   
   # 批量解密目录
   decryptor -key=UUID -dir=加密文件目录
   ```

## 免责声明
本项目遵循[MIT许可证](LICENSE)。开发者不对任何滥用行为负责。使用本工具即表示您同意：
1. 仅在合法授权的安全测试中使用
2. 不在生产环境或未授权系统中使用
3. 对因不当使用造成的损失承担全部责任

**注意**：真实勒索软件是非法行为！本工具仅用于教育目的。

## 项目链接
- GitHub: https://github.com/yangzifun/ransom_simulator
- 解密工具: https://encrypt.yangzifun.org/

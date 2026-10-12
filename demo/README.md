# 勒索软件模拟器 - 演示版 (Demo)

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Version](https://img.shields.io/badge/Version-v3.4--demo-blue.svg)

> **安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！

## 项目概述

这是勒索软件模拟器的**演示版本**，与完整版的关键区别在于：**仅加密程序所在目录下的文件**，不会遍历整个磁盘。适用于安全培训、产品演示和快速验证加密/解密流程。


## 快速开始

### 直接运行（双击）

将 `ransom_simulator_demo.exe` 放到任意测试目录，双击运行即可启动 **GUI 伪装 Chrome 安装模式**，后台静默加密该目录下的文件。

> 如需进入 CLI 控制台模式，请通过命令行传递任意参数，例如：
> ```cmd
> ransom_simulator_demo.exe --dry-run
> ```

### 演习模式（仅扫描，不加密）

```cmd
ransom_simulator_demo.exe --dry-run
```

### 指定扩展名

```cmd
ransom_simulator_demo.exe --ext ".txt,.pdf,.docx"
```

### 启用日志

```cmd
ransom_simulator_demo.exe --log
```

### GUI 伪装模式（仅 Windows）

```cmd
ransom_simulator_demo.exe -gui
```

启动后弹出 Chrome 安装程序窗口，显示进度条和状态文字，加密过程在后台静默执行。加密完成后窗口自动关闭。

## 命令行参数

| 参数 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `--workers` | int | 并发 worker 数量 | CPU 核心数 |
| `--dry-run` | bool | 演习模式，不实际加密 | false |
| `--ext` | string | 指定要加密的文件扩展名（逗号分隔，如 `.txt,.pdf`） | 所有默认扩展名 |
| `--remove` | bool | 加密后删除原文件（默认启用，可通过 -remove=false 禁用） | true |
| `--log` | bool | 启用日志功能，在程序所在目录输出日志文件 | false |
| `--gui` | bool | 显式指定 GUI 模式（双击无参数运行时默认启用，此参数仅用于与其他参数组合） | false |

## 密钥管理

程序采用 **API 优先获取密钥，失败回退本地密钥** 的策略。

### 1. 远程 API 模式（默认）

程序启动时自动向以下接口请求 RSA 公钥：

```
POST https://encrypt.yangzifun.org/E56dSY
```

如果 API 可用，将自动获取 UUID 和公钥。

### 2. 本地密钥模式（回退/离线）

当 API 不可用时（网络断开、服务不可达），自动回退到本地公钥文件。

将公钥文件命名为 `public_key_<uuid>.pem` 并放在程序所在目录：

```
测试目录/
├── ransom_simulator_demo.exe
└── public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem
```

程序将自动从文件名中提取 UUID。

## 加密算法

使用 **RSA-2048 + AES-256-GCM** 混合加密：

1. 为每个文件生成随机 AES-256 密钥
2. 使用 AES-256-GCM 加密文件内容
3. 使用 RSA-2048 公钥加密 AES 密钥
4. 加密后的文件保存为 `原文件名.encrypted`，默认删除原文件（可通过 `-remove=false` 保留）

## 编译

### Windows

```cmd
cd demo
go build -ldflags "-H windowsgui" -o ransom_simulator_demo.exe .
```

> `-ldflags "-H windowsgui"` 可彻底隐藏控制台窗口，双击运行时仅显示伪装安装器 GUI。
> 如仍需控制台交互（CLI 模式），省略此参数，程序会在 GUI 模式下自动隐藏控制台。

### Linux

```bash
cd demo
GOOS=linux GOARCH=amd64 go build -o ransom_simulator_demo .
```

## GUI 伪装模式

> **仅 Windows 平台支持**，非 Windows 平台启动会提示不支持。

**双击运行（无参数）默认进入此模式**，也可通过 `-gui` 参数显式指定。程序会弹出一个伪装为 Chrome 安装程序的窗口，包含以下元素：

- 标题栏显示 "Google Chrome 安装程序"
- 副标题 "正在安装 Chrome..."
- 动态状态文字（模拟安装步骤提示）
- 进度条（0%~100%）
- 取消按钮（点击后窗口关闭，但加密继续在后台执行）

加密流程在后台线程中执行，每 200ms 刷新一次 UI 进度，完成后窗口自动关闭。该模式下不会显示勒索信和倒计时退出提示。

**实现文件**：
- `installer_gui_windows.go`：Windows 原生 GUI 实现（Win32 API）
- `installer_gui_other.go`：非 Windows 平台存根

## 日志文件

启用 `--log` 参数后，程序目录下会生成以下日志文件：

```
程序所在目录/
├── success_encrypted.log  # 成功加密的文件列表
├── failed_encrypted.log   # 加密失败的文件列表及错误信息
└── operations.log         # 完整操作日志
```

## 排除规则

程序会自动排除以下文件，确保不会加密自身：

- 程序自身（`.exe`）
- 已加密文件（`.encrypted`）
- 勒索信（`!!!_如何解密你的文件_!!!.txt`）
- 日志文件（`.log`）
- 公钥文件（`public_key_*.pem`）
- 锁文件（`.lock`）
- 解密工具（`decryptor.exe`）
- Go 源码和模块文件（`go.mod`、`go.sum` 等）
- `workers/` 子目录

## 免责声明

**重要提醒**：本工具为**安全研究和培训专用**，严禁用于非法用途！

- ✅ 仅在合法授权的环境中使用
- ✅ 获取系统所有者的明确授权
- ✅ 在隔离的测试环境中运行
- ✅ 备份所有重要数据

开发者不对任何滥用行为负责。使用者需承担全部法律责任。真实勒索软件是严重犯罪行为！本工具仅用于教育和防御研究。

## 项目链接

- **GitHub 仓库**: https://github.com/yangzifun/ransom_simulator
- **密钥管理系统**: https://encrypt.yangzifun.org/
- **完整版文档**: 见项目根目录 [readme.md](../readme.md)
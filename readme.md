# Ransomware Simulator - 安全意识与应急响应演练工具

![警告](https://img.shields.io/badge/Status-Educational%20Tool-yellow.svg)
![语言](https://img.shields.io/badge/Language-Go-blue.svg)
![平台](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## ⚠️ 严正警告

**本项目仅用于合法的安全研究、教育和企业内部攻防演练目的。**

**在任何情况下，严禁在未经授权的系统上运行此程序。此工具会模拟对文件进行不可逆的加密操作。在非受控环境中运行可能导致真实的数据丢失和系统损坏。**

**使用者必须对自己的行为负责。开发者对因滥用此工具而造成的任何损害不承担任何责任。**

---

## 1. 项目简介

`Ransomware Simulator` 是一个跨平台的勒索软件攻击模拟器，使用 Go 语言编写。它旨在通过模拟真实勒索软件的关键攻击阶段，帮助蓝队成员、安全分析师和系统管理员：

-   **测试终端防护 (EDR/XDR) 的检测能力**：观察安全产品是否能捕获到可疑的文件操作、加密行为和网络信标。
-   **验证备份与恢复策略**：在安全的环境中检验数据恢复流程的有效性。
-   **提升应急响应能力**：为安全团队提供一个真实的模拟场景，以演练事件调查、溯源和清除流程。
-   **增强员工安全意识**：直观地展示勒索软件的破坏力，作为内部安全培训的生动案例。

### 模拟的关键攻击阶段 (MITRE ATT&CK®)

-   **(TA0002) 执行**: 需要密码才能运行，模拟通过社工手段获取执行权限。
-   **(TA0005) 防御规避**: 模拟删除卷影副本 (Windows) 或备份 (Linux/macOS) 的行为。
-   **(TA0011) 命令与控制 (C2)**: 模拟向攻击者控制的服务器发送网络信标 (Beacon)。
-   **(TA0007) 发现**: 扫描文件系统，寻找符合特定扩展名的“有价值”文件。
-   **(TA0040) 影响**:
    -   使用 **AES-256 + RSA-2048** 混合加密算法对目标文件进行加密。
    -   在桌面和用户目录下投放勒索信。
    -   模拟修改桌面壁纸的行为。

---

## 2. 功能特性

-   **跨平台支持**: 可编译为 Windows, Linux 和 macOS 的原生可执行文件。
-   **高强度加密**: 采用 AES-256 (GCM 模式) 对文件加密，并使用从模拟 C2 服务器获取的 RSA-2048 公钥加密 AES 密钥，模拟真实攻击流程。
-   **并发加密**: 利用多核心 CPU 并发执行文件加密，模拟攻击的高效性。
-   **目标精准**: 允许用户通过命令行参数自定义要加密的文件扩展名。
-   **“演习模式” (Dry Run)**: 提供一个安全的 `-dry-run` 模式，该模式下程序只会扫描和列出将要被加密的文件，**不会执行任何实际的加密或破坏性操作**。
-   **单实例运行**: 通过创建互斥锁 (Windows) 或锁文件 (Linux/macOS) 防止程序重复运行。

---

## 3. 安装与编译

### 先决条件

-   安装 [Go 编程语言](https://go.dev/doc/install) (版本 1.18 或更高)。

### 编译步骤

1.  **克隆或下载项目**

    ```bash
    git clone https://your-repository-url/ransomware-simulator.git
    cd ransomware-simulator
    ```
    或者直接将 `ransom_simulator.go`, `lock_windows.go`, `lock_unix.go` 三个文件放在同一个目录下。

2.  **编译**

    根据你的目标平台，执行以下命令之一：

    -   **编译为 Linux 可执行文件:**
        ```bash
        GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator_linux .
        ```

    -   **编译为 Windows 可执行文件:**
        ```bash
        GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator.exe .
        ```

    -   **编译为 macOS (Intel) 可执行文件:**
        ```bash
        GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ransom_simulator_macos_intel .
        ```

    -   **编译为 macOS (Apple Silicon) 可执行文件:**
        ```bash
        GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ransom_simulator_macos_arm .
        ```

    > `-ldflags="-s -w"` 是一个可选参数，用于减小可执行文件的大小。

---

## 4. 使用方法

**强烈建议在虚拟机或隔离的沙箱环境中运行。**

### 命令行参数

```
用法: ./<executable_name> -ext .ext1,.ext2 [-workers N] [-dry-run] [-yes]

参数:
  -ext string
        必须：指定要加密的文件扩展名 (例: .db,.jpg,.txt)
  -workers int
        可选：并发 worker 数量 (默认: CPU核心数)
  -dry-run
        可选：演习模式，只查找不加密，安全无害
  -yes
        可选：跳过危险操作的确认提示（请谨慎使用）
```
### 执行密码

为了防止意外执行，程序启动时需要输入预设的密码。默认密码为: `yangzifun`

### 使用示例

**示例 1: 安全的演习模式**

扫描系统中所有的 `.txt` 和 `.log` 文件，但**不执行任何加密**。这是最推荐的初步测试方法。

```bash
./ransom_simulator_linux -ext .txt,.log -dry-run
```

**示例 2: 模拟真实攻击**

在**受控的测试虚拟机**中，加密所有的 `.doc`, `.docx`, 和 `.pdf` 文件。

1.  执行程序：
    ```bash
    ./ransom_simulator_linux -ext .doc,.docx,.pdf
    ```

2.  按提示输入执行密码。

3.  阅读警告信息，并输入 `YES` 确认执行。

4.  程序将开始全盘扫描并加密目标文件。

---

## 5. 免责声明

本项目遵循 MIT 许可证。请查阅 `LICENSE` 文件了解详情。

再次强调，此工具的创建旨在赋能防御者，而非赋能攻击者。请在法律和道德允许的范围内负责任地使用。

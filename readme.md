- # 勒索软件模拟器 (Ransomware Simulator)

  [![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat&logo=go)](https://golang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white) ![Version](https://img.shields.io/badge/Version−2.9-blue.svg)

  > **安全警告**：本工具仅用于网络安全培训和防御研究。禁止用于非法用途。使用前请确保在隔离环境中运行！

  

  ## 🚀 项目概述

  这是一个用于红队演练和防御研究的勒索软件模拟器，模拟真实勒索软件的行为模式，包括文件加密、勒索信生成、C2通信等关键攻击链环节。项目遵循MIT许可证，旨在帮助安全团队测试防御方案和进行安全意识培训。

  ## ✨ 主要功能

  ### 🔒 核心功能
  - **文件加密系统**：使用RSA-2048 + AES-256混合加密
  - **多平台支持**：Windows/Linux/macOS 全平台兼容
  - **并发加密处理**：多worker线程优化性能

  ### 📜 勒索系统
  - **多语言勒索信**：中/英文双语勒索模板
  - **智能投放机制**：每个加密目录自动投放勒索信
  - **壁纸修改模拟**：尝试修改系统壁纸增加影响

  ### 🛡️ 攻击链模拟
  - **服务停止攻击**：停止数据库、安全软件服务
  - **内存清理技术**：清理数据库缓存、系统内存
  - **进程守护解除**：停止守护进程和定时任务
  - **数据库攻击**：针对企业数据库的专项攻击

  ### 📊 日志与审计
  - **详细日志记录**：成功/失败文件分别记录
  - **操作过程追踪**：完整记录程序执行流程
  - **日志自动分类**：按程序目录输出日志文件

  ## 🏗️ 技术架构

  ```
  └── Linux/
  	├── ransom_simulator_linux.go    # Linux版
  └── Windows/
  	├── ransom_simulator_windows.go  # Windows版
  ├── decryptor.go                 # 解密工具
  ├── go.mod                       # Go模块依赖
  ├── go.sum                       # Go依赖校验
  ├── LICENSE                      # MIT许可证
  ├── readme.md                    # 项目文档
  └── workers/                     # C2服务器组件
      ├── bad-c2-server.js         # Cloudflare Worker实现的C2服务器
      └── rsauuid.js               # RSA 密钥接口
  ```

  ## 🚀 安装与使用

  ### 预编译二进制

  从[Releases页面](https://github.com/yangzifun/ransom_simulator/releases)下载对应平台的二进制文件：

  ```bash
  # Windows
  ransom_simulator.exe [参数]
  # Linux增强版
  ./ransom_simulator_linux_enhanced [参数]
  ```
  
  ### 从源码编译
  
  #### 编译步骤
  
  | **目标平台**            | **命令**                                                     | **输出文件**                                                 |
  | ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
  | **Linux增强版（64位）** | GOOS=linux GOARCH=amd64 go build -o ransom_simulator_linux ransom_simulator_linux.go<br/>GO_ENABLED=0 go build -o ransom_simulator_linux_static ransom_simulator_linux.go | ransom_simulator_linux_enhanced<br/>ransom_simulator_linux_static |
  | **Windows版（64位）**   | GOOS=windows GOARCH=amd64 go build -o ransom_simulator.exe ransom_simulator_windows.go | ransom_simulator_linux_enhanced                              |
  | **macOS版（Intel）**    | GOOS=darwin GOARCH=amd64 go build -o ransom_simulator_macos ransom_simulator_linux.go | ransom_simulator_macos                                       |
  
  > **提示**：Linux增强版包含更多攻击技术和日志功能，建议用于企业环境测试。
  
  ### 基本使用
  
  ```bash
  # 演习模式（不实际加密文件）
  ./ransom_simulator_linux_enhanced -dry-run
  # 启用日志功能
  ./ransom_simulator_linux_enhanced -log -dry-run
  # 指定工作线程数
  ./ransom_simulator_linux_enhanced -workers=8 -log
  # 加密特定目录并启用日志
  ./ransom_simulator_linux_enhanced -dir="/path/to/target" -log
  # 加密后删除原文件（危险！）
  ./ransom_simulator_linux_enhanced -remove -log
  ```
  
  ## ⚙️ 命令行参数详解
  
  | 参数     | 类型   | 描述                       | Windows 版本功能 | Linux增强功能 | 默认值       | 备注                       |
  | -------- | ------ | -------------------------- | ---------------- | ------------- | ------------ | -------------------------- |
  | -dir     | string | 指定攻击目标（目录或文件） | ✅                | ✅             | 系统根目录   | 逗号分隔多个目录           |
  | -ext     | string | 指定要加密的文件扩展名     | ✅                | ✅             | 预定义扩展名 | 如：.txt,.pdf,.docx        |
  | -workers | int    | 并发Worker线程数量         | ✅                | ✅             | CPU核心数    | 建议根据系统资源调整       |
  | -dry-run | bool   | 演习模式，不实际加密       | ✅                | ✅             | false        | 用于测试和演示             |
  | -remove  | bool   | 加密后删除原文件           | ✅                | ✅             | false        | 高危操作，谨慎使用         |
  | -log     | bool   | 启用日志功能               | ✅                | ✅             | false        | 日志文件输出到程序所在目录 |
  
  ## 🔐 密钥管理
  
  ### 本地密钥模式（推荐）
  
  **文件要求**：
  
  ```
  程序目录/
  ├── ransom_simulator_linux     # 可执行文件
  └── public_key_<uuid>.pem                # 公钥文件，例如：
      ├── public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem
  ```
  
  **公钥文件格式**：

  ```
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL6+M4l4R/6mZRZz9cLr
  ...
  -----END PUBLIC KEY-----
  ```
  
  **UUID自动提取**：
  
  - 程序会自动从公钥文件名中提取UUID
  - UUID格式：`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
  - 示例：`5137d4c3-3901-4528-bfa9-6d9ce88fa287`
  
  ## 🎯 使用场景示例
  
  ### 场景1：企业数据库攻击测试
  ```bash
  # 模拟对数据库服务器的攻击
  ./ransom_simulator_linux_enhanced -log -dir="/var/lib/mysql,/opt/oracle" -workers=4
  # 效果：停止数据库服务、清理内存缓存、加密数据库文件
  ```
  
  ### 场景2：安全防御演练
  ```bash
  # 测试安全软件的防护能力
  ./ransom_simulator_linux_enhanced -log -dry-run -ext=".conf,.key,.pem"
  # 效果：记录所有潜在攻击目标，不实际加密
  ```
  
  ### 场景3：日志审计测试
  ```bash
  # 测试日志系统的记录能力
  ./ransom_simulator_linux_enhanced -log -workers=2 -ext=".log,.txt"
  
  # 效果：生成详细日志文件，便于事后分析
  ```
  
  ### 场景4：内部红队演练
  
  ```
  # 企业内部安全测试
  ./ransom_simulator_linux_localonly -log -workers=2 -ext=".sql,.db,.bak"
  # 日志文件便于事后分析和汇报
  ```
  
  ## 🔧 技术细节
  
  ### 本地密钥模式优势

  1. **完全离线运行**：无需网络连接，可在隔离环境中使用
  2. **简化部署**：只需要一个公钥文件
  3. **UUID自动识别**：从文件名自动提取，无需额外配置文件
  4. **安全可控**：密钥完全由用户管理
  
  ### 新增攻击技术
  
  #### 1. 服务停止攻击
  - **数据库服务**：MySQL、PostgreSQL、MongoDB、Redis、Oracle
  - **安全软件**：阿里云安骑士、ClamAV、rkhunter、ossec
  - **监控工具**：Zabbix、Nagios、Cacti
  
  #### 2. 内存清理技术
  - **数据库缓存**：MySQL缓存刷新、PostgreSQL缓存清理
  - **系统内存**：页面缓存清理、目录项清理
  - **网络缓存**：ARP缓存、DNS缓存清理
  
  #### 3. 进程守护解除
  - **进程管理器**：systemd、init、upstart、supervisord
  - **定时任务**：cron、atd
  - **监控进程**：各种守护进程
  
  #### 4. 数据库链接解挂
  - **客户端进程**：mysql、psql、mongo、redis-cli
  - **网络连接**：关闭数据库端口（3306、5432等）
  - **链接清理**：杀死所有数据库连接
  
  ### 增强文件识别
  
  #### 新增支持格式：
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
  程序版本: v2.9-Beta-Linux-Enhanced-Logging
  开始时间: 2024-01-15 14:30:25
  运行参数: ./ransom_simulator_linux_enhanced -log -workers 4
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
  ./ransom_simulator_linux_enhanced -log \
    -dir="/var/lib/mysql,/opt/oracle,/home/project" \
    -workers=8 \
    -remove
  ```
  
  ### 防御演练
  ```bash
  # 测试防御系统的检测能力
  ./ransom_simulator_linux_enhanced -log \
    -dry-run \
    -ext=".sql,.db,.conf" \
    -workers=4
  ```
  
  ### 日志审计测试
  ```bash
  # 测试日志系统的完整性
  ./ransom_simulator_linux_enhanced -log \
    -workers=2 \
    -dir="/tmp/test_data"
  ```
  
  ## 🔍 模拟的关键攻击阶段 (MITRE ATT&CK®)
  
  | **Tactic (战术)** | **ID** | **新增模拟行为**                                             |
  | ----------------- | ------ | ------------------------------------------------------------ |
  | **防御规避**      | TA0005 | **服务停止攻击**：停止数据库和安全服务<br>**内存清理**：清理数据库缓存和系统内存<br>**进程守护解除**：停止守护进程和定时任务 |
  | **持久化**        | TA0003 | **增强互斥锁**：强制释放旧锁文件，自动重置状态               |
  | **发现**          | TA0007 | **增强文件识别**：支持数据库文件、配置文件、备份文件<br>**数据库发现**：自动扫描数据库数据目录 |
  | **横向移动**      | TA0008 | **数据库攻击**：终止数据库连接，解挂网络链接                 |
  | **影响**          | TA0040 | **增强加密目标**：针对企业关键资产的专项攻击<br>**详细日志记录**：完整攻击过程审计追踪 |
  
  ## 🔐 解密流程

  1. 访问解密门户：https://encrypt.yangzifun.org/
  
  2. 输入加密时生成的UUID
  
  3. 下载解密工具：
     ```bash
     # 解密单个文件
     decryptor -key=UUID -file=加密文件.encrypted
      
     # 批量解密目录
     decryptor -key=UUID -dir=加密文件目录
     ```
  
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
  - **解密工具**: https://encrypt.yangzifun.org/
  - **C2服务器**: Cloudflare Workers实现
  - **文档**: 完整技术文档和使用指南
  
  ---
  
  **最后提醒**：网络安全是共同责任，使用本工具时请始终遵循道德和法律准则。让我们共同建设更安全的网络环境！

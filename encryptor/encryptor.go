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
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

// --- 常量与类型定义 ---

const API_BASE_URL = "https://rsa-uuid.api.yangzifun.org"
const VERSION = "v1.1-go-cli"

// 默认安全路径（可自行修改）
// 当 --secret-path 和 SECRET_PATH 环境变量均未设置时使用此默认值
const DEFAULT_SECRET_PATH = "E56dSY"

// API 安全路径（通过 --secret-path 或 SECRET_PATH 环境变量设置）
var apiSecretPath string

type APIResponse struct {
	PublicKeyPEM  string `json:"public_key_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	UUID          string `json:"uuid"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

type fileLog struct { // (与之前版本相同)
	mu   sync.Mutex
	file *os.File
}

type counters struct { // 用于统计任务结果
	success uint64
	failed  uint64
	skipped uint64
}

// --- 主逻辑 ---

func main() {
	// 1. 增强的命令行参数定义
	// 使用 flag.NewFlagSet 创建自定义的帮助信息
	fs := flag.NewFlagSet("encryptor_cli", flag.ExitOnError)
	extFlag := fs.String("ext", "", "可选：只加密指定扩展名的文件，用逗号分隔 (例: .txt,.jpg)")
	workersFlag := fs.Int("workers", runtime.NumCPU(), "可选：指定并发执行的 worker 数量")
	secretPathFlag := fs.String("secret-path", "", fmt.Sprintf("可选：API 安全路径（需与 Worker 配置一致，默认: %s）", DEFAULT_SECRET_PATH))

	// 自定义 Usage 函数，提供更丰富的帮助信息
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "RSA 密钥混合加密工具 - 版本: %s\n", VERSION)
		fmt.Fprintln(os.Stderr, "----------------------------------------------------")
		fmt.Fprintln(os.Stderr, "本工具可以加密指定的文件，或递归加密指定文件夹下的所有文件。")
		fmt.Fprintln(os.Stderr, "每个成功加密的文件都会生成一个独立的密钥对和UUID。")
		fmt.Fprintln(os.Stderr, "\n用法:")
		fmt.Fprintf(os.Stderr, "  %s [选项] <文件/文件夹路径1> [<文件/文件夹路径2> ...]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "\n选项:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n示例:")
		fmt.Fprintf(os.Stderr, "  # 加密单个文件\n")
		fmt.Fprintf(os.Stderr, "  %s my_secret.txt\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # 加密整个 'documents' 文件夹\n")
		fmt.Fprintf(os.Stderr, "  %s ./documents\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # 只加密 'photos' 文件夹中的 .jpg 和 .png 文件\n")
		fmt.Fprintf(os.Stderr, "  %s -ext .jpg,.png ./photos\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # 使用 8 个并发 worker 加密多个目标\n")
		fmt.Fprintf(os.Stderr, "  %s -workers 8 report.docx project_folder/\n", os.Args[0])
	}

	fs.Parse(os.Args[1:]) // 从 os.Args[1:] 解析参数

	// 设置安全路径：优先级 命令行参数 > 环境变量 > 默认值
	apiSecretPath = *secretPathFlag
	if apiSecretPath == "" {
		apiSecretPath = os.Getenv("SECRET_PATH")
	}
	if apiSecretPath == "" {
		apiSecretPath = DEFAULT_SECRET_PATH
	}
	fmt.Printf("安全路径已配置，将通过 %s/%s 访问 API\n", API_BASE_URL, apiSecretPath)

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 至少需要指定一个文件或文件夹路径。")
		fs.Usage()
		os.Exit(1)
	}

	fmt.Println("RSA 密钥混合加密工具 - 版本:", VERSION)
	fmt.Println("----------------------------------------------------")

	// 2. 解析扩展名过滤器
	extFilter := make(map[string]bool)
	if *extFlag != "" {
		extensions := strings.Split(*extFlag, ",")
		for _, ext := range extensions {
			trimmedExt := strings.TrimSpace(ext)
			if !strings.HasPrefix(trimmedExt, ".") {
				trimmedExt = "." + trimmedExt
			}
			extFilter[trimmedExt] = true
		}
		fmt.Printf("筛选器已激活：将只处理扩展名为 [%s] 的文件。\n", *extFlag)
	}

	// 3. 查找所有待加密的文件
	fmt.Println("正在扫描路径并查找待加密的文件...")
	var filesToProcess []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "警告：路径 '%s' 不存在，已跳过。\n", path)
			continue
		}
		if info.IsDir() {
			filepath.Walk(path, func(filePath string, fileInfo os.FileInfo, err error) error {
				if err == nil && !fileInfo.IsDir() && shouldEncrypt(filePath, extFilter) {
					filesToProcess = append(filesToProcess, filePath)
				}
				return nil
			})
		} else {
			if shouldEncrypt(path, extFilter) {
				filesToProcess = append(filesToProcess, path)
			}
		}
	}

	if len(filesToProcess) == 0 {
		fmt.Println("未找到任何需要加密的文件。程序退出。")
		os.Exit(0)
	}

	fmt.Printf("扫描完成！共找到 %d 个文件待加密。\n", len(filesToProcess))
	fmt.Println("----------------------------------------------------")

	// 4. 设置并发处理
	var wg sync.WaitGroup
	var stats counters
	jobs := make(chan string, len(filesToProcess))

	// 启动 worker Goroutines
	numWorkers := *workersFlag
	fmt.Printf("启动 %d 个并发 worker 开始加密任务...\n", numWorkers)
	for w := 0; w < numWorkers; w++ {
		go worker(w+1, jobs, &wg, &stats)
	}

	// 5. 将任务推送到 channel
	for _, file := range filesToProcess {
		jobs <- file
	}
	close(jobs)

	// 6. 等待所有任务完成
	wg.Add(len(filesToProcess))
	wg.Wait()

	// 7. 打印最终总结报告
	fmt.Println("----------------------------------------------------")
	fmt.Println("所有加密任务已完成！")
	fmt.Println("\n加密结果总结:")
	fmt.Printf("  - 成功: %d\n", stats.success)
	fmt.Printf("  - 失败: %d\n", stats.failed)
	fmt.Printf("  - 跳过 (因扩展名不匹配): %d\n", stats.skipped) // (此逻辑简化，实际在扫描阶段就过滤了)
	fmt.Println("\nUUID 记录已保存到 readme.txt 文件中。")
}

// worker 是执行加密任务的goroutine
func worker(id int, jobs <-chan string, wg *sync.WaitGroup, stats *counters) {
	defer func() {
		// 确保即使发生 panic (理论上不应有)，也能正确减少 WaitGroup 计数
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[Worker %d] FATAL: 发生 panic: %v\n", id, r)
			atomic.AddUint64(&stats.failed, 1)
			wg.Done()
		}
	}()

	logger, err := newFileLog("readme.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Worker %d] 警告: 无法打开日志文件: %v。UUID将不会被记录。\n", id, err)
	}
	if logger != nil {
		defer logger.Close()
	}

	for filePath := range jobs {
		err := processFile(filePath, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] 失败: '%s' -> %v\n", filePath, err)
			atomic.AddUint64(&stats.failed, 1) // 原子操作，保证并发安全
		} else {
			atomic.AddUint64(&stats.success, 1)
		}
		wg.Done()
	}
}

// processFile 包含对单个文件的完整加密流程 (微调输出)
func processFile(inputFile string, logger *fileLog) error {
	apiRes, err := fetchKeysFromAPI()
	if err != nil {
		return fmt.Errorf("获取密钥失败: %w", err)
	}

	publicKey, err := parsePublicKey(apiRes.PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %w", err)
	}

	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	encryptedKeyBase64, encryptedDataBase64, err := hybridEncrypt(plaintext, publicKey)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}

	var outputContent strings.Builder
	outputContent.WriteString("---BEGIN_AES_KEY---\n" + encryptedKeyBase64 + "\n---END_AES_KEY---\n")
	outputContent.WriteString("---BEGIN_ENCRYPTED_DATA---\n" + encryptedDataBase64 + "\n---END_ENCRYPTED_DATA---\n")
	outputContent.WriteString("---END_ENCRYPTED_FILE_AND_KEY---\n")

	outputFile := inputFile + ".enc"
	if err = os.WriteFile(outputFile, []byte(outputContent.String()), 0644); err != nil {
		return fmt.Errorf("写入加密文件失败: %w", err)
	}

	fmt.Printf("[+] 成功: '%s' -> '%s' (UUID: %s)\n", inputFile, outputFile, apiRes.UUID)

	if logger != nil {
		logger.Log(outputFile, apiRes.UUID)
	}
	return nil
}

// ... 此处省略 shouldEncrypt, newFileLog, Log, Close, fetchKeysFromAPI, parsePublicKey, hybridEncrypt 函数 ...
// ... 它们与上一个版本基本相同，请直接从之前的代码中复制过来 ...
// 为了代码完整性，我再次贴出它们，并做微小调整

func shouldEncrypt(filePath string, extFilter map[string]bool) bool {
	if len(extFilter) == 0 {
		return true
	}
	return extFilter[filepath.Ext(filePath)]
}

func newFileLog(filename string) (*fileLog, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &fileLog{file: f}, nil
}

func (l *fileLog) Log(filename, uuid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	logMessage := fmt.Sprintf("加密的文件名称：%s : %s\n", filepath.Base(filename), uuid)
	if _, err := l.file.WriteString(logMessage); err != nil {
		fmt.Fprintf(os.Stderr, "警告：写入日志到 %s 失败: %v\n", l.file.Name(), err)
	}
}

func (l *fileLog) Close() { l.file.Close() }

func fetchKeysFromAPI() (*APIResponse, error) {
	// 拼接 API URL：如果有安全路径，则添加到 URL 路径中
	apiURL := API_BASE_URL
	if apiSecretPath != "" {
		apiURL = strings.TrimRight(API_BASE_URL, "/") + "/" + strings.TrimLeft(apiSecretPath, "/")
	}
	resp, err := http.Post(apiURL, "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		return nil, fmt.Errorf("API请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取API响应失败: %w", err)
	}
	var apiRes APIResponse
	if err := json.Unmarshal(body, &apiRes); err != nil {
		return nil, fmt.Errorf("解析API响应JSON失败: %w。原始响应: %s", err, string(body))
	}
	if apiRes.Status == "error" {
		return nil, fmt.Errorf("API返回错误: %s", apiRes.Message)
	}
	if apiRes.PublicKeyPEM == "" || apiRes.PrivateKeyPEM == "" || apiRes.UUID == "" {
		return nil, fmt.Errorf("API响应中缺少密钥或UUID。原始响应: %s", string(body))
	}
	return &apiRes, nil
}

func parsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解码PEM块")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("无法解析公钥: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("获取到的密钥不是RSA公钥")
	}
	return rsaPub, nil
}

func hybridEncrypt(plaintext []byte, publicKey *rsa.PublicKey) (string, string, error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", "", fmt.Errorf("生成AES密钥失败: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", fmt.Errorf("创建AES cipher失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("创建GCM模式失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("生成nonce失败: %w", err)
	}
	encryptedData := gcm.Seal(nonce, nonce, plaintext, nil)
	encryptedDataBase64 := base64.StdEncoding.EncodeToString(encryptedData)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return "", "", fmt.Errorf("RSA加密AES密钥失败: %w", err)
	}
	encryptedKeyBase64 := base64.StdEncoding.EncodeToString(encryptedKey)
	return encryptedKeyBase64, encryptedDataBase64, nil
}

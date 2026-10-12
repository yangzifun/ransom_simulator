// decryptor.go
// 解密器主程序

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// RSA密钥的位数，必须与加密时使用的密钥大小一致
	rsaKeyBits = 2048
	// 加密后的AES密钥长度（等于RSA密钥字节数）
	encryptedKeyLength = rsaKeyBits / 8
	// AES-GCM的Nonce大小（固定为12字节）
	nonceSize = 12
	// 加密文件后缀
	encryptedFileSuffix = ".encrypted"
	// PENC格式魔法头
	pencMagic = "PENC"
)

// encryptedChunk 描述部分加密中的一个数据块（与加密器定义一致）
type encryptedChunk struct {
	Offset int64  `json:"offset"`
	Size   int    `json:"size"`
	Nonce  []byte `json:"nonce"`
	Data   []byte `json:"data"`
}

// fileEntry 表示一个待处理的加密文件条目（用于 dry-run 列表）
type fileEntry struct {
	Path      string
	OrigPath  string
	Format    string // "full" 或 "partial"
	FileSize  int64
}

// decryptFile 是核心解密函数，处理单个文件
func decryptFile(filePath string, privateKey *rsa.PrivateKey, removeAfterDecrypt bool, verbose bool) error {
	// 1. 读取整个加密文件内容
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// 2. 检测文件格式：PENC魔法头 = 大文件部分加密，否则 = 小文件完整加密
	if len(encryptedData) >= 4 && string(encryptedData[:4]) == pencMagic {
		if verbose {
			log.Printf("  [PENC] Detected partial encryption format for: %s", filePath)
		}
		return partialDecryptFile(filePath, encryptedData, privateKey, removeAfterDecrypt, verbose)
	}

	// 3. 小文件完整加密路径：验证文件大小是否合法
	if len(encryptedData) < encryptedKeyLength+nonceSize {
		return fmt.Errorf("invalid encrypted file format or size")
	}

	// 4. 分离数据块：[加密的AES密钥][Nonce][文件密文]
	encryptedAESKey := encryptedData[:encryptedKeyLength]
	nonce := encryptedData[encryptedKeyLength : encryptedKeyLength+nonceSize]
	ciphertext := encryptedData[encryptedKeyLength+nonceSize:]

	// 5. 使用RSA私钥解密AES密钥
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// 6. 使用解密出的AES密钥解密文件内容
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM instance: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt file content (authentication failed): %w", err)
	}

	// 7. 构造原始文件名并写入解密后的内容
	originalFilePath := strings.TrimSuffix(filePath, encryptedFileSuffix)
	fileMode := detectFileMode(originalFilePath)
	err = os.WriteFile(originalFilePath, plaintext, fileMode)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	// 8. 如果设置了 -remove, 则删除源加密文件
	if removeAfterDecrypt {
		if err := os.Remove(filePath); err != nil {
			log.Printf("Warning: Failed to remove encrypted file %s: %v", filePath, err)
		}
	}

	if verbose {
		log.Printf("Decrypted: %s -> %s", filePath, originalFilePath)
	}
	return nil
}

// partialDecryptFile 解密大文件部分加密格式（PENC格式）
// 格式: [4字节 magic "PENC"][4字节 chunks JSON长度][chunks JSON][4字节 加密AES密钥长度][加密AES密钥][所有加密块数据]
func partialDecryptFile(filePath string, data []byte, privateKey *rsa.PrivateKey, removeAfterDecrypt bool, verbose bool) error {
	if len(data) < 4+4 {
		return fmt.Errorf("PENC format too short: missing chunks metadata")
	}

	// 解析 chunks JSON 长度
	chunksLen := binary.LittleEndian.Uint32(data[4:8])
	jsonStart := 8
	jsonEnd := 8 + int(chunksLen)
	if jsonEnd > len(data) {
		return fmt.Errorf("PENC format corrupted: chunks metadata exceeds file size")
	}

	// 解析 chunks JSON
	chunksJSON := data[jsonStart:jsonEnd]
	var chunks []encryptedChunk
	if err := json.Unmarshal(chunksJSON, &chunks); err != nil {
		return fmt.Errorf("failed to parse chunks metadata: %w", err)
	}

	// 解析加密AES密钥长度
	keyOffset := jsonEnd
	if keyOffset+4 > len(data) {
		return fmt.Errorf("PENC format corrupted: missing key metadata")
	}
	keyLen := binary.LittleEndian.Uint32(data[keyOffset : keyOffset+4])
	keyStart := keyOffset + 4
	keyEnd := keyStart + int(keyLen)
	if keyEnd > len(data) {
		return fmt.Errorf("PENC format corrupted: encrypted key exceeds file size")
	}

	// 解密AES密钥
	encryptedAESKey := data[keyStart:keyEnd]
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt AES key (PENC): %w", err)
	}

	// 创建AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block (PENC): %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM instance (PENC): %w", err)
	}

	// 所有加密块数据起始位置
	chunkDataStart := keyEnd

	// 打开原始文件（即去掉 .encrypted 后缀的文件）进行原地写入
	originalFilePath := strings.TrimSuffix(filePath, encryptedFileSuffix)
	f, err := os.OpenFile(originalFilePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file for writing: %w", err)
	}
	defer f.Close()

	// 逐个解密数据块并写回原位置
	currentOffset := chunkDataStart
	for i, chunk := range chunks {
		if currentOffset+len(chunk.Data) > len(data) {
			return fmt.Errorf("PENC format corrupted: chunk %d data exceeds file size", i)
		}

		// 解密该块
		plaintext, err := aesgcm.Open(nil, chunk.Nonce, data[currentOffset:currentOffset+len(chunk.Data)], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d (offset=%d, size=%d): %w", i, chunk.Offset, chunk.Size, err)
		}

		// 写回原文件中的对应位置
		if _, err := f.WriteAt(plaintext, chunk.Offset); err != nil {
			return fmt.Errorf("failed to write chunk %d to output file: %w", i, err)
		}

		currentOffset += len(chunk.Data)
		if verbose {
			log.Printf("  [PENC] Decrypted chunk %d/%d at offset=%d", i+1, len(chunks), chunk.Offset)
		}
	}

	// 调整文件权限
	fileMode := detectFileMode(originalFilePath)
	if chmodErr := os.Chmod(originalFilePath, fileMode); chmodErr != nil {
		log.Printf("Warning: Failed to set file mode for %s: %v", originalFilePath, chmodErr)
	}

	// 如果设置了 -remove, 删除加密文件
	if removeAfterDecrypt {
		if err := os.Remove(filePath); err != nil {
			log.Printf("Warning: Failed to remove encrypted file %s: %v", filePath, err)
		}
	}

	if verbose {
		log.Printf("Decrypted (PENC): %s -> %s (%d chunks)", filePath, originalFilePath, len(chunks))
	}
	return nil
}

// detectFileMode 根据文件扩展名判断应有的权限
// 可执行文件返回 0755，其余返回 0644
func detectFileMode(filePath string) os.FileMode {
	ext := strings.ToLower(filepath.Ext(filePath))
	executableExts := map[string]bool{
		".sh":   true,
		".bash": true,
		".exe":  true,
		".bin":  true,
		".run":  true,
		".out":  true,
		".app":  true,
	}
	if executableExts[ext] {
		return 0755
	}
	// 检查文件路径是否包含 "bin/" 等可执行目录
	lower := strings.ToLower(filePath)
	if strings.Contains(lower, "/bin/") || strings.Contains(lower, "/sbin/") ||
		strings.Contains(lower, "\\bin\\") || strings.Contains(lower, "\\sbin\\") {
		return 0755
	}
	return 0644
}

// loadPrivateKey 从PEM文件中加载RSA私钥（支持PKCS#1和PKCS#8格式）
func loadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}

	block, rest := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// 检查是否有意外的额外数据
	if len(rest) > 0 && len(strings.TrimSpace(string(rest))) > 0 {
		log.Printf("Warning: private key file contains extra data after PEM block, ignoring")
	}

	// 尝试 PKCS#1 格式 (RSA PRIVATE KEY)
	if block.Type == "RSA PRIVATE KEY" {
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
		return privateKey, nil
	}

	// 尝试 PKCS#8 格式 (PRIVATE KEY)
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PEM block does not contain an RSA private key (got %T)", key)
		}
		return privateKey, nil
	}

	// 尝试 EC PRIVATE KEY（转换为通用处理）
	if block.Type == "EC PRIVATE KEY" {
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return nil, fmt.Errorf("EC private key is not supported (RSA required), got EC key with curve %v", key.Curve)
	}

	return nil, fmt.Errorf("unexpected PEM block type '%s': expected 'RSA PRIVATE KEY' or 'PRIVATE KEY'", block.Type)
}

// scanEncryptedFiles 扫描目录中的加密文件，返回文件条目列表
func scanEncryptedFiles(targetDir string) ([]fileEntry, error) {
	var entries []fileEntry

	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("Warning: cannot access path %q: %v", path, err)
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), encryptedFileSuffix) {
			entry := fileEntry{
				Path:     path,
				OrigPath: strings.TrimSuffix(path, encryptedFileSuffix),
				Format:   "full",
			}
			if info, statErr := d.Info(); statErr == nil {
				entry.FileSize = info.Size()
			}

			// 检测格式：读取前4字节判断是否为PENC
			if info, statErr := d.Info(); statErr == nil && info.Size() >= 4 {
				f, openErr := os.Open(path)
				if openErr == nil {
					magic := make([]byte, 4)
					if n, _ := f.Read(magic); n == 4 && string(magic) == pencMagic {
						entry.Format = "partial"
					}
					f.Close()
				}
			}

			entries = append(entries, entry)
		}
		return nil
	})

	return entries, err
}

// formatFileSize 格式化文件大小为可读字符串
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func main() {
	// --- 命令行参数定义 ---
	keyFile := flag.String("key-file", "", "Path to the RSA private key PEM file (required)")
	targetDir := flag.String("dir", ".", "Directory to scan for encrypted files (default: current directory)")
	removeEncrypted := flag.Bool("remove", false, "Remove the .encrypted file after successful decryption")
	workers := flag.Int("workers", 4, "Number of concurrent decryption workers")
	dryRun := flag.Bool("dry-run", false, "Dry-run mode: scan and list encrypted files without decrypting")
	verbose := flag.Bool("verbose", false, "Enable verbose output for each file")
	flag.Parse()

	// --- 参数校验 ---
	if *keyFile == "" && !*dryRun {
		log.Println("Error: -key-file argument is required.")
		flag.Usage()
		os.Exit(1)
	}

	// --- 扫描文件 ---
	log.Printf("Scanning directory '%s' for encrypted files...", *targetDir)
	startTime := time.Now()

	entries, err := scanEncryptedFiles(*targetDir)
	if err != nil {
		log.Fatalf("Fatal: Error walking the path %q: %v", *targetDir, err)
	}

	if len(entries) == 0 {
		log.Println("No encrypted files found.")
		os.Exit(0)
	}

	// --- Dry-run 模式：仅列出文件 ---
	if *dryRun {
		log.Println("=== DRY RUN MODE - No files will be decrypted ===")
		log.Printf("Found %d encrypted file(s):\n", len(entries))
		var fullCount, partialCount int
		var totalSize int64
		for _, entry := range entries {
			fmt.Printf("  [%s] %s -> %s (%s)\n", entry.Format, entry.Path, entry.OrigPath, formatFileSize(entry.FileSize))
			if entry.Format == "full" {
				fullCount++
			} else {
				partialCount++
			}
			totalSize += entry.FileSize
		}
		log.Printf("Summary: %d full, %d partial, total %s", fullCount, partialCount, formatFileSize(totalSize))
		log.Println("Use without -dry-run to perform actual decryption.")
		os.Exit(0)
	}

	// --- 加载私钥 ---
	log.Println("Loading RSA private key...")
	privateKey, err := loadPrivateKey(*keyFile)
	if err != nil {
		log.Fatalf("Fatal: %v", err)
	}
	log.Println("Private key loaded successfully.")

	// --- 并发设置 ---
	var wg sync.WaitGroup
	filesChan := make(chan string, *workers*2)

	// 启动指定数量的worker goroutine
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				if err := decryptFile(filePath, privateKey, *removeEncrypted, *verbose); err != nil {
					log.Printf("ERROR decrypting %s: %v", filePath, err)
				}
			}
		}()
	}

	// --- 发送文件到工作队列 ---
	var fileCount int64
	for _, entry := range entries {
		filesChan <- entry.Path
		fileCount++
	}

	close(filesChan)
	wg.Wait()

	duration := time.Since(startTime)
	log.Printf("Decryption complete. Processed %d files in %v.", fileCount, duration)
}
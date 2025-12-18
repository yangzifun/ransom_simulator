// decryptor.go
package main

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
	// 加密文件后缀
	encryptedFileSuffix = ".encrypted"
)

// decryptFile 是核心解密函数，处理单个文件
func decryptFile(filePath string, privateKey *rsa.PrivateKey, removeAfterDecrypt bool) error {
	// 1. 读取整个加密文件内容
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// 2. 验证文件大小是否合法
	// 必须至少包含：RSA加密的AES密钥 + Nonce
	// AES-GCM的Nonce大小从AEAD接口获取，更具鲁棒性
	tempCipher, _ := aes.NewCipher(make([]byte, 32)) // 临时创建一个cipher以获取nonce size
	gcm, _ := cipher.NewGCM(tempCipher)
	nonceSize := gcm.NonceSize()

	if len(encryptedData) < encryptedKeyLength+nonceSize {
		return fmt.Errorf("invalid encrypted file format or size")
	}

	// 3. 分离数据块：[加密的AES密钥][Nonce][文件密文]
	encryptedAESKey := encryptedData[:encryptedKeyLength]
	nonce := encryptedData[encryptedKeyLength : encryptedKeyLength+nonceSize]
	ciphertext := encryptedData[encryptedKeyLength+nonceSize:]

	// 4. 使用RSA私钥解密AES密钥
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedAESKey, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// 5. 使用解密出的AES密钥解密文件内容
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
		// 常见错误：密钥不匹配或密文被篡改
		return fmt.Errorf("failed to decrypt file content (authentication failed): %w", err)
	}

	// 6. 构造原始文件名并写入解密后的内容
	originalFilePath := strings.TrimSuffix(filePath, encryptedFileSuffix)
	err = os.WriteFile(originalFilePath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	// (可选) 7. 如果设置了 -remove, 则删除源加密文件
	if removeAfterDecrypt {
		if err := os.Remove(filePath); err != nil {
			log.Printf("Warning: Failed to remove encrypted file %s: %v", filePath, err)
		}
	}

	log.Printf("Decrypted: %s -> %s", filePath, originalFilePath)
	return nil
}

// loadPrivateKey 从PEM文件中加载RSA私钥
func loadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected 'RSA PRIVATE KEY', got '%s'", block.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
	}

	return privateKey, nil
}

func main() {
	// --- 命令行参数定义 ---
	keyFile := flag.String("key-file", "", "Path to the RSA private key PEM file (required)")
	targetDir := flag.String("dir", ".", "Directory to scan for encrypted files (default: current directory)")
	removeEncrypted := flag.Bool("remove", false, "Remove the .encrypted file after successful decryption")
	workers := flag.Int("workers", 4, "Number of concurrent decryption workers")
	flag.Parse()

	// --- 参数校验 ---
	if *keyFile == "" {
		log.Println("Error: -key-file argument is required.")
		flag.Usage()
		os.Exit(1)
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
	filesChan := make(chan string, *workers*2) // 带缓冲的channel

	// 启动指定数量的worker goroutine
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range filesChan {
				if err := decryptFile(filePath, privateKey, *removeEncrypted); err != nil {
					log.Printf("ERROR decrypting %s: %v", filePath, err)
				}
			}
		}()
	}

	// --- 扫描文件 ---
	log.Printf("Scanning directory '%s' for encrypted files...", *targetDir)
	startTime := time.Now()
	var fileCount int64

	err = filepath.WalkDir(*targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("Warning: cannot access path %q: %v", path, err)
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), encryptedFileSuffix) {
			filesChan <- path
			fileCount++
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Fatal: Error walking the path %q: %v", *targetDir, err)
	}

	close(filesChan) // 所有文件名已发送完毕，关闭channel
	wg.Wait()        // 等待所有worker完成工作

	duration := time.Since(startTime)
	log.Printf("Decryption complete. Processed %d files in %v.", fileCount, duration)
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKeyPEM 测试用合法 RSA 公钥（进程启动时生成一次）。
var testKeyPEM []byte

func TestMain(m *testing.M) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	testKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	os.Exit(m.Run())
}

func writeTestKey(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), testKeyPEM, 0600); err != nil {
		t.Fatalf("写入测试公钥失败: %v", err)
	}
}

// withProgramDir 临时把 programDir 指向测试目录。
func withProgramDir(t *testing.T, dir string) {
	t.Helper()
	old := programDir
	programDir = dir
	t.Cleanup(func() { programDir = old })
}

// withIsolatedKeyCache 把用户级密钥缓存目录重定向到临时目录，避免读到宿主机真实缓存。
func withIsolatedKeyCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "")
}

func TestLoadLocalKeyStrictName(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem")
	withProgramDir(t, dir)

	uuid, pemText, path, err := loadLocalKey()
	if err != nil {
		t.Fatalf("期望加载成功，实际失败: %v", err)
	}
	if uuid != "5137d4c3-3901-4528-bfa9-6d9ce88fa287" {
		t.Fatalf("UUID 提取错误: %s", uuid)
	}
	if !strings.Contains(pemText, "BEGIN PUBLIC KEY") {
		t.Fatalf("公钥内容异常: %q", pemText)
	}
	if filepath.Base(path) != "public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem" {
		t.Fatalf("文件路径异常: %s", path)
	}
}

func TestLoadLocalKeyRelaxedNames(t *testing.T) {
	for _, name := range []string{"public_key.pem", "mykey.pem", "server.PEM"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestKey(t, dir, name)
			withProgramDir(t, dir)

			uuid, _, _, err := loadLocalKey()
			if err != nil {
				t.Fatalf("期望加载成功，实际失败: %v", err)
			}
			if !isValidUUID(uuid) {
				t.Fatalf("为无 UUID 文件名生成的 ID 不合法: %s", uuid)
			}
		})
	}
}

func TestLoadLocalKeyStrictNameWins(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "mykey.pem")
	writeTestKey(t, dir, "public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem")
	withProgramDir(t, dir)

	uuid, _, path, err := loadLocalKey()
	if err != nil {
		t.Fatalf("期望加载成功，实际失败: %v", err)
	}
	if uuid != "5137d4c3-3901-4528-bfa9-6d9ce88fa287" || filepath.Base(path) != "public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem" {
		t.Fatalf("应优先使用严格命名文件，实际: %s / %s", uuid, path)
	}
}

func TestLoadLocalKeyNone(t *testing.T) {
	dir := t.TempDir()
	withProgramDir(t, dir)
	withIsolatedKeyCache(t)

	_, _, _, err := loadLocalKey()
	if err == nil {
		t.Fatal("空目录下不应找到公钥")
	}
	if !strings.Contains(err.Error(), "未找到可用公钥") {
		t.Fatalf("错误信息缺少可操作提示: %v", err)
	}
}

func TestLoadLocalKeySkipsInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "public_key_broken.pem"), []byte("not a pem"), 0600); err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, dir, "public_key.pem")
	withProgramDir(t, dir)

	_, _, path, err := loadLocalKey()
	if err != nil {
		t.Fatalf("期望跳过损坏文件并加载可用公钥，实际失败: %v", err)
	}
	if filepath.Base(path) != "public_key.pem" {
		t.Fatalf("应优先使用 public_key 前缀的文件，实际: %s", path)
	}
}

func TestUuidFromPublicKeyStable(t *testing.T) {
	pub, err := parseRSAPublicKey(testKeyPEM)
	if err != nil {
		t.Fatalf("测试公钥无法解析: %v", err)
	}
	first := uuidFromPublicKey(pub)
	if second := uuidFromPublicKey(pub); first != second {
		t.Fatalf("同一公钥两次生成 UUID 不一致: %s / %s", first, second)
	}
	if !isValidUUID(first) {
		t.Fatalf("生成的 UUID 不合法: %s", first)
	}
}

// TestAcquireKeysOfflineFallback 验证断网时 acquireKeys 直接回退本地公钥。
func TestAcquireKeysOfflineFallback(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem")
	withProgramDir(t, dir)
	withIsolatedKeyCache(t)

	uuid, pemText, source, err := acquireKeys()
	if err != nil {
		t.Fatalf("断网时应回退本地密钥，实际失败: %v", err)
	}
	if uuid != "5137d4c3-3901-4528-bfa9-6d9ce88fa287" {
		t.Fatalf("回退 UUID 错误: %s", uuid)
	}
	if !strings.Contains(pemText, "BEGIN PUBLIC KEY") {
		t.Fatal("回退公钥内容异常")
	}
	if source != "本地公钥文件" {
		t.Fatalf("来源标识错误: %s", source)
	}
}

// TestAcquireKeysOfflineNoKey 验证断网且无本地公钥时返回可读错误（不再直接 os.Exit）。
func TestAcquireKeysOfflineNoKey(t *testing.T) {
	dir := t.TempDir()
	withProgramDir(t, dir)
	withIsolatedKeyCache(t)

	if _, _, _, err := acquireKeys(); err == nil {
		t.Fatal("断网且无本地公钥时应返回错误")
	} else if !strings.Contains(err.Error(), "本地回退失败") {
		t.Fatalf("错误信息应说明本地回退失败: %v", err)
	}
}

// TestCachePublicKeyCopy 验证联网成功后公钥副本会落到用户级缓存目录。
func TestCachePublicKeyCopy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	uuid := "5137d4c3-3901-4528-bfa9-6d9ce88fa287"
	cachePublicKeyCopy(uuid, string(testKeyPEM))

	cached := filepath.Join(dir, "RansomSimulator", "keys", "public_key_"+uuid+".pem")
	data, err := os.ReadFile(cached)
	if err != nil {
		t.Fatalf("缓存文件未写入: %v", err)
	}
	if string(data) != string(testKeyPEM) {
		t.Fatal("缓存内容与下发公钥不一致")
	}
}

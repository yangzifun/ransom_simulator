package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResidentAndKeepKeyFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	opt := setupFlags(fs)
	if err := fs.Parse([]string{"-resident", "-keep-key", "-dry-run"}); err != nil {
		t.Fatalf("解析参数失败: %v", err)
	}
	if !opt.resident {
		t.Fatal("-resident 未生效")
	}
	if !opt.keepKey {
		t.Fatal("-keep-key 未生效")
	}
	if !opt.dryRun {
		t.Fatal("-dry-run 未生效")
	}
}

func TestPersistKeyCache(t *testing.T) {
	programTemp := t.TempDir()
	userTemp := t.TempDir()
	withProgramDir(t, programTemp)
	t.Setenv("AppData", userTemp)

	uuid := "5137d4c3-3901-4528-bfa9-6d9ce88fa287"
	path, err := persistKeyCache(uuid, string(testKeyPEM), "attack", true)
	if err != nil {
		t.Fatalf("写入密钥缓存失败: %v", err)
	}
	if filepath.Dir(path) != programTemp {
		t.Fatalf("首选缓存路径应在程序目录，实际: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取缓存失败: %v", err)
	}
	var record keyCacheRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("缓存 JSON 解析失败: %v", err)
	}
	if record.UUID != uuid {
		t.Fatalf("UUID 字段错误: %s", record.UUID)
	}
	if !strings.Contains(record.PublicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Fatal("缓存中缺少公钥 PEM")
	}
	if record.Mode != "attack" || !record.RemoveOriginal {
		t.Fatalf("元数据错误: mode=%s remove=%v", record.Mode, record.RemoveOriginal)
	}
	if record.CreatedAt == "" || record.Version != version {
		t.Fatalf("创建时间/版本缺失: %q %q", record.CreatedAt, record.Version)
	}

	userCopy := filepath.Join(userTemp, "RansomSimulator", "keys", "key_cache_"+uuid+".json")
	if _, err := os.Stat(userCopy); err != nil {
		t.Fatalf("用户级缓存副本缺失: %v", err)
	}
}

func TestPersistKeyCacheRejectsEmpty(t *testing.T) {
	withProgramDir(t, t.TempDir())
	if _, err := persistKeyCache("", string(testKeyPEM), "attack", false); err == nil {
		t.Fatal("空 UUID 应返回错误")
	}
	if _, err := persistKeyCache("uuid", "  ", "attack", false); err == nil {
		t.Fatal("空公钥应返回错误")
	}
}

func TestIsProtectedArtifact(t *testing.T) {
	cases := map[string]bool{
		ransomNoteFileName:                             true,
		ransomWallpaperFileName:                        true,
		"public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem": true,
		"public_key.pem":                               true,
		"key_cache_5137d4c3.json":                      true,
		"recon_report_20260101_000000.json":            true,
		"remote_report_20260101_000000.json":           true,
		"ransom_log.txt":                               true,
		"operations.log":                               true,
		"success_encrypted.log":                        true,
		"failed_encrypted.log":                         true,
		"ransom_simulator_instance.lock":               true,
		"document.docx.encrypted":                      true,
		"document.docx":                                false,
		"notes.txt":                                    false,
		"key_cache_data.txt":                           false,
		"my_public_key.pem":                            false,
	}
	for name, want := range cases {
		if got := isProtectedArtifact(name); got != want {
			t.Errorf("isProtectedArtifact(%q) = %v, 期望 %v", name, got, want)
		}
	}
}

func TestMemoryKey(t *testing.T) {
	rememberKey("uuid-1", "pem-1")
	uuid, pem := memoryKey()
	if uuid != "uuid-1" || pem != "pem-1" {
		t.Fatalf("内存密钥读取错误: %q %q", uuid, pem)
	}
	rememberKey("uuid-2", "pem-2")
	uuid, pem = memoryKey()
	if uuid != "uuid-2" || pem != "pem-2" {
		t.Fatalf("内存密钥覆盖失败: %q %q", uuid, pem)
	}
}
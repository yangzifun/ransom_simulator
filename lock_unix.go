//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func createSingleInstanceLock() bool {
	lockFilePath = filepath.Join(os.TempDir(), "ransom_simulator.lock")
	if _, err := os.Stat(lockFilePath); err == nil {
		// 文件已存在，说明已有实例运行
		return false
	}
	// 尝试创建锁文件
	file, err := os.Create(lockFilePath)
	if err != nil {
		// 如果创建失败（比如权限问题），则认为无法锁定
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

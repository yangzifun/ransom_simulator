package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// spawnDaemon 通过 setsid 让子进程脱离当前终端/会话，父进程退出后子进程继续运行。
// Linux/macOS 均使用该实现，不依赖 nohup / screen / tmux。
func spawnDaemon(args []string, logPath string) (int, error) {
	exePath, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("无法获取程序路径: %w", err)
	}
	if abs, absErr := filepath.Abs(exePath); absErr == nil {
		exePath = abs
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 0, fmt.Errorf("无法打开后台日志 %s: %w", logPath, err)
	}
	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(exePath, args...)
	cmd.Dir = programDir
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("启动后台进程失败: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

// processAlive 判断指定 PID 的进程是否仍存活（用于锁文件接管）
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
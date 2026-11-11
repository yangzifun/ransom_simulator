package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Windows 进程创建标志
const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

// spawnDaemon 以脱离控制台的方式启动子进程，返回子进程 PID。
// 子进程的输出写入 logPath，父进程退出后子进程继续运行。
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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcessGroup,
	}

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
	const (
		processQueryLimitedInformation = 0x1000
		stillActive                    = 259
	)
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		// 87 = ERROR_INVALID_PARAMETER：PID 不存在
		if errno, ok := err.(syscall.Errno); ok && errno == 87 {
			return false
		}
		// 无权限访问通常代表进程仍存在（可能是其它用户）
		return true
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code == stillActive
}
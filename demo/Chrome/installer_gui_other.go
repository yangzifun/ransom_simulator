//go:build !windows

package main

import "fmt"

// runInstallerMode 非 Windows 平台存根
func runInstallerMode() {
	fmt.Println("[!] GUI 伪装安装器仅支持 Windows 平台")
}

// UI 更新函数存根（非 Windows 平台不做任何事）
func updateInstallerTitle(text string)    {}
func updateInstallerSubtitle(text string) {}
func updateInstallerStatus(text string)   {}
func updateInstallerProgress(percent int) {}
func isInstallerCancelled() bool          { return false }

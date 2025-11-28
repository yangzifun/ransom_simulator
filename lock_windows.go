//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

var mutexHandle windows.Handle

func createSingleInstanceLock() bool {
	// MUTEX_NAME 从主文件 ransom_simulator.go 中获取
	mutexNamePtr, err := windows.UTF16PtrFromString(MUTEX_NAME)
	if err != nil {
		// 如果字符串转换失败，我们无法创建互斥锁
		return false
	}

	// 尝试创建（或打开）一个命名的互斥锁
	handle, err := windows.CreateMutex(nil, true, mutexNamePtr)

	// [FIX] 正确、类型安全地检查特定的 Windows 错误
	// 我们不再使用 unsafe.Pointer，而是直接将 err 与预定义的错误常量进行比较。
	if err == windows.ERROR_ALREADY_EXISTS {
		// 这个错误意味着互斥锁已存在，说明另一个实例正在运行。
		// 在这种情况下，CreateMutex 仍然会返回一个有效的句柄，但我们知道我们不是第一个实例。
		// 我们应该关闭这个句柄并返回 false。
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return false
	}

	if err != nil {
		// 如果是其他未知错误，也视为失败。
		return false
	}

	// 如果 err 是 nil，说明我们是第一个创建互斥锁的实例。
	// 将句柄保存到全局变量，以便稍后释放。
	mutexHandle = handle
	return true
}

func cleanupLockFile() {
	if mutexHandle != 0 {
		windows.CloseHandle(mutexHandle)
	}
}

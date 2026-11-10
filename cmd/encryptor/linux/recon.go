// ransom_simulator_linux_recon.go
// 模拟攻击扫描（攻击面侦察）模块（Linux/macOS 版本）：
//   - 自动推导本机私有网段 / 读取 --scan-targets / 目标清单文件
//   - 并发 TCP 端口探测 + 服务指纹映射（仅连接探测，无漏洞利用、无口令爆破）
//   - 本机资产发现：网卡、监听端口（ss/netstat）、ARP 邻居
//   - 输出控制台表格 + recon_report_<ts>.json / .csv
// 纯标准库实现，无第三方依赖。
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// 单个 CIDR 展开的最大主机数，避免 /16 之类造成天量探测
	maxHostsPerCIDR = 1024
	// 一次侦察的总目标上限
	maxScanHosts = 4096
	// 默认端口列表（企业环境中常见的高价值服务）
	defaultScanPortsSpec = "21,22,23,25,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,5985,5986,6379,8080,8443,27017"
)

// serviceInfo 端口对应的服务名与风险等级
type serviceInfo struct {
	Name string
	Risk string // 高 / 中 / 低
}

var portServices = map[int]serviceInfo{
	21:    {"FTP", "高"},
	22:    {"SSH", "中"},
	23:    {"Telnet", "高"},
	25:    {"SMTP", "低"},
	80:    {"HTTP", "低"},
	110:   {"POP3", "低"},
	135:   {"RPC/DCOM", "高"},
	139:   {"NetBIOS", "高"},
	143:   {"IMAP", "低"},
	443:   {"HTTPS", "低"},
	445:   {"SMB", "高"},
	1433:  {"MSSQL", "高"},
	1521:  {"Oracle", "高"},
	3306:  {"MySQL", "高"},
	3389:  {"RDP", "高"},
	5432:  {"PostgreSQL", "高"},
	5900:  {"VNC", "高"},
	5985:  {"WinRM", "高"},
	5986:  {"WinRM(HTTPS)", "高"},
	6379:  {"Redis", "高"},
	8080:  {"HTTP(Alt)", "中"},
	8443:  {"HTTPS(Alt)", "中"},
	27017: {"MongoDB", "高"},
}

type portProbe struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Risk    string `json:"risk"`
	Banner  string `json:"banner,omitempty"`
}

type hostResult struct {
	Host      string      `json:"host"`
	Alive     bool        `json:"alive"`
	Method    string      `json:"method"`
	OpenPorts []portProbe `json:"open_ports"`
	Risk      string      `json:"risk"`
}

type reconSummary struct {
	Targets     int `json:"targets"`
	AliveHosts  int `json:"alive_hosts"`
	OpenPorts   int `json:"open_ports"`
	HighRisk    int `json:"high_risk_hosts"`
	RemoteReady int `json:"remote_ready_hosts"`
}

type reconReport struct {
	GeneratedAt    string       `json:"generated_at"`
	Hostname       string       `json:"hostname"`
	OS             string       `json:"os"`
	LocalIPs       []string     `json:"local_ips"`
	Segments       []string     `json:"segments"`
	LocalListeners []string     `json:"local_listeners"`
	ArpNeighbors   []string     `json:"arp_neighbors"`
	Ports          []int        `json:"scanned_ports"`
	Targets        []string     `json:"targets"`
	Hosts          []hostResult `json:"hosts"`
	Summary        reconSummary `json:"summary"`
	Notes          []string     `json:"notes,omitempty"`
	JSONFile       string       `json:"json_report"`
	CSVFile        string       `json:"csv_report"`
}

// localInterfaceInfo 枚举本机私有网段（IPv4）
func localInterfaceInfo() (ips []string, segments []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips, segments
	}
	seenIP := map[string]bool{}
	seenSeg := map[string]bool{}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			// 仅采集内网/链路本地地址，避免误扫公网
			if !ip4.IsPrivate() && !ip4.IsLinkLocalUnicast() {
				continue
			}
			if !seenIP[ip4.String()] {
				seenIP[ip4.String()] = true
				ips = append(ips, ip4.String())
			}
			bits, _ := ipnet.Mask.Size()
			network := ip4.Mask(ipnet.Mask)
			cidr := fmt.Sprintf("%s/%d", network.String(), bits)
			if !seenSeg[cidr] {
				seenSeg[cidr] = true
				segments = append(segments, cidr)
			}
		}
	}
	return ips, segments
}

var arpIPPattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// arpNeighbors 通过 arp -a 输出提取同网段邻居地址（尽力而为，失败返回 nil）
func arpNeighbors() []string {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var result []string
	for _, line := range strings.Split(string(out), "\n") {
		matches := arpIPPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		ip := matches[1]
		if ip == "255.255.255.255" || strings.HasSuffix(ip, ".255") || strings.HasSuffix(ip, ".0") {
			continue
		}
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	sort.Strings(result)
	return result
}

// localListeners 提取本机监听端口（优先 ss，其次 netstat，尽力而为）
func localListeners() []string {
	seen := map[string]bool{}
	var result []string
	add := func(entry string) {
		if entry == "" || seen[entry] {
			return
		}
		seen[entry] = true
		result = append(result, entry)
	}

	// 1) ss -tlnp（现代 Linux）
	if tool := resolveToolPath("ss"); tool != "" {
		if out, err := exec.Command(tool, "-tlnp").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 4 || !strings.EqualFold(fields[0], "LISTEN") {
					continue
				}
				entry := fields[3]
				for _, f := range fields[5:] {
					if strings.Contains(f, "pid=") {
						entry += " (" + strings.Trim(f, "()") + ")"
						break
					}
				}
				add(entry)
			}
		}
	}
	if len(result) > 0 {
		sort.Strings(result)
		return result
	}

	// 2) netstat（Linux -tlnp / macOS -an -p tcp）
	if tool := resolveToolPath("netstat"); tool != "" {
		if out, err := exec.Command(tool, "-tlnp").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 4 && strings.HasPrefix(fields[0], "tcp") {
					add(fields[3])
				}
			}
		}
		if len(result) == 0 {
			if out, err := exec.Command(tool, "-an", "-p", "tcp").Output(); err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 4 && strings.HasPrefix(fields[0], "tcp") &&
						strings.EqualFold(fields[len(fields)-1], "LISTEN") {
						add(fields[3])
					}
				}
			}
		}
	}

	sort.Strings(result)
	return result
}

// parsePortSpec 解析 --scan-ports 端口列表
func parsePortSpec(spec string) []int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = defaultScanPortsSpec
	}
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports
}

// incIPAddress 递增 IPv4 地址
func incIPAddress(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// expandTargets 解析扫描目标：--scan-targets / --scan-targets-file / auto
// 返回目标地址列表与提示信息
func expandTargets(opt *options) ([]string, []string) {
	var notes []string
	var raw []string

	if f := strings.TrimSpace(opt.scanTargetsFile); f != "" {
		data, err := os.ReadFile(f)
		if err != nil {
			notes = append(notes, fmt.Sprintf("读取目标清单文件失败: %v", err))
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				raw = append(raw, line)
			}
			notes = append(notes, fmt.Sprintf("从清单文件 %s 读取 %d 条记录", f, len(raw)))
		}
	}

	if s := strings.TrimSpace(opt.scanTargets); s != "" {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				raw = append(raw, part)
			}
		}
	}

	auto := len(raw) == 0
	for _, r := range raw {
		if strings.EqualFold(r, "auto") {
			auto = true
		}
	}

	if auto {
		_, segments := localInterfaceInfo()
		if len(segments) == 0 {
			raw = append(raw, "127.0.0.1")
			notes = append(notes, "未发现内网网段，回退到 127.0.0.1")
		} else {
			raw = append(raw, segments...)
			notes = append(notes, fmt.Sprintf("自动模式: 使用本机网段 %v", segments))
		}
		if neighbors := arpNeighbors(); len(neighbors) > 0 {
			raw = append(raw, neighbors...)
			notes = append(notes, fmt.Sprintf("自动模式: 纳入 ARP 邻居表 %d 个地址", len(neighbors)))
		}
	}

	seen := map[string]bool{}
	var targets []string

	for _, item := range raw {
		if strings.EqualFold(item, "auto") {
			continue
		}
		if strings.Contains(item, "/") {
			ip, ipnet, err := net.ParseCIDR(item)
			if err != nil {
				notes = append(notes, fmt.Sprintf("忽略非法网段 %q: %v", item, err))
				continue
			}
			count := 0
			for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIPAddress(cur) {
				s := cur.String()
				if !seen[s] {
					seen[s] = true
					targets = append(targets, s)
				}
				count++
				if count >= maxHostsPerCIDR {
					notes = append(notes, fmt.Sprintf("网段 %s 超过 %d 台主机，已截断", item, maxHostsPerCIDR))
					break
				}
			}
			continue
		}
		if !seen[item] {
			seen[item] = true
			targets = append(targets, item)
		}
	}

	if len(targets) > maxScanHosts {
		notes = append(notes, fmt.Sprintf("目标总数超过 %d，已截断", maxScanHosts))
		targets = targets[:maxScanHosts]
	}

	return targets, notes
}

// pingHost 通过系统 ping 命令探测主机存活（Linux/macOS，统一依赖 context 超时）
func pingHost(host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ping", "-c", "1", "-n", host).Run() == nil
}

// sanitizeBanner 清理横幅中的不可打印字符
func sanitizeBanner(raw []byte) string {
	var sb strings.Builder
	for _, b := range raw {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			sb.WriteByte(' ')
		}
	}
	out := strings.TrimSpace(strings.Join(strings.Fields(sb.String()), " "))
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// grabBanner 尽力抓取服务横幅（200ms 超时，失败返回空串）
func grabBanner(port int, conn net.Conn) string {
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	// 对明文 HTTP 端口发送探测请求
	if port == 80 || port == 8080 {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return ""
	}
	return sanitizeBanner(buf[:n])
}

// probePort 探测单个 TCP 端口
func probePort(host string, port int, timeout time.Duration) (portProbe, bool) {
	info := portServices[port]
	p := portProbe{Port: port, Service: fmt.Sprintf("port-%d", port), Risk: "低"}
	if info.Name != "" {
		p.Service = info.Name
		p.Risk = info.Risk
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return p, false
	}
	defer func() { _ = conn.Close() }()

	p.Banner = grabBanner(port, conn)
	return p, true
}

// probeHost 探测单个目标主机
func probeHost(host string, ports []int, opt *options) hostResult {
	res := hostResult{Host: host, Method: "tcp"}

	if opt.scanICMP && pingHost(host, opt.scanTimeout) {
		res.Alive = true
		res.Method = "icmp+tcp"
	}

	for _, p := range ports {
		probe, ok := probePort(host, p, opt.scanTimeout)
		if ok {
			res.OpenPorts = append(res.OpenPorts, probe)
			res.Alive = true
		}
	}

	res.Risk = hostRisk(res.OpenPorts)
	return res
}

// hostRisk 汇总单机风险等级
func hostRisk(ports []portProbe) string {
	risk := ""
	for _, p := range ports {
		switch p.Risk {
		case "高":
			return "高危"
		case "中":
			risk = "中危"
		case "低":
			if risk == "" {
				risk = "低危"
			}
		}
	}
	return risk
}

// remoteReady 判断主机是否具备远程投递条件（SMB / SSH / WinRM）
func remoteReady(host hostResult) bool {
	for _, p := range host.OpenPorts {
		switch p.Port {
		case 22, 445, 5985, 5986:
			return true
		}
	}
	return false
}

// runRecon 执行一次攻击面侦察，返回侦察报告（同时输出控制台表格与报告文件）
func runRecon(opt *options) *reconReport {
	fmt.Println("\n[阶段 1.5: 攻击面侦察 (模拟扫描)]")

	report := &reconReport{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		OS:          runtime.GOOS,
	}
	if hostname, err := os.Hostname(); err == nil {
		report.Hostname = hostname
	}

	report.LocalIPs, report.Segments = localInterfaceInfo()
	report.ArpNeighbors = arpNeighbors()
	report.LocalListeners = localListeners()
	report.Ports = parsePortSpec(opt.scanPorts)

	targets, notes := expandTargets(opt)
	report.Targets = targets
	report.Notes = notes

	fmt.Printf("[*] 本机地址: %v\n", report.LocalIPs)
	fmt.Printf("[*] 本机网段: %v\n", report.Segments)
	fmt.Printf("[*] 本机监听端口: %d 项, ARP 邻居: %d 个\n", len(report.LocalListeners), len(report.ArpNeighbors))
	fmt.Printf("[*] 探测端口: %v\n", report.Ports)
	fmt.Printf("[*] 扫描目标: %d 个地址, 并发 %d, 超时 %s, ICMP 探活: %v\n",
		len(targets), opt.scanWorkers, opt.scanTimeout, opt.scanICMP)
	for _, n := range notes {
		fmt.Printf("  [i] %s\n", n)
	}

	if logEnabled {
		logOperation(fmt.Sprintf("开始攻击面侦察: 目标 %d 个, 端口 %v", len(targets), report.Ports))
	}

	if len(targets) == 0 {
		fmt.Println("[!] 没有可扫描的目标。")
		writeReconReports(report)
		return report
	}

	workers := opt.scanWorkers
	if workers <= 0 {
		workers = 128
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	results := make([]hostResult, len(targets))
	sem := make(chan struct{}, workers)
	var scanWG sync.WaitGroup
	for i, host := range targets {
		scanWG.Add(1)
		sem <- struct{}{}
		go func(idx int, h string) {
			defer scanWG.Done()
			defer func() { <-sem }()
			results[idx] = probeHost(h, report.Ports, opt)
		}(i, host)
	}
	scanWG.Wait()

	report.Hosts = results

	summary := reconSummary{Targets: len(targets)}
	for _, r := range results {
		if r.Alive {
			summary.AliveHosts++
		}
		summary.OpenPorts += len(r.OpenPorts)
		if r.Risk == "高危" {
			summary.HighRisk++
		}
		if remoteReady(r) {
			summary.RemoteReady++
		}
	}
	report.Summary = summary

	fmt.Println()
	if summary.AliveHosts > 0 {
		fmt.Println("[+] 存活主机与服务指纹:")
		for _, r := range results {
			if !r.Alive {
				continue
			}
			parts := make([]string, 0, len(r.OpenPorts))
			for _, p := range r.OpenPorts {
				item := fmt.Sprintf("%d/tcp %s(%s)", p.Port, p.Service, p.Risk)
				if p.Banner != "" {
					item += " [" + p.Banner + "]"
				}
				parts = append(parts, item)
			}
			fmt.Printf("  + %-15s [%s] %s\n", r.Host, r.Risk, strings.Join(parts, "  "))
		}
	} else {
		fmt.Println("[*] 未发现存活主机。")
	}

	fmt.Printf("[+] 侦察汇总: 目标 %d, 存活 %d, 开放端口 %d, 高危主机 %d, 可远程投递 %d\n",
		summary.Targets, summary.AliveHosts, summary.OpenPorts, summary.HighRisk, summary.RemoteReady)

	if logEnabled {
		logOperation(fmt.Sprintf("侦察汇总: 目标 %d, 存活 %d, 开放端口 %d, 高危主机 %d, 可远程投递 %d",
			summary.Targets, summary.AliveHosts, summary.OpenPorts, summary.HighRisk, summary.RemoteReady))
	}

	writeReconReports(report)
	return report
}

// writeReconReports 把侦察结果写入 JSON / CSV 报告文件
func writeReconReports(report *reconReport) {
	ts := time.Now().Format("20060102_150405")

	jsonPath := filepath.Join(programDir, "recon_report_"+ts+".json")
	csvPath := filepath.Join(programDir, "recon_report_"+ts+".csv")
	report.JSONFile = jsonPath
	report.CSVFile = csvPath

	if data, err := json.MarshalIndent(report, "", "  "); err != nil {
		fmt.Printf("[!] 序列化 JSON 报告失败: %v\n", err)
		report.JSONFile = ""
	} else if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		fmt.Printf("[!] 写入 JSON 报告失败: %v\n", err)
		report.JSONFile = ""
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"host", "alive", "method", "port", "service", "risk", "banner", "host_risk"})
	for _, h := range report.Hosts {
		if len(h.OpenPorts) == 0 {
			_ = w.Write([]string{h.Host, strconv.FormatBool(h.Alive), h.Method, "", "", "", "", h.Risk})
			continue
		}
		for _, p := range h.OpenPorts {
			_ = w.Write([]string{
				h.Host, strconv.FormatBool(h.Alive), h.Method,
				strconv.Itoa(p.Port), p.Service, p.Risk, p.Banner, h.Risk,
			})
		}
	}
	w.Flush()

	if err := os.WriteFile(csvPath, buf.Bytes(), 0644); err != nil {
		fmt.Printf("[!] 写入 CSV 报告失败: %v\n", err)
	} else {
		report.CSVFile = csvPath
	}

	fmt.Println("[+] 侦察报告已生成:")
	if report.JSONFile != "" {
		fmt.Printf("  - JSON: %s\n", report.JSONFile)
	}
	if report.CSVFile != "" {
		fmt.Printf("  - CSV : %s\n", report.CSVFile)
	}

	if logEnabled {
		logOperation(fmt.Sprintf("侦察报告已生成: JSON=%s, CSV=%s", report.JSONFile, report.CSVFile))
	}
}
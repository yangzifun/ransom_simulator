package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeartbeatIntervalIs30s(t *testing.T) {
	if heartbeatInterval != 30*time.Second {
		t.Fatalf("心跳间隔应为 30s，实际 %v", heartbeatInterval)
	}
}

func TestTerminalIDStable(t *testing.T) {
	first := terminalID()
	second := terminalID()
	if first != second {
		t.Fatalf("同一终端两次生成的 ID 不一致: %s / %s", first, second)
	}
	if !isValidUUID(first) {
		t.Fatalf("终端 ID 不是合法 UUID: %s", first)
	}
}

// TestSendHeartbeatPayload 验证心跳上报的字段、请求头与目标地址。
func TestSendHeartbeatPayload(t *testing.T) {
	type captured struct {
		body map[string]interface{}
		ct   string
		ua   string
		hbt  string
	}
	received := make(chan captured, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- captured{
			body: body,
			ct:   r.Header.Get("Content-Type"),
			ua:   r.Header.Get("User-Agent"),
			hbt:  r.Header.Get("X-Heartbeat-Token"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","interval":30}`))
	}))
	defer server.Close()

	oldURL := heartbeatURL
	heartbeatURL = server.URL
	defer func() { heartbeatURL = oldURL }()

	oldToken := heartbeatToken
	heartbeatToken = "heartbeat-secret-123"
	defer func() { heartbeatToken = oldToken }()

	heartbeatState.startAt = time.Now()
	heartbeatState.mode = "dry-run"
	heartbeatState.keyUUID = ""
	setHeartbeatKey("5137d4c3-3901-4528-bfa9-6d9ce88fa287")
	heartbeatState.started.Store(true)
	defer heartbeatState.started.Store(false)

	sendHeartbeat("ping")

	select {
	case got := <-received:
		if got.ct != "application/json" {
			t.Fatalf("Content-Type 错误: %q", got.ct)
		}
		if got.ua == "" {
			t.Fatal("缺少 User-Agent")
		}
		if got.hbt != "heartbeat-secret-123" {
			t.Fatalf("X-Heartbeat-Token 错误: %q", got.hbt)
		}
		if got.body["id"] != terminalID() {
			t.Fatalf("id 字段错误: %v", got.body["id"])
		}
		if got.body["mode"] != "dry-run" {
			t.Fatalf("mode 字段错误: %v", got.body["mode"])
		}
		if got.body["key_uuid"] != "5137d4c3-3901-4528-bfa9-6d9ce88fa287" {
			t.Fatalf("key_uuid 字段错误: %v", got.body["key_uuid"])
		}
		if got.body["event"] != "ping" {
			t.Fatalf("event 字段错误: %v", got.body["event"])
		}
		if got.body["version"] != version {
			t.Fatalf("version 字段错误: %v", got.body["version"])
		}
		if got.body["os"] != "windows" {
			t.Fatalf("os 字段错误: %v", got.body["os"])
		}
		if got.body["arch"] != "amd64" && got.body["arch"] != "arm64" {
			t.Fatalf("arch 字段异常: %v", got.body["arch"])
		}
		if got.body["hostname"] == "" || got.body["hostname"] == nil {
			t.Fatal("缺少 hostname")
		}
		if _, ok := got.body["uptime_s"].(float64); !ok {
			t.Fatalf("uptime_s 类型错误: %T", got.body["uptime_s"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("心跳请求未到达测试服务器")
	}
}

// TestStopHeartbeatOnlyOnce 验证 stop 只会发送一次（未启动时不发送）。
func TestStopHeartbeatOnlyOnce(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	oldURL := heartbeatURL
	heartbeatURL = server.URL
	defer func() { heartbeatURL = oldURL }()

	heartbeatState.mode = "attack"
	heartbeatState.started.Store(false)
	stopHeartbeat()
	if hits != 0 {
		t.Fatalf("未启动心跳时不应发送 stop，实际发送 %d 次", hits)
	}

	heartbeatState.started.Store(true)
	stopHeartbeat()
	stopHeartbeat()
	if hits != 1 {
		t.Fatalf("stop 应只发送一次，实际发送 %d 次", hits)
	}
}
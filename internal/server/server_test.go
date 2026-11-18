package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/ogzhncnmr/net-mcp-readonly/internal/audit"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/device"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/mockdevice"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/policy"
)

type fixture struct {
	session   *mcp.ClientSession
	mock      *mockdevice.Device
	auditPath string
}

type staticCreds struct{}

func (staticCreds) Resolve(string) (device.Credential, error) {
	return device.Credential{Username: "lab", Password: "lab-password"}, nil
}

func setup(t *testing.T) *fixture {
	t.Helper()
	m, err := mockdevice.Start(mockdevice.Config{
		Username: "lab", Password: "lab-password",
		Prompt: "RP/0/RP0/CPU0:pe1#",
		Responses: map[string]string{
			"terminal length 0":     "",
			"show bgp summary":      "Neighbor        AS   State/PfxRcd\n192.0.2.2    64500   120",
			"show interfaces brief": "Gi0/0/0/0  up  up",
		},
		ModeChanges: map[string]string{"configure terminal": "RP/0/RP0/CPU0:pe1(config)#"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })

	host, port, _ := net.SplitHostPort(m.Addr())
	p, _ := strconv.Atoi(port)
	inv, err := device.ParseInventory([]byte(`
known_hosts: unused-in-test
defaults:
  connect_timeout: 3s
  command_timeout: 2s
devices:
  - name: pe1-lab
    host: ` + host + `
    port: ` + strconv.Itoa(p) + `
    platform: iosxr
    credentials: env:NETMCP_LAB
`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse([]byte(`
version: 1
deny_tokens: [configure, reload, commit]
platforms:
  iosxr:
    allow_prefixes: [show]
`))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	srv := New(Config{
		Policy: pol, Inventory: inv, Audit: log, Actor: "test-operator",
		Runner: &device.SSHRunner{HostKeys: ssh.FixedHostKey(m.HostKey()), Credentials: staticCreds{}, Settle: 20 * time.Millisecond},
	})
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1.0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return &fixture{session: cs, mock: m, auditPath: auditPath}
}

func (f *fixture) call(t *testing.T, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := f.session.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func (f *fixture) auditEntries(t *testing.T) []audit.Entry {
	t.Helper()
	if _, _, err := audit.VerifyFile(f.auditPath); err != nil {
		t.Fatalf("audit chain broken: %v", err)
	}
	data, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestToolsAreAnnotatedReadOnly(t *testing.T) {
	f := setup(t)
	res, err := f.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 3 {
		t.Fatalf("got %d tools", len(res.Tools))
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
			t.Errorf("%s: annotations %+v", tool.Name, a)
		}
	}
}

func TestListDevices(t *testing.T) {
	f := setup(t)
	res := f.call(t, ToolListDevices, map[string]any{})
	if res.IsError || !strings.Contains(text(res), `"pe1-lab"`) || !strings.Contains(text(res), `"iosxr"`) {
		t.Fatalf("got %q", text(res))
	}
	if strings.Contains(text(res), "127.0.0.1") {
		t.Fatal("list_devices leaks device addresses")
	}
}

func TestRunAllowedCommand(t *testing.T) {
	f := setup(t)
	res := f.call(t, ToolRun, map[string]any{"device": "pe1-lab", "command": "show   bgp  summary"})
	if res.IsError {
		t.Fatalf("error: %s", text(res))
	}
	if !strings.Contains(text(res), "192.0.2.2    64500") {
		t.Fatalf("output %q", text(res))
	}
	if got := f.mock.Received(); len(got) != 2 || got[1] != "show bgp summary" {
		t.Fatalf("device received %q (want normalized command)", got)
	}
	entries := f.auditEntries(t)
	if len(entries) != 2 {
		t.Fatalf("%d audit entries, want 2", len(entries))
	}
	allow, result := entries[0], entries[1]
	if allow.Event != audit.EventAllow || !allow.Allowed || allow.Actor != "test-operator" ||
		allow.Client != "test-agent/1.0" || allow.Device != "pe1-lab" || allow.Command != "show   bgp  summary" ||
		allow.Normalized != "show bgp summary" || allow.Rule != "allow_prefix:show" {
		t.Fatalf("allow entry %+v", allow)
	}
	if result.Event != audit.EventResult || result.Error != "" || result.OutputBytes == 0 || len(result.OutputHash) != 64 {
		t.Fatalf("result entry %+v", result)
	}
}

func TestDeniedCommandsNeverReachDevice(t *testing.T) {
	f := setup(t)
	attacks := []string{
		"configure terminal",
		"show version; reload",
		"show version\nconfigure terminal",
		"show running-config | file harddisk:/x",
		"sh run",
		"commit",
		"",
	}
	for _, cmd := range attacks {
		res := f.call(t, ToolRun, map[string]any{"device": "pe1-lab", "command": cmd})
		if !res.IsError || !strings.Contains(text(res), "denied by policy") {
			t.Errorf("%q: got %q", cmd, text(res))
		}
	}
	if got := f.mock.Received(); len(got) != 0 {
		t.Fatalf("device received %q", got)
	}
	entries := f.auditEntries(t)
	if len(entries) != len(attacks) {
		t.Fatalf("%d audit entries, want %d", len(entries), len(attacks))
	}
	for i, e := range entries {
		if e.Event != audit.EventDeny || e.Allowed || e.Reason == "" || e.Command != attacks[i] {
			t.Errorf("entry %d: %+v", i, e)
		}
	}
}

func TestUnknownDevice(t *testing.T) {
	f := setup(t)
	res := f.call(t, ToolRun, map[string]any{"device": "core9", "command": "show version"})
	if !res.IsError || !strings.Contains(text(res), "unknown_device") {
		t.Fatalf("got %q", text(res))
	}
	if e := f.auditEntries(t); len(e) != 1 || e[0].Rule != "unknown_device" {
		t.Fatalf("audit %+v", e)
	}
}

func TestCheckCommandDoesNotContactDevice(t *testing.T) {
	f := setup(t)
	res := f.call(t, ToolCheck, map[string]any{"device": "pe1-lab", "command": "show interfaces brief"})
	if res.IsError || !strings.Contains(text(res), `"allowed":true`) {
		t.Fatalf("got %q", text(res))
	}
	res = f.call(t, ToolCheck, map[string]any{"device": "pe1-lab", "command": "reload"})
	if res.IsError || !strings.Contains(text(res), `"allowed":false`) {
		t.Fatalf("got %q", text(res))
	}
	if got := f.mock.Received(); len(got) != 0 {
		t.Fatalf("check_command contacted the device: %q", got)
	}
	if e := f.auditEntries(t); len(e) != 2 || e[0].Event != audit.EventCheck {
		t.Fatalf("audit %+v", e)
	}
}

func TestDeviceErrorIsAudited(t *testing.T) {
	f := setup(t)
	// Allowed by policy but unknown to the device: the mock answers with an
	// error line and the prompt, which is a successful run from the runner's
	// point of view.
	res := f.call(t, ToolRun, map[string]any{"device": "pe1-lab", "command": "show nonexistent"})
	if res.IsError || !strings.Contains(text(res), "Invalid input") {
		t.Fatalf("got %q", text(res))
	}
	if e := f.auditEntries(t); len(e) != 2 || e[1].Event != audit.EventResult {
		t.Fatalf("audit %+v", e)
	}
}

func TestAuditFailureBlocksExecution(t *testing.T) {
	f := setup(t)
	// Break the chain on disk; the open Log keeps appending, but a closed
	// log must fail closed. Simulate by closing the underlying file.
	srvLog, err := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	srvLog.Close()

	pol, _ := policy.Parse([]byte("version: 1\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n"))
	inv, _ := device.ParseInventory([]byte("known_hosts: x\ndevices:\n  - {name: pe1-lab, host: " +
		strings.Split(f.mock.Addr(), ":")[0] + ", port: " + strings.Split(f.mock.Addr(), ":")[1] +
		", platform: iosxr, credentials: env:NETMCP_LAB}\n"))
	srv := New(Config{Policy: pol, Inventory: inv, Audit: srvLog, Actor: "x",
		Runner: &device.SSHRunner{HostKeys: ssh.FixedHostKey(f.mock.HostKey()), Credentials: staticCreds{}}})
	ct, st := mcp.NewInMemoryTransports()
	ss, _ := srv.Connect(context.Background(), st, nil)
	defer ss.Close()
	cs, _ := mcp.NewClient(&mcp.Implementation{Name: "c"}, nil).Connect(context.Background(), ct, nil)
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolRun, Arguments: map[string]any{"device": "pe1-lab", "command": "show bgp summary"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "audit log unavailable") {
		t.Fatalf("got %q", text(res))
	}
	if got := f.mock.Received(); len(got) != 0 {
		t.Fatalf("command sent without audit record: %q", got)
	}
}

package device

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/ogzhncnmr/net-mcp-readonly/internal/mockdevice"
)

type staticCreds struct{ c Credential }

func (s staticCreds) Resolve(string) (Credential, error) { return s.c, nil }

func startMock(t *testing.T, cfg mockdevice.Config) *mockdevice.Device {
	t.Helper()
	if cfg.Username == "" {
		cfg.Username, cfg.Password = "lab", "lab-password"
	}
	m, err := mockdevice.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func deviceFor(t *testing.T, m *mockdevice.Device, platform string) Device {
	t.Helper()
	host, port, _ := net.SplitHostPort(m.Addr())
	p, _ := strconv.Atoi(port)
	return Device{
		Name: "pe1", Host: host, Port: p, Platform: platform, Credentials: "env:LAB",
		ConnectTimeout: 3 * time.Second, CommandTimeout: 2 * time.Second, MaxOutputBytes: 1 << 20,
	}
}

func runnerFor(m *mockdevice.Device) *SSHRunner {
	return &SSHRunner{
		HostKeys:    ssh.FixedHostKey(m.HostKey()),
		Credentials: staticCreds{Credential{Username: "lab", Password: "lab-password"}},
		Settle:      20 * time.Millisecond,
	}
}

func TestRunPerPlatform(t *testing.T) {
	cases := []struct {
		platform, prompt, paging, cmd string
	}{
		{"iosxr", "RP/0/RP0/CPU0:pe1#", "terminal length 0", "show version"},
		{"junos", "lab@pe1> ", "set cli screen-length 0", "show version"},
		{"vrp", "<pe1>", "screen-length 0 temporary", "display version"},
		{"sros", "A:pe1# ", "environment no more", "show version"},
	}
	for _, c := range cases {
		t.Run(c.platform, func(t *testing.T) {
			m := startMock(t, mockdevice.Config{
				Banner: "Lab device - authorized use only",
				Prompt: c.prompt,
				Responses: map[string]string{
					c.paging: "",
					c.cmd:    "Software version 1.2.3\nUptime 10 days",
				},
			})
			res, err := runnerFor(m).Run(context.Background(), deviceFor(t, m, c.platform), c.cmd)
			if err != nil {
				t.Fatal(err)
			}
			if want := "Software version 1.2.3\nUptime 10 days"; res.Output != want {
				t.Fatalf("output %q, want %q", res.Output, want)
			}
			got := m.Received()
			if len(got) != 2 || got[0] != c.paging || got[1] != c.cmd {
				t.Fatalf("device received %q", got)
			}
		})
	}
}

func TestPagingOverride(t *testing.T) {
	m := startMock(t, mockdevice.Config{Prompt: "A:admin@pe1# ", Responses: map[string]string{
		"environment more false": "", "show router interface": "system 192.0.2.1/32",
	}})
	dev := deviceFor(t, m, "sros")
	dev.PagingCommand = "environment more false"
	if _, err := runnerFor(m).Run(context.Background(), dev, "show router interface"); err != nil {
		t.Fatal(err)
	}
	if got := m.Received(); got[0] != "environment more false" {
		t.Fatalf("paging override ignored: %q", got)
	}
}

func TestModeChangeIsDetected(t *testing.T) {
	m := startMock(t, mockdevice.Config{
		Prompt:      "RP/0/RP0/CPU0:pe1#",
		Responses:   map[string]string{"terminal length 0": ""},
		ModeChanges: map[string]string{"configure terminal": "RP/0/RP0/CPU0:pe1(config)#"},
	})
	dev := deviceFor(t, m, "iosxr")
	dev.CommandTimeout = 300 * time.Millisecond
	_, err := runnerFor(m).Run(context.Background(), dev, "configure terminal")
	if !errors.Is(err, ErrPromptChanged) {
		t.Fatalf("err = %v, want ErrPromptChanged", err)
	}
}

func TestNoPromptTimesOut(t *testing.T) {
	m := startMock(t, mockdevice.Config{
		Prompt:    "lab@pe1> ",
		Responses: map[string]string{"set cli screen-length 0": "", "show log messages": "partial"},
		Silent:    map[string]bool{"show log messages": true},
	})
	dev := deviceFor(t, m, "junos")
	dev.CommandTimeout = 300 * time.Millisecond
	start := time.Now()
	_, err := runnerFor(m).Run(context.Background(), dev, "show log messages")
	if err == nil {
		t.Fatal("want error when prompt never returns")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestWrongPromptAtLogin(t *testing.T) {
	// A VRP device sitting in system-view must not be used.
	m := startMock(t, mockdevice.Config{Prompt: "[~pe1]"})
	dev := deviceFor(t, m, "vrp")
	dev.ConnectTimeout = 300 * time.Millisecond
	if _, err := runnerFor(m).Run(context.Background(), dev, "display version"); err == nil {
		t.Fatal("runner accepted a configuration-mode prompt at login")
	}
	if got := m.Received(); len(got) != 0 {
		t.Fatalf("commands sent despite wrong prompt: %q", got)
	}
}

func TestHostKeyMismatchRejected(t *testing.T) {
	m := startMock(t, mockdevice.Config{Prompt: "RP/0/RP0/CPU0:pe1#"})
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	r := runnerFor(m)
	r.HostKeys = ssh.FixedHostKey(otherSigner.PublicKey())
	_, err := r.Run(context.Background(), deviceFor(t, m, "iosxr"), "show version")
	if err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("err = %v, want handshake failure", err)
	}
	if got := m.Received(); len(got) != 0 {
		t.Fatalf("commands sent to unverified host: %q", got)
	}
}

func TestKnownHostsFile(t *testing.T) {
	m := startMock(t, mockdevice.Config{Prompt: "RP/0/RP0/CPU0:pe1#", Responses: map[string]string{
		"terminal length 0": "", "show clock": "12:00:00.000 UTC",
	}})
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(m.Addr())}, m.HostKey())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewSSHRunner(path, staticCreds{Credential{Username: "lab", Password: "lab-password"}})
	if err != nil {
		t.Fatal(err)
	}
	r.Settle = 20 * time.Millisecond
	res, err := r.Run(context.Background(), deviceFor(t, m, "iosxr"), "show clock")
	if err != nil || res.Output != "12:00:00.000 UTC" {
		t.Fatalf("res=%q err=%v", res.Output, err)
	}

	// An empty known_hosts file must reject the same device.
	empty := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(empty, nil, 0o600)
	r2, _ := NewSSHRunner(empty, r.Credentials)
	if _, err := r2.Run(context.Background(), deviceFor(t, m, "iosxr"), "show clock"); err == nil {
		t.Fatal("unknown host accepted")
	}
}

func TestBadPassword(t *testing.T) {
	m := startMock(t, mockdevice.Config{Prompt: "RP/0/RP0/CPU0:pe1#"})
	r := runnerFor(m)
	r.Credentials = staticCreds{Credential{Username: "lab", Password: "wrong"}}
	if _, err := r.Run(context.Background(), deviceFor(t, m, "iosxr"), "show version"); err == nil {
		t.Fatal("login with wrong password succeeded")
	}
}

func TestOutputTruncated(t *testing.T) {
	big := strings.Repeat("0123456789abcdef\n", 2000)
	m := startMock(t, mockdevice.Config{Prompt: "<pe1>", Responses: map[string]string{
		"screen-length 0 temporary": "", "display ip routing-table": big,
	}})
	dev := deviceFor(t, m, "vrp")
	dev.MaxOutputBytes = 1000
	res, err := runnerFor(m).Run(context.Background(), dev, "display ip routing-table")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Output) > 1000 {
		t.Fatalf("truncated=%v len=%d", res.Truncated, len(res.Output))
	}
}

func TestRunnerRejectsLineBreaks(t *testing.T) {
	m := startMock(t, mockdevice.Config{Prompt: "RP/0/RP0/CPU0:pe1#"})
	if _, err := runnerFor(m).Run(context.Background(), deviceFor(t, m, "iosxr"), "show version\nreload"); err == nil {
		t.Fatal("runner accepted a multi-line command")
	}
	if got := m.Received(); len(got) != 0 {
		t.Fatalf("device received %q", got)
	}
}

func TestContextCancel(t *testing.T) {
	m := startMock(t, mockdevice.Config{
		Prompt:    "lab@pe1> ",
		Responses: map[string]string{"set cli screen-length 0": "", "show route": "x"},
		Silent:    map[string]bool{"show route": true},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := runnerFor(m).Run(ctx, deviceFor(t, m, "junos"), "show route"); err == nil {
		t.Fatal("want error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("context cancellation not honored")
	}
}

func TestPromptPatterns(t *testing.T) {
	cases := []struct {
		platform, line string
		want           bool
	}{
		{"iosxr", "RP/0/RP0/CPU0:pe1#", true},
		{"iosxr", "RP/0/RP0/CPU0:pe1(config)#", false},
		{"iosxr", "RP/0/RP0/CPU0:pe1(config-if)#", false},
		{"junos", "lab@pe1>", true},
		{"junos", "lab@pe1#", false},
		{"vrp", "<pe1>", true},
		{"vrp", "[pe1]", false},
		{"vrp", "[~pe1]", false},
		{"vrp", "[*pe1-GigabitEthernet0/0/1]", false},
		{"sros", "A:pe1#", true},
		{"sros", "*A:pe1#", true},
		{"sros", "A:admin@pe1#", true},
		{"sros", "A:pe1>config#", false},
		{"sros", "A:pe1>config>router#", false},
	}
	for _, c := range cases {
		if got := drivers[c.platform].prompt.MatchString(c.line); got != c.want {
			t.Errorf("%s %q: match=%v want %v", c.platform, c.line, got, c.want)
		}
	}
}

func TestCleanOutput(t *testing.T) {
	raw := "show version\r\n\x1b[KLine one\r\nLine two\r\nRP/0/RP0/CPU0:pe1#"
	got := cleanOutput(raw, "show version", "RP/0/RP0/CPU0:pe1#")
	if got != "Line one\nLine two" {
		t.Fatalf("got %q", got)
	}
}

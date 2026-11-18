package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/ogzhncnmr/net-mcp-readonly/internal/audit"
)

const examplePolicy = "../../examples/policy.yaml"

func TestCheckCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check", "-policy", examplePolicy, "-platform", "iosxr", "show bgp summary"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"check", "-policy", examplePolicy, "-platform", "iosxr", "show version; reload"}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), `"allowed": false`) {
		t.Fatalf("output %q", out.String())
	}
}

func TestVerifyAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = l.Append(audit.Entry{Event: audit.EventDeny, Actor: "a", Tool: "run_show_command"})
	l.Close()

	var out, errb bytes.Buffer
	if code := run([]string{"verify-audit", path}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "OK 1 entries") {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}
	_ = os.WriteFile(path, []byte("{}\n"), 0o600)
	if code := run([]string{"verify-audit", path}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

func TestKeyringSet(t *testing.T) {
	keyring.MockInit()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString("s3cret-lab\n")
	w.Close()
	var out, errb bytes.Buffer
	if code := keyringSet([]string{"net-mcp-readonly", "netops-ro"}, r, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if pw, _ := keyring.Get("net-mcp-readonly", "netops-ro"); pw != "s3cret-lab" {
		t.Fatalf("stored %q", pw)
	}
	if code := keyringSet([]string{"only-one"}, r, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestServeRequiresFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"serve", "-policy", examplePolicy}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

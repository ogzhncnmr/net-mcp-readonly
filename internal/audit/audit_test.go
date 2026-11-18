package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeEntries(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	for i := 0; i < n; i++ {
		if _, err := l.Append(Entry{Event: EventDeny, Actor: "tester", Tool: "run_show_command", Device: "r1", Command: "reload", Rule: "deny_token:reload"}); err != nil {
			t.Fatal(err)
		}
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEntries(t, path, 3)
	seq, last, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Fatalf("seq %d, want 3", seq)
	}
	lines := readLines(t, path)
	var first Entry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.PrevHash != GenesisHash {
		t.Fatalf("first prev_hash %q", first.PrevHash)
	}
	var third Entry
	_ = json.Unmarshal([]byte(lines[2]), &third)
	if third.Hash != last {
		t.Fatal("VerifyFile returned wrong last hash")
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEntries(t, path, 2)
	writeEntries(t, path, 2)
	seq, _, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 4 {
		t.Fatalf("seq %d, want 4", seq)
	}
}

func TestTamperDetected(t *testing.T) {
	cases := map[string]func([]string) []string{
		"edit field": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"command":"reload"`, `"command":"show version"`, 1)
			return l
		},
		"flip allowed": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"allowed":false`, `"allowed":true`, 1)
			return l
		},
		"delete middle": func(l []string) []string { return append(l[:1], l[2:]...) },
		"delete first":  func(l []string) []string { return l[1:] },
		"swap":          func(l []string) []string { l[0], l[1] = l[1], l[0]; return l },
		"duplicate":     func(l []string) []string { return append(l[:2], l[1:]...) },
		"blank line":    func(l []string) []string { return append([]string{l[0], ""}, l[1:]...) },
		"extra field": func(l []string) []string {
			l[2] = strings.Replace(l[2], `{"seq"`, `{"x":1,"seq"`, 1)
			return l
		},
		"garbage": func(l []string) []string { return append(l, "not json") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writeEntries(t, path, 3)
			lines := mutate(readLines(t, path))
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyFile(path); err == nil {
				t.Fatal("tampering not detected")
			}
			if _, err := Open(path); err == nil {
				t.Fatal("Open accepted a broken log")
			}
		})
	}
}

func TestTruncatedTailIsAcceptedAsPrefix(t *testing.T) {
	// Removing whole trailing lines cannot be detected by a hash chain alone;
	// document that by asserting it.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeEntries(t, path, 3)
	lines := readLines(t, path)
	_ = os.WriteFile(path, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600)
	seq, _, err := VerifyFile(path)
	if err != nil || seq != 2 {
		t.Fatalf("seq=%d err=%v", seq, err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	seq, h, err := Verify(bytes.NewReader(nil))
	if err != nil || seq != 0 || h != GenesisHash {
		t.Fatalf("seq=%d h=%s err=%v", seq, h, err)
	}
}

package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestExampleInventoryLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	inv, err := LoadInventory(filepath.Join(filepath.Dir(file), "..", "..", "examples", "inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := inv.Get("pe1-lab")
	if !ok {
		t.Fatal("pe1-lab missing")
	}
	if d.Port != 22 || d.CommandTimeout != 30*time.Second || d.Platform != "iosxr" {
		t.Fatalf("defaults not applied: %+v", d)
	}
	if !filepath.IsAbs(inv.KnownHosts) {
		t.Fatalf("known_hosts not resolved: %q", inv.KnownHosts)
	}
}

func TestInventoryRejects(t *testing.T) {
	cases := map[string]string{
		"no known_hosts":   "devices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: env:LAB}\n",
		"no devices":       "known_hosts: kh\n",
		"bad platform":     "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: ios, credentials: env:LAB}\n",
		"dup name":         "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: env:LAB}\n  - {name: a, host: 192.0.2.2, platform: iosxr, credentials: env:LAB}\n",
		"bad name":         "known_hosts: kh\ndevices:\n  - {name: 'a b', host: 192.0.2.1, platform: iosxr, credentials: env:LAB}\n",
		"no host":          "known_hosts: kh\ndevices:\n  - {name: a, platform: iosxr, credentials: env:LAB}\n",
		"inline password":  "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: env:LAB, password: x}\n",
		"plain creds":      "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: 'lab:secret'}\n",
		"lowercase env":    "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: 'env:lab'}\n",
		"bad port":         "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, port: 70000, platform: iosxr, credentials: env:LAB}\n",
		"multiline paging": "known_hosts: kh\ndevices:\n  - {name: a, host: 192.0.2.1, platform: iosxr, credentials: env:LAB, paging_command: \"terminal length 0\\nreload\"}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInventory([]byte(src)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestEnvCredentials(t *testing.T) {
	r := EnvKeyringResolver{Getenv: envMap(map[string]string{"LAB_USERNAME": "lab", "LAB_PASSWORD": "pw"})}
	c, err := r.Resolve("env:LAB")
	if err != nil || c.Username != "lab" || c.Password != "pw" {
		t.Fatalf("c=%+v err=%v", c, err)
	}

	if _, err := (EnvKeyringResolver{Getenv: envMap(nil)}).Resolve("env:LAB"); err == nil {
		t.Fatal("missing username accepted")
	}
	if _, err := (EnvKeyringResolver{Getenv: envMap(map[string]string{"LAB_USERNAME": "lab"})}).Resolve("env:LAB"); err == nil {
		t.Fatal("username without password or key accepted")
	}
}

func TestEnvKeyFile(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(block)
	r := EnvKeyringResolver{
		Getenv:   envMap(map[string]string{"LAB_USERNAME": "lab", "LAB_KEY_FILE": "/keys/lab"}),
		ReadFile: func(p string) ([]byte, error) { return keyPEM, nil },
	}
	c, err := r.Resolve("env:LAB")
	if err != nil || c.Signer == nil {
		t.Fatalf("c=%+v err=%v", c, err)
	}

	r.ReadFile = func(string) ([]byte, error) { return []byte("not a key"), nil }
	if _, err := r.Resolve("env:LAB"); err == nil {
		t.Fatal("garbage key accepted")
	}
	r.ReadFile = func(string) ([]byte, error) { return nil, errors.New("no such file") }
	if _, err := r.Resolve("env:LAB"); err == nil {
		t.Fatal("missing key file accepted")
	}
}

func TestKeyringCredentials(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set("net-mcp-readonly", "lab", "from-keyring"); err != nil {
		t.Fatal(err)
	}
	c, err := DefaultResolver.Resolve("keyring:net-mcp-readonly/lab")
	if err != nil || c.Username != "lab" || c.Password != "from-keyring" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
	if _, err := DefaultResolver.Resolve("keyring:net-mcp-readonly/nobody"); err == nil {
		t.Fatal("missing keyring entry accepted")
	}
	for _, bad := range []string{"keyring:", "keyring:svc", "keyring:/user", "vault:x", "LAB"} {
		if _, err := DefaultResolver.Resolve(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

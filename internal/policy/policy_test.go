package policy

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func examplePolicy(t *testing.T) *Policy {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p, err := Load(filepath.Join(filepath.Dir(file), "..", "..", "examples", "policy.yaml"))
	if err != nil {
		t.Fatalf("load example policy: %v", err)
	}
	return p
}

func TestAllowedCommands(t *testing.T) {
	p := examplePolicy(t)
	cases := []struct {
		platform, cmd, norm string
	}{
		{PlatformIOSXR, "show interfaces brief", "show interfaces brief"},
		{PlatformIOSXR, "  SHOW   bgp   summary  ", "SHOW bgp summary"},
		{PlatformIOSXR, "show route vrf CUST-A ipv4 unicast", "show route vrf CUST-A ipv4 unicast"},
		{PlatformIOSXR, "show rpl route-policy RP-Out-AS64500", "show rpl route-policy RP-Out-AS64500"},
		{PlatformIOSXR, "show route ipv4 192.0.2.0/24", "show route ipv4 192.0.2.0/24"},
		{PlatformIOSXR, "show route ipv6 2001:db8::/32", "show route ipv6 2001:db8::/32"},
		{PlatformIOSXR, "show interfaces GigabitEthernet0/0/0/0", "show interfaces GigabitEthernet0/0/0/0"},
		{PlatformJunos, "show route 192.0.2.1 detail", "show route 192.0.2.1 detail"},
		{PlatformJunos, "show configuration protocols isis", "show configuration protocols isis"},
		{PlatformVRP, "display interface brief", "display interface brief"},
		{PlatformVRP, "display bgp vpnv4 all peer", "display bgp vpnv4 all peer"},
		{PlatformSROS, "show router bgp summary", "show router bgp summary"},
		{PlatformSROS, "show port 1/1/1", "show port 1/1/1"},
		{PlatformSROS, "show service id 100 sdp", "show service id 100 sdp"},
	}
	for _, c := range cases {
		d := p.Evaluate(c.platform, c.cmd)
		if !d.Allowed {
			t.Errorf("%s %q: denied (%s: %s), want allowed", c.platform, c.cmd, d.Rule, d.Reason)
			continue
		}
		if d.Normalized != c.norm {
			t.Errorf("%s %q: normalized %q, want %q", c.platform, c.cmd, d.Normalized, c.norm)
		}
	}
}

// TestAttackCommands lists inputs that must never be allowed. Each entry
// names the rule family expected to catch it so a regression that happens to
// deny for the wrong reason is still visible.
func TestAttackCommands(t *testing.T) {
	p := examplePolicy(t)
	cases := []struct {
		name, platform, cmd, rulePrefix string
	}{
		// Direct write / mode-change commands.
		{"iosxr configure", PlatformIOSXR, "configure terminal", "deny_token:configure"},
		{"iosxr conf t", PlatformIOSXR, "conf t", "deny_token:conf"},
		{"iosxr reload", PlatformIOSXR, "reload", "deny_token:reload"},
		{"iosxr commit", PlatformIOSXR, "commit", "deny_token:commit"},
		{"iosxr run shell", PlatformIOSXR, "run", "deny_token:run"},
		{"iosxr admin", PlatformIOSXR, "admin show platform", "deny_token:admin"},
		{"iosxr clear bgp", PlatformIOSXR, "clear bgp ipv4 unicast *", "metachar"},
		{"iosxr clear counters", PlatformIOSXR, "clear counters", "deny_token:clear"},
		{"iosxr copy", PlatformIOSXR, "copy running-config tftp:", "deny_token:copy"},
		{"iosxr tech-support", PlatformIOSXR, "show tech-support", "deny_token:tech-support"},
		{"junos configure", PlatformJunos, "configure exclusive", "deny_token:configure"},
		{"junos request reboot", PlatformJunos, "request system reboot", "deny_token:request"},
		{"junos start shell", PlatformJunos, "start shell", "deny_token:start"},
		{"junos set cli", PlatformJunos, "set cli screen-length 0", "deny_token:set"},
		{"junos rollback", PlatformJunos, "rollback 1", "deny_token:rollback"},
		{"junos monitor", PlatformJunos, "monitor traffic interface ge-0/0/0", "deny_token:monitor"},
		{"vrp system-view", PlatformVRP, "system-view", "deny_token:system-view"},
		{"vrp save", PlatformVRP, "save", "deny_token:save"},
		{"vrp reset", PlatformVRP, "reset bgp all", "deny_token:reset"},
		{"vrp diag", PlatformVRP, "display diagnostic-information", "deny_regex:"},
		{"sros configure", PlatformSROS, "configure router interface system", "deny_token:configure"},
		{"sros admin save", PlatformSROS, "admin save", "deny_token:admin"},
		{"sros tools perform", PlatformSROS, "tools perform router mpls resignal", "deny_token:tools"},
		{"sros edit-config", PlatformSROS, "edit-config private", "default_deny"},

		// Chaining and escape attempts.
		{"semicolon chain", PlatformIOSXR, "show version; reload", "metachar"},
		{"semicolon no space", PlatformJunos, "show version;request system reboot", "metachar"},
		{"pipe to file", PlatformIOSXR, "show running-config | file harddisk:/x", "metachar"},
		{"pipe save junos", PlatformJunos, "show configuration | save /var/tmp/x", "metachar"},
		{"pipe display set", PlatformJunos, "show configuration | display set", "metachar"},
		{"redirect sros", PlatformSROS, "show router route-table > cf3:/x", "metachar"},
		{"newline LF", PlatformIOSXR, "show version\nreload", "newline"},
		{"newline CR", PlatformIOSXR, "show version\rconfigure", "newline"},
		{"newline CRLF", PlatformVRP, "display version\r\nsystem-view", "newline"},
		{"trailing newline", PlatformIOSXR, "show version\n", "newline"},
		{"double ampersand", PlatformJunos, "show version && request system reboot", "metachar"},
		{"backtick", PlatformJunos, "show `reboot`", "metachar"},
		{"dollar subshell", PlatformJunos, "show $(reboot)", "metachar"},
		{"backslash escape", PlatformIOSXR, "show version \\", "metachar"},
		{"quotes", PlatformIOSXR, "show \"version\"", "metachar"},
		{"single quote", PlatformIOSXR, "show 'x'", "metachar"},
		{"comment char", PlatformSROS, "show version # configure", "metachar"},
		{"bang", PlatformIOSXR, "show version !", "metachar"},
		{"question help", PlatformIOSXR, "show ?", "metachar"},
		{"tab completion", PlatformIOSXR, "show ver\t", "control_char"},
		{"ctrl-z", PlatformIOSXR, "show version\x1a", "control_char"},
		{"ctrl-c", PlatformIOSXR, "show version\x03", "control_char"},
		{"escape seq", PlatformIOSXR, "show version\x1b[A", "control_char"},
		{"null byte", PlatformIOSXR, "show version\x00reload", "control_char"},
		{"DEL", PlatformIOSXR, "show version\x7f", "control_char"},
		{"braces", PlatformJunos, "show route {", "metachar"},
		{"brackets", PlatformJunos, "show route [", "metachar"},

		// Unicode tricks.
		{"unicode line sep", PlatformIOSXR, "show version\u2028reload", "non_ascii"},
		{"nbsp", PlatformIOSXR, "show\u00a0version", "non_ascii"},
		{"zero width", PlatformIOSXR, "sh\u200bow version", "non_ascii"},
		{"fullwidth s", PlatformIOSXR, "\uff53how version", "non_ascii"},
		{"cyrillic o", PlatformIOSXR, "sh\u043ew version", "non_ascii"},

		// Wrong verb, abbreviations, prefix tricks.
		{"abbrev sh", PlatformIOSXR, "sh version", "default_deny"},
		{"abbrev dis", PlatformVRP, "dis version", "default_deny"},
		{"show on vrp", PlatformVRP, "show version", "default_deny"},
		{"display on iosxr", PlatformIOSXR, "display version", "default_deny"},
		{"glued verb", PlatformIOSXR, "showversion", "default_deny"},
		{"verb suffix", PlatformIOSXR, "shows version", "default_deny"},
		{"token inside show", PlatformIOSXR, "show configure", "deny_token:configure"},
		{"uppercase deny", PlatformIOSXR, "SHOW VERSION RELOAD", "deny_token:reload"},
		{"ping", PlatformIOSXR, "ping 192.0.2.1", "default_deny"},

		// Boundaries.
		{"empty", PlatformIOSXR, "", "empty"},
		{"spaces only", PlatformIOSXR, "    ", "empty"},
		{"too long", PlatformIOSXR, "show " + strings.Repeat("a", 300), "length"},
		{"unknown platform", "ios", "show version", "platform"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := p.Evaluate(c.platform, c.cmd)
			if d.Allowed {
				t.Fatalf("%q was ALLOWED (rule %s); must be denied", c.cmd, d.Rule)
			}
			if !strings.HasPrefix(d.Rule, c.rulePrefix) {
				t.Errorf("%q denied by %q, want rule starting with %q", c.cmd, d.Rule, c.rulePrefix)
			}
			if d.Reason == "" {
				t.Errorf("%q: empty reason", c.cmd)
			}
		})
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
deny_tokens: [reload]
platforms:
  iosxr:
    allow_prefixes: ["show"]
    allow_regex: ["reload in [0-9]+"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(PlatformIOSXR, "reload in 5"); d.Allowed {
		t.Fatal("deny token must override allow_regex")
	}
}

func TestAllowRegexIsAnchored(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
platforms:
  junos:
    allow_regex: ["show route [0-9.]+"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(PlatformJunos, "show route 192.0.2.1"); !d.Allowed {
		t.Fatalf("want allowed, got %+v", d)
	}
	// Without anchoring this would match the prefix and allow the rest.
	if d := p.Evaluate(PlatformJunos, "show route 192.0.2.1 extensive"); d.Allowed {
		t.Fatal("allow_regex must match the whole command")
	}
	if d := p.Evaluate(PlatformJunos, "request show route 192.0.2.1"); d.Allowed {
		t.Fatal("allow_regex must be anchored at the start")
	}
}

func TestAllowPrefixIsTokenWise(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
platforms:
  iosxr:
    allow_prefixes: ["show interfaces"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(PlatformIOSXR, "show interfaces brief"); !d.Allowed {
		t.Fatalf("want allowed, got %+v", d)
	}
	for _, cmd := range []string{"show interfacesx", "show interface", "show version", "show"} {
		if d := p.Evaluate(PlatformIOSXR, cmd); d.Allowed {
			t.Errorf("%q allowed by token prefix %q", cmd, "show interfaces")
		}
	}
}

func TestPlatformDenyIsScoped(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
platforms:
  vrp:
    allow_prefixes: [display]
    deny_tokens: [current-configuration]
  iosxr:
    allow_prefixes: [show]
`))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Evaluate(PlatformVRP, "display current-configuration"); d.Allowed {
		t.Fatal("platform deny token ignored")
	}
	if d := p.Evaluate(PlatformIOSXR, "show current-configuration"); !d.Allowed {
		t.Fatal("platform deny token leaked into another platform")
	}
}

func TestParseRejectsBadPolicies(t *testing.T) {
	cases := map[string]string{
		"wrong version":    "version: 2\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n",
		"no platforms":     "version: 1\n",
		"unknown platform": "version: 1\nplatforms:\n  ios:\n    allow_prefixes: [show]\n",
		"typo field":       "version: 1\nplatforms:\n  iosxr:\n    allow_prefix: [show]\n",
		"allows nothing":   "version: 1\nplatforms:\n  iosxr: {}\n",
		"bad regex":        "version: 1\nplatforms:\n  iosxr:\n    allow_regex: ['show (']\n",
		"bad deny regex":   "version: 1\ndeny_regex: ['(']\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n",
		"multiword token":  "version: 1\ndeny_tokens: ['conf t']\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n",
		"empty prefix":     "version: 1\nplatforms:\n  iosxr:\n    allow_prefixes: ['  ']\n",
		"negative max len": "version: 1\nmax_command_length: -1\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n",
		"huge max len":     "version: 1\nmax_command_length: 100000\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n",
		"not yaml":         "{{{",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatalf("policy accepted:\n%s", src)
			}
		})
	}
}

func TestEveryPrintableMetacharDenied(t *testing.T) {
	p := examplePolicy(t)
	for _, c := range forbiddenChars {
		cmd := "show version " + string(c)
		if d := p.Evaluate(PlatformIOSXR, cmd); d.Allowed {
			t.Errorf("%q allowed", cmd)
		}
	}
}

// FuzzEvaluate checks invariants that must hold for any input: an allowed
// command contains no line break or forbidden byte, and its normalized form
// is what the device would receive.
func FuzzEvaluate(f *testing.F) {
	p, err := Parse([]byte("version: 1\nplatforms:\n  iosxr:\n    allow_prefixes: [show]\n"))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"show version", "show version; reload", "show\nreload", "show   x", "SHOW  bgp"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		d := p.Evaluate(PlatformIOSXR, cmd)
		if !d.Allowed {
			return
		}
		if !strings.HasPrefix(strings.ToLower(d.Normalized), "show") {
			t.Fatalf("allowed %q normalized to %q", cmd, d.Normalized)
		}
		for i := 0; i < len(d.Normalized); i++ {
			c := d.Normalized[i]
			if c < 0x20 || c > 0x7e || strings.IndexByte(forbiddenChars, c) >= 0 {
				t.Fatalf("allowed %q contains byte 0x%02x", cmd, c)
			}
		}
	})
}

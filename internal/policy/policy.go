// Package policy decides whether a CLI command may be sent to a network
// device. The engine is default-deny: a command is allowed only when it
// survives character checks, matches no deny rule and matches at least one
// allow rule for the device's platform.
package policy

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Platform identifiers accepted in policy and inventory files.
const (
	PlatformSROS  = "sros"  // Nokia SR OS
	PlatformVRP   = "vrp"   // Huawei VRP
	PlatformIOSXR = "iosxr" // Cisco IOS XR
	PlatformJunos = "junos" // Juniper Junos
)

// KnownPlatforms lists every platform the engine understands.
var KnownPlatforms = []string{PlatformSROS, PlatformVRP, PlatformIOSXR, PlatformJunos}

// DefaultMaxCommandLength is used when the policy file does not set one.
const DefaultMaxCommandLength = 256

// File is the YAML representation of a policy.
type File struct {
	Version          int                     `yaml:"version"`
	MaxCommandLength int                     `yaml:"max_command_length"`
	DenyTokens       []string                `yaml:"deny_tokens"`
	DenyRegex        []string                `yaml:"deny_regex"`
	Platforms        map[string]PlatformFile `yaml:"platforms"`
}

// PlatformFile holds the per-platform rules.
type PlatformFile struct {
	// AllowPrefixes are matched token by token against the normalized
	// command: "show interfaces" allows "show interfaces brief" but not
	// "show interfacesx".
	AllowPrefixes []string `yaml:"allow_prefixes"`
	// AllowRegex patterns are anchored and must match the whole normalized
	// command.
	AllowRegex []string `yaml:"allow_regex"`
	// DenyTokens and DenyRegex add to the global deny lists for this
	// platform only.
	DenyTokens []string `yaml:"deny_tokens"`
	DenyRegex  []string `yaml:"deny_regex"`
}

// Decision is the result of evaluating one command.
type Decision struct {
	Allowed bool `json:"allowed"`
	// Normalized is the exact string that would be sent to the device:
	// whitespace collapsed, case preserved (VRF and policy names can be
	// case-sensitive). Rules are matched case-insensitively.
	// Empty when the command was rejected before normalization finished.
	Normalized string `json:"normalized,omitempty"`
	// Rule identifies the rule that produced the decision.
	Rule string `json:"rule"`
	// Reason is a human readable explanation.
	Reason string `json:"reason"`
}

type compiledPlatform struct {
	allowPrefixes [][]string
	allowRegex    []*regexp.Regexp
	denyTokens    map[string]bool
	denyRegex     []*regexp.Regexp
}

// Policy is a compiled, immutable policy. It is safe for concurrent use.
type Policy struct {
	maxLen    int
	platforms map[string]*compiledPlatform
}

// Load reads and compiles a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse compiles a policy from YAML bytes. Unknown fields are rejected so a
// typo such as "allow_prefix" cannot silently disable a rule.
func Parse(data []byte) (*Policy, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return Compile(f)
}

// Compile validates a policy and compiles its regular expressions.
func Compile(f File) (*Policy, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d (want 1)", f.Version)
	}
	if len(f.Platforms) == 0 {
		return nil, errors.New("policy: no platforms defined")
	}
	maxLen := f.MaxCommandLength
	if maxLen == 0 {
		maxLen = DefaultMaxCommandLength
	}
	if maxLen < 0 || maxLen > 4096 {
		return nil, fmt.Errorf("policy: max_command_length %d out of range 1..4096", maxLen)
	}

	globalDenyRegex, err := compileAll(f.DenyRegex, "deny_regex")
	if err != nil {
		return nil, err
	}

	p := &Policy{maxLen: maxLen, platforms: map[string]*compiledPlatform{}}
	for name, pf := range f.Platforms {
		if !isKnownPlatform(name) {
			return nil, fmt.Errorf("policy: unknown platform %q (known: %s)", name, strings.Join(KnownPlatforms, ", "))
		}
		cp := &compiledPlatform{denyTokens: map[string]bool{}}
		for _, t := range append(append([]string{}, f.DenyTokens...), pf.DenyTokens...) {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || strings.ContainsRune(t, ' ') {
				return nil, fmt.Errorf("policy: deny token %q must be a single word", t)
			}
			cp.denyTokens[t] = true
		}
		for _, pref := range pf.AllowPrefixes {
			toks := strings.Fields(strings.ToLower(pref))
			if len(toks) == 0 {
				return nil, fmt.Errorf("policy: platform %s has an empty allow prefix", name)
			}
			cp.allowPrefixes = append(cp.allowPrefixes, toks)
		}
		if cp.allowRegex, err = compileAll(pf.AllowRegex, name+".allow_regex"); err != nil {
			return nil, err
		}
		local, err := compileAll(pf.DenyRegex, name+".deny_regex")
		if err != nil {
			return nil, err
		}
		cp.denyRegex = append(append([]*regexp.Regexp{}, globalDenyRegex...), local...)
		if len(cp.allowPrefixes) == 0 && len(cp.allowRegex) == 0 {
			return nil, fmt.Errorf("policy: platform %s allows nothing; remove it or add allow rules", name)
		}
		p.platforms[name] = cp
	}
	return p, nil
}

// Platforms returns the platforms this policy has rules for, sorted.
func (p *Policy) Platforms() []string {
	out := make([]string, 0, len(p.platforms))
	for k := range p.platforms {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Evaluate decides whether command may be sent to a device of the given
// platform. It never returns an error: every failure is a deny decision.
func (p *Policy) Evaluate(platform, command string) Decision {
	cp, ok := p.platforms[platform]
	if !ok {
		return deny("platform", fmt.Sprintf("no rules for platform %q", platform))
	}
	norm, d := normalize(command, p.maxLen)
	if d != nil {
		return *d
	}
	lower := strings.ToLower(norm)
	tokens := strings.Split(lower, " ")

	// Deny rules always win over allow rules.
	for _, t := range tokens {
		if cp.denyTokens[t] {
			return Decision{Normalized: norm, Rule: "deny_token:" + t, Reason: fmt.Sprintf("token %q is on the deny list", t)}
		}
	}
	for _, re := range cp.denyRegex {
		if re.MatchString(lower) {
			return Decision{Normalized: norm, Rule: "deny_regex:" + re.String(), Reason: "command matches a deny pattern"}
		}
	}

	for _, pref := range cp.allowPrefixes {
		if hasTokenPrefix(tokens, pref) {
			return Decision{Allowed: true, Normalized: norm, Rule: "allow_prefix:" + strings.Join(pref, " "), Reason: "matches allowed prefix"}
		}
	}
	for _, re := range cp.allowRegex {
		if re.MatchString(lower) {
			return Decision{Allowed: true, Normalized: norm, Rule: "allow_regex:" + re.String(), Reason: "matches allowed pattern"}
		}
	}
	return Decision{Normalized: norm, Rule: "default_deny", Reason: "no allow rule matches (default deny)"}
}

// forbiddenChars are rejected anywhere in a command. They are chaining,
// piping, redirection, quoting, escaping, comment or CLI-help characters on
// at least one supported platform. Rejecting them outright is cruder than
// parsing each CLI grammar, but it is easy to reason about.
const forbiddenChars = ";|&<>`$\\\"'#!?{}()[]*^~%"

func normalize(cmd string, maxLen int) (string, *Decision) {
	if len(cmd) > maxLen {
		d := deny("length", fmt.Sprintf("command is %d bytes; limit is %d", len(cmd), maxLen))
		return "", &d
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == '\n' || c == '\r':
			d := deny("newline", "line breaks would send a second command")
			return "", &d
		case c == '\t':
			d := deny("control_char", "tab triggers CLI completion")
			return "", &d
		case c < 0x20 || c == 0x7f:
			d := deny("control_char", fmt.Sprintf("control character 0x%02x", c))
			return "", &d
		case c > 0x7e:
			d := deny("non_ascii", "only printable ASCII is accepted")
			return "", &d
		case strings.IndexByte(forbiddenChars, c) >= 0:
			d := deny("metachar", fmt.Sprintf("character %q is not allowed (chaining, piping, redirection or quoting)", c))
			return "", &d
		}
	}
	norm := strings.Join(strings.Fields(cmd), " ")
	if norm == "" {
		d := deny("empty", "empty command")
		return "", &d
	}
	return norm, nil
}

func hasTokenPrefix(tokens, prefix []string) bool {
	if len(prefix) > len(tokens) {
		return false
	}
	for i := range prefix {
		if tokens[i] != prefix[i] {
			return false
		}
	}
	return true
}

func compileAll(patterns []string, field string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, s := range patterns {
		re, err := regexp.Compile("^(?:" + s + ")$")
		if err != nil {
			return nil, fmt.Errorf("policy: %s %q: %w", field, s, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func isKnownPlatform(name string) bool {
	for _, k := range KnownPlatforms {
		if k == name {
			return true
		}
	}
	return false
}

func deny(rule, reason string) Decision {
	return Decision{Rule: rule, Reason: reason}
}

// Command net-mcp-readonly is an MCP server that lets AI agents run only
// policy-approved, read-only CLI commands on network devices over SSH.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"github.com/ogzhncnmr/net-mcp-readonly/internal/audit"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/device"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/policy"
	"github.com/ogzhncnmr/net-mcp-readonly/internal/server"
)

const usage = `net-mcp-readonly - read-only network CLI access for AI agents (MCP, stdio)

Usage:
  net-mcp-readonly serve        -policy FILE -inventory FILE -audit FILE [-actor NAME] [-max-concurrent N]
  net-mcp-readonly check        -policy FILE -platform iosxr|junos|vrp|sros "COMMAND"
  net-mcp-readonly verify-audit FILE
  net-mcp-readonly keyring-set  SERVICE USER
  net-mcp-readonly version

"check" exits 0 when the command is allowed and 1 when it is denied.
"keyring-set" stores a device password in the OS keyring for use as
credentials: keyring:SERVICE/USER in the inventory.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr)
	case "check":
		return check(args[1:], stdout, stderr)
	case "verify-audit":
		return verifyAudit(args[1:], stdout, stderr)
	case "keyring-set":
		return keyringSet(args[1:], os.Stdin, stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, server.Version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func serve(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "policy YAML file (required)")
	invPath := fs.String("inventory", "", "inventory YAML file (required)")
	auditPath := fs.String("audit", "", "audit log file, JSON Lines, created if missing (required)")
	actor := fs.String("actor", "", "identity recorded in the audit log (default: OS user)")
	maxConc := fs.Int("max-concurrent", 4, "maximum simultaneous device sessions")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *invPath == "" || *auditPath == "" {
		fmt.Fprintln(stderr, "serve: -policy, -inventory and -audit are required")
		return 2
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	inv, err := device.LoadInventory(*invPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, d := range inv.Devices {
		if !contains(pol.Platforms(), d.Platform) {
			fmt.Fprintf(stderr, "warning: device %s uses platform %s, which has no policy rules; every command to it will be denied\n", d.Name, d.Platform)
		}
	}
	runner, err := device.NewSSHRunner(inv.KnownHosts, device.DefaultResolver)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	log, err := audit.Open(*auditPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer log.Close()

	if *actor == "" {
		if u, err := user.Current(); err == nil {
			*actor = u.Username
		} else {
			*actor = "unknown"
		}
	}
	srv := server.New(server.Config{
		Policy: pol, Inventory: inv, Runner: runner, Audit: log,
		Actor: *actor, MaxConcurrent: *maxConc,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "policy YAML file (required)")
	platform := fs.String("platform", "", "iosxr, junos, vrp or sros (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *platform == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, `check: usage: check -policy FILE -platform NAME "COMMAND"`)
		return 2
	}
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	d := pol.Evaluate(*platform, fs.Arg(0))
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(d)
	if d.Allowed {
		return 0
	}
	return 1
}

func verifyAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "verify-audit: usage: verify-audit FILE")
		return 2
	}
	seq, last, err := audit.VerifyFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "FAIL after %d good entries: %v\n", seq, err)
		return 1
	}
	fmt.Fprintf(stdout, "OK %d entries, last hash %s\n", seq, last)
	return 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// keyringSet stores a password for keyring:SERVICE/USER. The password is
// read from the terminal without echo, or as one line from piped stdin.
func keyringSet(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] == "" || args[1] == "" {
		fmt.Fprintln(stderr, "keyring-set: usage: keyring-set SERVICE USER")
		return 2
	}
	var pw []byte
	var err error
	if term.IsTerminal(int(stdin.Fd())) {
		fmt.Fprintf(stderr, "Password for %s/%s: ", args[0], args[1])
		pw, err = term.ReadPassword(int(stdin.Fd()))
		fmt.Fprintln(stderr)
	} else {
		var line string
		line, err = bufio.NewReader(stdin).ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(pw) == 0 {
		fmt.Fprintln(stderr, "keyring-set: empty password")
		return 1
	}
	if err := keyring.Set(args[0], args[1], string(pw)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "stored; reference it as credentials: keyring:%s/%s\n", args[0], args[1])
	return 0
}

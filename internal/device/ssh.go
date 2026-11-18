package device

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Result is the output of one command.
type Result struct {
	Output    string
	Truncated bool
}

// Runner sends a single, already-approved command to a device.
type Runner interface {
	Run(ctx context.Context, dev Device, command string) (Result, error)
}

// ErrPromptChanged means the device prompt after the command differed from
// the operational prompt seen at login, e.g. the CLI entered another mode.
var ErrPromptChanged = errors.New("device prompt changed or never returned; session closed")

// SSHRunner opens one interactive SSH session per command: log in, wait for
// the operational prompt, disable paging, send the command, read until the
// same prompt returns, disconnect.
type SSHRunner struct {
	HostKeys    ssh.HostKeyCallback
	Credentials CredentialResolver
	// Settle is how long the output must stay quiet after a prompt-looking
	// line before it is accepted as the real prompt. Default 200ms.
	Settle time.Duration
}

// NewSSHRunner builds a runner that verifies host keys against an OpenSSH
// known_hosts file.
func NewSSHRunner(knownHostsPath string, creds CredentialResolver) (*SSHRunner, error) {
	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	return &SSHRunner{HostKeys: cb, Credentials: creds}, nil
}

// Run implements Runner.
func (r *SSHRunner) Run(ctx context.Context, dev Device, command string) (Result, error) {
	drv, ok := drivers[dev.Platform]
	if !ok {
		return Result{}, fmt.Errorf("unknown platform %q", dev.Platform)
	}
	if strings.ContainsAny(command, "\r\n") {
		// The policy engine already rejects this; refuse again here so the
		// runner is safe even if someone calls it directly.
		return Result{}, errors.New("command contains a line break")
	}
	cred, err := r.Credentials.Resolve(dev.Credentials)
	if err != nil {
		return Result{}, fmt.Errorf("credentials: %w", err)
	}
	settle := r.Settle
	if settle == 0 {
		settle = 200 * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(ctx, dev.ConnectTimeout+dev.CommandTimeout)
	defer cancel()

	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            cred.authMethods(),
		HostKeyCallback: r.HostKeys,
		Timeout:         dev.ConnectTimeout,
	}
	dialer := net.Dialer{Timeout: dev.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", dev.Addr())
	if err != nil {
		return Result{}, fmt.Errorf("connect: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(dev.ConnectTimeout))
	cc, chans, reqs, err := ssh.NewClientConn(conn, dev.Addr(), cfg)
	if err != nil {
		conn.Close()
		return Result{}, fmt.Errorf("ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	sess, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	// A wide terminal keeps long lines from wrapping.
	if err := sess.RequestPty("vt100", 0, 511, modes); err != nil {
		return Result{}, fmt.Errorf("pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	out := newOutputBuffer(dev.MaxOutputBytes)
	sess.Stdout = out
	sess.Stderr = out
	if err := sess.Shell(); err != nil {
		return Result{}, fmt.Errorf("shell: %w", err)
	}

	loginDeadline := time.Now().Add(dev.ConnectTimeout)
	prompt, err := out.waitFor(ctx, loginDeadline, settle, drv.prompt.MatchString)
	if err != nil {
		return Result{}, fmt.Errorf("waiting for login prompt: %w", err)
	}
	isPrompt := func(line string) bool { return line == prompt }

	paging := drv.pagingCommand
	if dev.PagingCommand != "" {
		paging = dev.PagingCommand
	}
	if paging != "" {
		out.reset()
		if _, err := io.WriteString(stdin, paging+"\n"); err != nil {
			return Result{}, err
		}
		if _, err := out.waitFor(ctx, time.Now().Add(dev.CommandTimeout), settle, isPrompt); err != nil {
			return Result{}, fmt.Errorf("disabling paging: %w", err)
		}
	}

	out.reset()
	if _, err := io.WriteString(stdin, command+"\n"); err != nil {
		return Result{}, err
	}
	if _, err := out.waitFor(ctx, time.Now().Add(dev.CommandTimeout), settle, isPrompt); err != nil {
		if errors.Is(err, errTimeout) {
			return Result{}, fmt.Errorf("%w (expected %q)", ErrPromptChanged, prompt)
		}
		return Result{}, err
	}
	body, truncated := out.snapshot()
	return Result{Output: cleanOutput(body, command, prompt), Truncated: truncated}, nil
}

var errTimeout = errors.New("timed out waiting for prompt")

// outputBuffer collects session output up to a byte limit while always
// keeping the most recent bytes so the prompt can still be found after the
// limit is reached.
type outputBuffer struct {
	mu        sync.Mutex
	max       int
	data      []byte
	tail      []byte
	truncated bool
	changed   chan struct{}
	lastWrite time.Time
}

const tailSize = 4096

func newOutputBuffer(max int) *outputBuffer {
	return &outputBuffer{max: max, changed: make(chan struct{})}
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.max - len(b.data)
	if room > 0 {
		n := min(room, len(p))
		b.data = append(b.data, p[:n]...)
	}
	if len(p) > room {
		b.truncated = true
	}
	b.tail = append(b.tail, p...)
	if len(b.tail) > tailSize {
		b.tail = append([]byte(nil), b.tail[len(b.tail)-tailSize:]...)
	}
	b.lastWrite = time.Now()
	close(b.changed)
	b.changed = make(chan struct{})
	return len(p), nil
}

func (b *outputBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data, b.tail, b.truncated = nil, nil, false
}

func (b *outputBuffer) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data), b.truncated
}

// waitFor blocks until the last line of output satisfies match and no new
// output has arrived for settle. It returns that last line.
func (b *outputBuffer) waitFor(ctx context.Context, deadline time.Time, settle time.Duration, match func(string) bool) (string, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		b.mu.Lock()
		last := lastLine(string(b.tail))
		quiet := time.Since(b.lastWrite)
		ch := b.changed
		b.mu.Unlock()

		var settleTimer *time.Timer
		var settleC <-chan time.Time
		if match(last) {
			if quiet >= settle {
				return last, nil
			}
			settleTimer = time.NewTimer(settle - quiet)
			settleC = settleTimer.C
		}
		var err error
		select {
		case <-ch:
		case <-settleC:
		case <-timer.C:
			err = errTimeout
		case <-ctx.Done():
			err = ctx.Err()
		}
		if settleTimer != nil {
			settleTimer.Stop()
		}
		if err != nil {
			return "", err
		}
	}
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]`)

func stripControl(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return -1
	}, s)
	return s
}

func lastLine(s string) string {
	s = stripControl(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimRight(s, " ")
}

// cleanOutput removes the echoed command line and the trailing prompt.
func cleanOutput(raw, command, prompt string) string {
	s := stripControl(raw)
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == strings.TrimSpace(command) {
		lines = lines[1:]
	}
	if n := len(lines); n > 0 && strings.TrimRight(lines[n-1], " ") == prompt {
		lines = lines[:n-1]
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n ")
}

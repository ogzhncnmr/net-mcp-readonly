// Package mockdevice is an in-process SSH server that imitates a network
// device CLI closely enough to test the runner: password login, PTY + shell,
// character echo, a prompt, canned command output and prompt changes for
// mode-switching commands. It is for tests only.
package mockdevice

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Config describes the simulated device.
type Config struct {
	Username string
	Password string
	Banner   string
	Prompt   string
	// Responses maps an exact command line to its output. Output uses "\n";
	// the server converts it to "\r\n" like a real terminal.
	Responses map[string]string
	// ModeChanges maps a command to the prompt shown after it, simulating
	// e.g. "configure terminal".
	ModeChanges map[string]string
	// Silent commands produce no prompt at all afterwards.
	Silent map[string]bool
}

// Device is a running mock device.
type Device struct {
	cfg      Config
	ln       net.Listener
	hostKey  ssh.Signer
	mu       sync.Mutex
	received []string
	wg       sync.WaitGroup
}

// Start listens on 127.0.0.1 on a random port.
func Start(cfg Config) (*Device, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &Device{cfg: cfg, ln: ln, hostKey: signer}
	d.wg.Add(1)
	go d.accept()
	return d, nil
}

// Addr returns host:port.
func (d *Device) Addr() string { return d.ln.Addr().String() }

// HostKey returns the server's public host key.
func (d *Device) HostKey() ssh.PublicKey { return d.hostKey.PublicKey() }

// Received returns every command line the device received, in order,
// including paging commands sent by the runner.
func (d *Device) Received() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.received...)
}

// Close stops the listener.
func (d *Device) Close() error {
	err := d.ln.Close()
	d.wg.Wait()
	return err
}

func (d *Device) accept() {
	defer d.wg.Done()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == d.cfg.Username && string(pw) == d.cfg.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(d.hostKey)
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.serve(conn, cfg)
	}
}

func (d *Device) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go d.session(ch, creqs)
	}
}

func (d *Device) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	started := false
	for req := range reqs {
		switch req.Type {
		case "pty-req", "window-change", "env":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			if !started {
				started = true
				go func() {
					d.cli(ch)
					_ = ch.Close()
				}()
			}
		default: // exec, subsystem, ...
			_ = req.Reply(false, nil)
		}
	}
}

func (d *Device) cli(rw io.ReadWriter) {
	prompt := d.cfg.Prompt
	w := func(s string) { _, _ = io.WriteString(rw, strings.ReplaceAll(s, "\n", "\r\n")) }
	if d.cfg.Banner != "" {
		w(d.cfg.Banner + "\n")
	}
	w(prompt)
	r := bufio.NewReader(rw)
	var line []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return
		}
		if c != '\r' && c != '\n' {
			line = append(line, c)
			_, _ = rw.Write([]byte{c}) // terminal echo
			continue
		}
		cmd := string(line)
		line = line[:0]
		w("\n")
		d.mu.Lock()
		d.received = append(d.received, cmd)
		d.mu.Unlock()
		if cmd == "" {
			w(prompt)
			continue
		}
		if cmd == "exit" || cmd == "quit" || cmd == "logout" {
			return
		}
		if out, ok := d.cfg.Responses[cmd]; ok {
			if out != "" {
				w(out + "\n")
			}
		} else if np, ok := d.cfg.ModeChanges[cmd]; ok {
			prompt = np
		} else {
			w("% Invalid input detected\n")
		}
		if d.cfg.Silent[cmd] {
			continue
		}
		w(prompt)
	}
}

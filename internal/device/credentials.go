package device

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// Credential is what the SSH client authenticates with. Secrets are never
// read from the inventory file itself.
type Credential struct {
	Username string
	Password string
	Signer   ssh.Signer
}

type credentialRef struct {
	kind    string // "env" or "keyring"
	prefix  string // env
	service string // keyring
	user    string // keyring
}

var envPrefixRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,62}$`)

// parseCredentialRef accepts:
//
//	env:PREFIX              PREFIX_USERNAME plus PREFIX_PASSWORD and/or PREFIX_KEY_FILE
//	keyring:SERVICE/USER    password stored in the OS keyring under SERVICE, USER
func parseCredentialRef(ref string) (credentialRef, error) {
	kind, rest, ok := strings.Cut(ref, ":")
	if !ok {
		return credentialRef{}, fmt.Errorf("credentials %q: want env:PREFIX or keyring:SERVICE/USER", ref)
	}
	switch kind {
	case "env":
		if !envPrefixRe.MatchString(rest) {
			return credentialRef{}, fmt.Errorf("credentials %q: env prefix must match %s", ref, envPrefixRe)
		}
		return credentialRef{kind: kind, prefix: rest}, nil
	case "keyring":
		svc, user, ok := strings.Cut(rest, "/")
		if !ok || svc == "" || user == "" {
			return credentialRef{}, fmt.Errorf("credentials %q: want keyring:SERVICE/USER", ref)
		}
		return credentialRef{kind: kind, service: svc, user: user}, nil
	}
	return credentialRef{}, fmt.Errorf("credentials %q: unknown source %q", ref, kind)
}

// CredentialResolver turns an inventory credential reference into secrets.
type CredentialResolver interface {
	Resolve(ref string) (Credential, error)
}

// EnvKeyringResolver reads environment variables and the OS keyring. Getenv
// and ReadFile can be replaced in tests.
type EnvKeyringResolver struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
}

// DefaultResolver uses the real environment, file system and OS keyring.
var DefaultResolver CredentialResolver = EnvKeyringResolver{Getenv: os.Getenv, ReadFile: os.ReadFile}

// Resolve implements CredentialResolver.
func (r EnvKeyringResolver) Resolve(ref string) (Credential, error) {
	cr, err := parseCredentialRef(ref)
	if err != nil {
		return Credential{}, err
	}
	switch cr.kind {
	case "keyring":
		pw, err := keyring.Get(cr.service, cr.user)
		if err != nil {
			return Credential{}, fmt.Errorf("keyring %s/%s: %w", cr.service, cr.user, err)
		}
		return Credential{Username: cr.user, Password: pw}, nil
	default: // env
		c := Credential{
			Username: r.Getenv(cr.prefix + "_USERNAME"),
			Password: r.Getenv(cr.prefix + "_PASSWORD"),
		}
		if c.Username == "" {
			return Credential{}, fmt.Errorf("%s_USERNAME is not set", cr.prefix)
		}
		if keyFile := r.Getenv(cr.prefix + "_KEY_FILE"); keyFile != "" {
			pem, err := r.ReadFile(keyFile)
			if err != nil {
				return Credential{}, fmt.Errorf("%s_KEY_FILE: %w", cr.prefix, err)
			}
			var signer ssh.Signer
			if pass := r.Getenv(cr.prefix + "_KEY_PASSPHRASE"); pass != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(pass))
			} else {
				signer, err = ssh.ParsePrivateKey(pem)
			}
			if err != nil {
				return Credential{}, fmt.Errorf("%s_KEY_FILE: %w", cr.prefix, err)
			}
			c.Signer = signer
		}
		if c.Password == "" && c.Signer == nil {
			return Credential{}, errors.New(cr.prefix + "_PASSWORD or " + cr.prefix + "_KEY_FILE must be set")
		}
		return c, nil
	}
}

func (c Credential) authMethods() []ssh.AuthMethod {
	var m []ssh.AuthMethod
	if c.Signer != nil {
		m = append(m, ssh.PublicKeys(c.Signer))
	}
	if c.Password != "" {
		pw := c.Password
		m = append(m, ssh.Password(pw))
		// Many network OSes offer keyboard-interactive instead of password.
		m = append(m, ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	return m
}

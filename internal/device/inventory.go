// Package device holds the device inventory, credential lookup and the SSH
// runner that sends already-approved commands to devices.
package device

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Device is one entry from the inventory.
type Device struct {
	Name           string        `yaml:"name"`
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	Platform       string        `yaml:"platform"`
	Credentials    string        `yaml:"credentials"`
	PagingCommand  string        `yaml:"paging_command"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	CommandTimeout time.Duration `yaml:"command_timeout"`
	MaxOutputBytes int           `yaml:"max_output_bytes"`
}

// Addr returns host:port.
func (d Device) Addr() string { return net.JoinHostPort(d.Host, fmt.Sprint(d.Port)) }

// Inventory is the parsed inventory file.
type Inventory struct {
	// KnownHosts is the OpenSSH known_hosts file used to verify device host
	// keys. It is required; there is no option to skip host key checks.
	KnownHosts string   `yaml:"known_hosts"`
	Defaults   Defaults `yaml:"defaults"`
	Devices    []Device `yaml:"devices"`

	byName map[string]Device
}

// Defaults apply to devices that leave a field unset.
type Defaults struct {
	Port           int           `yaml:"port"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	CommandTimeout time.Duration `yaml:"command_timeout"`
	MaxOutputBytes int           `yaml:"max_output_bytes"`
}

var deviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// LoadInventory reads an inventory file. A relative known_hosts path is
// resolved against the inventory file's directory.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}
	inv, err := ParseInventory(data)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(inv.KnownHosts) {
		inv.KnownHosts = filepath.Join(filepath.Dir(path), inv.KnownHosts)
	}
	return inv, nil
}

// ParseInventory parses and validates inventory YAML.
func ParseInventory(data []byte) (*Inventory, error) {
	var inv Inventory
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	if inv.KnownHosts == "" {
		return nil, errors.New("inventory: known_hosts is required")
	}
	if len(inv.Devices) == 0 {
		return nil, errors.New("inventory: no devices")
	}
	d := inv.Defaults
	if d.Port == 0 {
		d.Port = 22
	}
	if d.ConnectTimeout == 0 {
		d.ConnectTimeout = 10 * time.Second
	}
	if d.CommandTimeout == 0 {
		d.CommandTimeout = 30 * time.Second
	}
	if d.MaxOutputBytes == 0 {
		d.MaxOutputBytes = 1 << 20
	}
	inv.byName = map[string]Device{}
	for i := range inv.Devices {
		dev := &inv.Devices[i]
		if !deviceNameRe.MatchString(dev.Name) {
			return nil, fmt.Errorf("inventory: device %d: invalid name %q", i, dev.Name)
		}
		if _, dup := inv.byName[dev.Name]; dup {
			return nil, fmt.Errorf("inventory: duplicate device %q", dev.Name)
		}
		if dev.Host == "" {
			return nil, fmt.Errorf("inventory: device %s: host is required", dev.Name)
		}
		if _, ok := drivers[dev.Platform]; !ok {
			return nil, fmt.Errorf("inventory: device %s: unknown platform %q", dev.Name, dev.Platform)
		}
		if _, err := parseCredentialRef(dev.Credentials); err != nil {
			return nil, fmt.Errorf("inventory: device %s: %w", dev.Name, err)
		}
		if strings.ContainsAny(dev.PagingCommand, "\r\n") {
			return nil, fmt.Errorf("inventory: device %s: paging_command must be one line", dev.Name)
		}
		if dev.Port == 0 {
			dev.Port = d.Port
		}
		if dev.Port < 1 || dev.Port > 65535 {
			return nil, fmt.Errorf("inventory: device %s: port %d out of range", dev.Name, dev.Port)
		}
		if dev.ConnectTimeout == 0 {
			dev.ConnectTimeout = d.ConnectTimeout
		}
		if dev.CommandTimeout == 0 {
			dev.CommandTimeout = d.CommandTimeout
		}
		if dev.MaxOutputBytes == 0 {
			dev.MaxOutputBytes = d.MaxOutputBytes
		}
		inv.byName[dev.Name] = *dev
	}
	return &inv, nil
}

// Get returns the device with the given name.
func (inv *Inventory) Get(name string) (Device, bool) {
	d, ok := inv.byName[name]
	return d, ok
}

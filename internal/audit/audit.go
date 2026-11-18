// Package audit writes an append-only, hash-chained JSON Lines log.
//
// Every entry carries the SHA-256 of the previous entry, so editing,
// deleting or reordering lines breaks the chain and Verify reports the first
// bad line. The chain detects tampering; it does not prevent someone with
// write access from rewriting the whole file. Ship the log off the host if
// that matters.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// GenesisHash is the prev_hash of the first entry.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event types.
const (
	EventCheck  = "check"  // dry-run policy evaluation, nothing sent
	EventDeny   = "deny"   // command rejected, nothing sent
	EventAllow  = "allow"  // command accepted, about to be sent
	EventResult = "result" // outcome of an allowed command
)

// Entry is one audit record. Field order is fixed by the struct, which keeps
// the hashed JSON stable.
type Entry struct {
	Seq         uint64 `json:"seq"`
	Time        string `json:"time"`
	Event       string `json:"event"`
	Actor       string `json:"actor"`
	Client      string `json:"client,omitempty"`
	Tool        string `json:"tool"`
	Device      string `json:"device,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Command     string `json:"command,omitempty"`
	Normalized  string `json:"normalized,omitempty"`
	Allowed     bool   `json:"allowed"`
	Rule        string `json:"rule,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Error       string `json:"error,omitempty"`
	OutputBytes int    `json:"output_bytes,omitempty"`
	OutputHash  string `json:"output_sha256,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
}

// Log is an append-only audit log. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	prev string
	now  func() time.Time
}

// Open opens path for appending, creating it with mode 0600 if needed. An
// existing file is verified first so a new entry is never chained onto a
// broken log.
func Open(path string) (*Log, error) {
	seq, prev, err := VerifyFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit: existing log failed verification: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	return &Log{f: f, seq: seq, prev: prev, now: time.Now}, nil
}

// Append fills Seq, Time, PrevHash and Hash, then writes and syncs the entry.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.seq + 1
	e.Time = l.now().UTC().Format(time.RFC3339Nano)
	e.PrevHash = l.prev
	e.Hash = ""
	h, err := hashEntry(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return Entry{}, fmt.Errorf("audit: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, fmt.Errorf("audit: sync: %w", err)
	}
	l.seq, l.prev = e.Seq, e.Hash
	return e, nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// hashEntry returns SHA-256 over the canonical JSON of e with Hash empty.
func hashEntry(e Entry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyFile checks the chain in path and returns the last sequence number
// and hash. A missing file returns os.ErrNotExist wrapped, with the genesis
// state.
func VerifyFile(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, GenesisHash, err
	}
	defer f.Close()
	return Verify(f)
}

// Verify checks a log stream. It returns the last good sequence number and
// hash, and an error naming the first line that breaks the chain.
func Verify(r io.Reader) (uint64, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var seq uint64
	prev := GenesisHash
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			return seq, prev, fmt.Errorf("line %d: empty line", line)
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return seq, prev, fmt.Errorf("line %d: %w", line, err)
		}
		if e.Seq != seq+1 {
			return seq, prev, fmt.Errorf("line %d: seq %d, want %d", line, e.Seq, seq+1)
		}
		if e.PrevHash != prev {
			return seq, prev, fmt.Errorf("line %d: prev_hash does not match previous entry", line)
		}
		want, err := hashEntry(e)
		if err != nil {
			return seq, prev, fmt.Errorf("line %d: %w", line, err)
		}
		if e.Hash != want {
			return seq, prev, fmt.Errorf("line %d: hash mismatch (entry modified)", line)
		}
		seq, prev = e.Seq, e.Hash
	}
	if err := sc.Err(); err != nil {
		return seq, prev, fmt.Errorf("line %d: %w", line+1, err)
	}
	return seq, prev, nil
}

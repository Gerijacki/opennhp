// Package audit provides a tamper-evident security audit ledger for NHP.
//
// The daemons already emit a free-text "[Audit]" log stream, but plain
// text on disk offers no integrity: anyone who can write the file can edit
// or delete lines without leaving a trace. This package records security
// events as append-only JSON lines linked into a hash chain — each entry
// carries the hash of the entry before it, so deleting, editing or
// reordering any line breaks the chain and is detectable after the fact.
//
// An optional HMAC key binds the chain to a secret the log file itself
// does not contain, so an attacker who can rewrite the whole file still
// cannot forge a chain that verifies.
//
// The ledger is opt-in and off by default; enabling it is a config choice
// on the server. It runs alongside — not in place of — the existing text
// audit log.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Severity levels for an event, ordered from least to most urgent.
const (
	SeverityInfo   = "info"
	SeverityNotice = "notice"
	SeverityWarn   = "warn"
	SeverityAlert  = "alert"
)

// Event is one record in the ledger. Fields are ordered so the JSON
// encoding is deterministic (encoding/json emits struct fields in
// declaration order and map keys sorted), which is what makes the hash
// reproducible during verification.
type Event struct {
	Seq      uint64            `json:"seq"`
	Time     string            `json:"time"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	Fields   map[string]string `json:"fields,omitempty"`
	PrevHash string            `json:"prevHash"`
	Hash     string            `json:"hash"`
	Sig      string            `json:"sig,omitempty"`
}

// chainInput is the canonical byte sequence the Hash is computed over: the
// event without its own Hash/Sig. Keeping it a distinct type (rather than
// blanking fields on Event) guarantees the marshaled shape used for
// hashing never accidentally drifts from what verification recomputes.
type chainInput struct {
	Seq      uint64            `json:"seq"`
	Time     string            `json:"time"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	Fields   map[string]string `json:"fields,omitempty"`
	PrevHash string            `json:"prevHash"`
}

func (e *Event) chainBytes() ([]byte, error) {
	return json.Marshal(chainInput{
		Seq:      e.Seq,
		Time:     e.Time,
		Type:     e.Type,
		Severity: e.Severity,
		Fields:   e.Fields,
		PrevHash: e.PrevHash,
	})
}

// computeHash returns the hex SHA-256 of the event's canonical bytes. This
// is the chain link and is always present, key or no key.
func computeHash(e *Event) (string, error) {
	b, err := e.chainBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// computeSig returns the hex HMAC-SHA256 over "chainBytes || hash" using
// key. Empty string when no key is configured.
func computeSig(e *Event, key []byte) (string, error) {
	if len(key) == 0 {
		return "", nil
	}
	b, err := e.chainBytes()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	mac.Write([]byte(e.Hash))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// genesisHash is the PrevHash of the very first entry — a fixed, well-known
// value so an empty ledger has a defined starting link.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Ledger is a concurrency-safe, append-only, hash-chained event writer.
type Ledger struct {
	// MalformedOnOpen is how many unparseable lines Open skipped while
	// resuming an existing ledger (a torn trailing write after a crash is
	// the usual cause). Non-zero means the file deserves an `audit verify`
	// and an operator's attention; it is not fatal and the chain simply
	// continues from the last good entry. Read-only after Open.
	MalformedOnOpen int

	mu       sync.Mutex
	w        io.Writer
	closer   io.Closer
	hmacKey  []byte
	fsync    bool
	seq      uint64
	lastHash string
}

// Options configures a Ledger.
type Options struct {
	// HMACKey, when non-empty, adds an HMAC signature to every entry that
	// binds the chain to this secret.
	HMACKey []byte
	// Fsync flushes each entry to stable storage before returning. Safer
	// against crash/power loss at the cost of throughput; audit logs are
	// low-volume so this is usually worth enabling.
	Fsync bool
}

// NewLedger writes to w with no restart continuity. Mainly for tests and
// callers that manage their own file handle; production servers use
// Open, which resumes an existing chain across restarts.
func NewLedger(w io.Writer, opts Options) *Ledger {
	l := &Ledger{
		w:        w,
		hmacKey:  opts.HMACKey,
		fsync:    opts.Fsync,
		lastHash: genesisHash,
	}
	if c, ok := w.(io.Closer); ok {
		l.closer = c
	}
	return l
}

// Open opens (creating parent dirs as needed) the ledger file at path for
// append. If the file already exists its chain is scanned so new entries
// continue the existing sequence and hash chain — a server restart does
// not start a fresh, disconnected chain.
func Open(path string, opts Options) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}

	seq, last := uint64(0), genesisHash
	malformed := 0
	if f, err := os.Open(filepath.Clean(path)); err == nil {
		lastSeq, lastHash, bad, scanErr := scanTail(f)
		f.Close()
		if scanErr != nil {
			// Only a real I/O failure gets here; unparseable content is
			// tolerated by scanTail (see below).
			return nil, fmt.Errorf("audit: existing ledger %q is unreadable: %w", path, scanErr)
		}
		malformed = bad
		if lastHash != "" {
			seq, last = lastSeq, lastHash
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}

	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open for append: %w", err)
	}

	// If the file does not end in a newline, a previous append was torn
	// mid-write. Close that partial line off before appending, or the next
	// entry would be concatenated onto the fragment and be unparseable
	// too — turning one damaged line into two.
	if err := terminatePartialLine(f, path); err != nil {
		f.Close()
		return nil, err
	}

	l := NewLedger(f, opts)
	l.closer = f
	l.seq = seq
	l.lastHash = last
	l.MalformedOnOpen = malformed
	return l, nil
}

// terminatePartialLine writes a newline if the file is non-empty and its
// last byte is not already one.
func terminatePartialLine(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("audit: stat %q: %w", path, err)
	}
	if info.Size() == 0 {
		return nil
	}

	rf, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("audit: reopen %q: %w", path, err)
	}
	defer rf.Close()

	var lastByte [1]byte
	if _, err := rf.ReadAt(lastByte[:], info.Size()-1); err != nil {
		return fmt.Errorf("audit: read tail of %q: %w", path, err)
	}
	if lastByte[0] == '\n' {
		return nil
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("audit: terminate partial line in %q: %w", path, err)
	}
	return nil
}

// scanTail reads every line and returns the last parseable entry's seq and
// hash (so Open can continue the chain) plus a count of lines it could not
// parse. It parses only the fields it needs.
//
// Unparseable content is deliberately NOT an error. A crash or power loss
// mid-append leaves a torn trailing line, and a log-rotation tool can drop
// a stray line in; refusing to open the ledger in those cases would take
// the whole daemon down over a cosmetic log problem. Instead the chain
// resumes from the last good entry and the caller is told how many lines
// were skipped so it can log loudly. Detecting real tampering remains the
// job of VerifyChain / `audit verify`, which is the out-of-band tool for
// exactly that. Only a genuine I/O failure returns an error here.
func scanTail(r io.Reader) (uint64, string, int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var seq uint64
	var hash string
	malformed := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			malformed++
			continue
		}
		seq, hash = e.Seq, e.Hash
	}
	if err := sc.Err(); err != nil {
		return 0, "", malformed, err
	}
	return seq, hash, malformed, nil
}

// Log appends one event of the given type/severity with optional key/value
// fields. It is safe for concurrent use. The written entry links to the
// previous one via its hash.
func (l *Ledger) Log(evType, severity string, fields map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e := Event{
		Seq:      l.seq,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Type:     evType,
		Severity: severity,
		Fields:   fields,
		PrevHash: l.lastHash,
	}

	hash, err := computeHash(&e)
	if err != nil {
		l.seq-- // roll back so a failed write does not skip a sequence number
		return err
	}
	e.Hash = hash
	sig, err := computeSig(&e, l.hmacKey)
	if err != nil {
		l.seq--
		return err
	}
	e.Sig = sig

	line, err := json.Marshal(&e)
	if err != nil {
		l.seq--
		return err
	}
	line = append(line, '\n')
	if _, err := l.w.Write(line); err != nil {
		l.seq--
		return err
	}
	if l.fsync {
		if f, ok := l.w.(*os.File); ok {
			_ = f.Sync()
		}
	}

	l.lastHash = e.Hash
	return nil
}

// Close closes the underlying file if the ledger owns one.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

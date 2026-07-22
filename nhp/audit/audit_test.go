package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeN(t *testing.T, l *Ledger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Log("knock_denied", SeverityWarn, map[string]string{
			"srcIp":  "1.2.3.4",
			"reason": "peer_not_found",
		}); err != nil {
			t.Fatalf("Log #%d: %v", i, err)
		}
	}
}

func TestChainVerifiesIntact(t *testing.T) {
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{})
	writeN(t, l, 5)

	res := VerifyChain(bytes.NewReader(buf.Bytes()), nil)
	if res.Err != nil {
		t.Fatalf("expected intact chain, got err: %v", res.Err)
	}
	if res.Count != 5 {
		t.Fatalf("verified %d entries, want 5", res.Count)
	}
}

func TestDetectsAlteredField(t *testing.T) {
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{})
	writeN(t, l, 5)

	lines := splitLines(buf.Bytes())
	// Tamper with the "reason" field inside entry seq=3 while leaving its
	// stored hash untouched.
	var e Event
	if err := json.Unmarshal(lines[2], &e); err != nil {
		t.Fatal(err)
	}
	e.Fields["reason"] = "totally_fine"
	lines[2] = mustMarshal(t, &e)

	res := VerifyChain(bytes.NewReader(join(lines)), nil)
	if res.Err == nil {
		t.Fatal("expected verification failure for altered field")
	}
	if res.BadSeq != 3 {
		t.Fatalf("BadSeq=%d, want 3", res.BadSeq)
	}
}

func TestDetectsDeletedEntry(t *testing.T) {
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{})
	writeN(t, l, 5)

	lines := splitLines(buf.Bytes())
	// Remove entry seq=3; seq=4's prevHash now points at a hash that is
	// no longer the previous line.
	lines = append(lines[:2], lines[3:]...)

	res := VerifyChain(bytes.NewReader(join(lines)), nil)
	if res.Err == nil {
		t.Fatal("expected verification failure for deleted entry")
	}
	if res.BadSeq != 4 {
		t.Fatalf("BadSeq=%d, want 4", res.BadSeq)
	}
}

func TestDetectsTruncatedTail(t *testing.T) {
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{})
	writeN(t, l, 5)

	lines := splitLines(buf.Bytes())
	lines = lines[:4] // drop the last entry

	// Truncation alone still verifies as a valid (shorter) chain — that is
	// expected, hash chains detect edits/reorders, not a clean tail cut.
	// The count is what reveals the truncation to a caller who knows how
	// many entries there should be.
	res := VerifyChain(bytes.NewReader(join(lines)), nil)
	if res.Err != nil {
		t.Fatalf("truncated-but-consistent chain should verify, got: %v", res.Err)
	}
	if res.Count != 4 {
		t.Fatalf("Count=%d, want 4", res.Count)
	}
}

func TestHMACDetectsForgery(t *testing.T) {
	key := []byte("audit-signing-key")
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{HMACKey: key})
	writeN(t, l, 4)

	// A verifier with the right key accepts it.
	if res := VerifyChain(bytes.NewReader(buf.Bytes()), key); res.Err != nil {
		t.Fatalf("valid signed chain rejected: %v", res.Err)
	}

	// An attacker who rewrites an entry AND recomputes its plain hash (but
	// lacks the key) still fails the HMAC check.
	lines := splitLines(buf.Bytes())
	var e Event
	if err := json.Unmarshal(lines[1], &e); err != nil {
		t.Fatal(err)
	}
	e.Fields["srcIp"] = "9.9.9.9"
	h, err := computeHash(&e)
	if err != nil {
		t.Fatal(err)
	}
	e.Hash = h // recompute the public hash to keep the chain internally consistent
	// but Sig is left stale (attacker cannot recompute without the key)
	lines[1] = mustMarshal(t, &e)

	res := VerifyChain(bytes.NewReader(join(lines)), key)
	if res.Err == nil {
		t.Fatal("expected HMAC verification failure for forged entry")
	}
	if res.BadSeq != 2 {
		t.Fatalf("BadSeq=%d, want 2", res.BadSeq)
	}
}

func TestWrongHMACKeyRejected(t *testing.T) {
	var buf bytes.Buffer
	l := NewLedger(&buf, Options{HMACKey: []byte("right")})
	writeN(t, l, 3)

	res := VerifyChain(bytes.NewReader(buf.Bytes()), []byte("wrong"))
	if res.Err == nil {
		t.Fatal("expected failure verifying with the wrong key")
	}
}

func TestOpenResumesChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.log")

	l1, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	writeN(t, l1, 3)
	if err := l1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and append more — the chain must continue, not restart.
	l2, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	writeN(t, l2, 2)
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyChain(bytes.NewReader(data), nil)
	if res.Err != nil {
		t.Fatalf("resumed chain failed to verify: %v", res.Err)
	}
	if res.Count != 5 {
		t.Fatalf("Count=%d, want 5 (3 before restart + 2 after)", res.Count)
	}

	// Confirm seq numbering is continuous 1..5.
	lines := splitLines(data)
	for i, ln := range lines {
		var e Event
		if err := json.Unmarshal(ln, &e); err != nil {
			t.Fatal(err)
		}
		if e.Seq != uint64(i+1) {
			t.Fatalf("entry %d has seq=%d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestEmptyLedgerVerifies(t *testing.T) {
	res := VerifyChain(strings.NewReader(""), nil)
	if res.Err != nil || res.Count != 0 {
		t.Fatalf("empty ledger: got (count=%d, err=%v), want (0, nil)", res.Count, res.Err)
	}
}

// helpers

func splitLines(b []byte) [][]byte {
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		cp := make([]byte, len(sc.Bytes()))
		copy(cp, sc.Bytes())
		out = append(out, cp)
	}
	return out
}

func join(lines [][]byte) []byte {
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func mustMarshal(t *testing.T, e *Event) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

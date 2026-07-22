package server

import (
	"encoding/base64"
	"path/filepath"

	"github.com/OpenNHP/opennhp/nhp/audit"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// defaultAuditLedgerFile is the ledger path used when [Audit] is enabled
// but FilePath is left blank. Resolved against the executable directory.
const defaultAuditLedgerFile = "logs/audit-ledger.jsonl"

// initAuditLedger opens the audit ledger when enabled in config. It is a
// no-op (leaving s.auditLedger nil) when auditing is off, so the rest of
// the server can call auditEvent unconditionally.
func (s *UdpServer) initAuditLedger() error {
	if s.config == nil || !s.config.Audit.Enabled {
		return nil
	}

	path := s.config.Audit.FilePath
	if path == "" {
		path = defaultAuditLedgerFile
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(ExeDirPath, path)
	}

	var hmacKey []byte
	if s.config.Audit.SigningKeyBase64 != "" {
		key, err := base64.StdEncoding.DecodeString(s.config.Audit.SigningKeyBase64)
		if err != nil {
			return err
		}
		hmacKey = key
	}

	ledger, err := audit.Open(path, audit.Options{
		HMACKey: hmacKey,
		Fsync:   s.config.Audit.Fsync,
	})
	if err != nil {
		return err
	}
	s.auditLedger = ledger
	log.Info("audit ledger enabled at %s (signed=%v)", path, len(hmacKey) > 0)
	return nil
}

// auditEvent appends one security event to the ledger. It is safe to call
// when auditing is disabled (nil ledger) — it simply does nothing. A write
// failure is logged but never propagated: an audit-log hiccup must not
// break the request being served.
func (s *UdpServer) auditEvent(evType, severity string, fields map[string]string) {
	if s == nil || s.auditLedger == nil {
		return
	}
	if err := s.auditLedger.Log(evType, severity, fields); err != nil {
		log.Error("audit ledger write failed: %v", err)
	}
}

// closeAuditLedger flushes and closes the ledger on shutdown.
func (s *UdpServer) closeAuditLedger() {
	if s.auditLedger != nil {
		_ = s.auditLedger.Close()
		s.auditLedger = nil
	}
}

// shortKey returns a compact, log-safe fingerprint of a base64 public key
// for audit fields — enough to correlate, not the whole key.
func shortKey(pubKeyBase64 string) string {
	if len(pubKeyBase64) <= 12 {
		return pubKeyBase64
	}
	return pubKeyBase64[:12]
}

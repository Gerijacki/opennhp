package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// newTestStore opens a fresh keystore in t.TempDir() and registers a
// cleanup. Returns the store and a deterministic pair of test public keys.
func newTestStore(t *testing.T) (*AgentKeyStore, string, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewAgentKeyStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("NewAgentKeyStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const pkA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const pkB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	return s, pkA, pkB
}

func TestRegisterAgentKey_TTLZeroStoresNull(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 0); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}

	active, exp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry: %v", err)
	}
	if !active {
		t.Fatalf("expected active=true for TTL=0 row")
	}
	if exp != nil {
		t.Fatalf("expected expiresAt=nil for TTL=0, got %v", *exp)
	}

	found, err := s.FindAgentByPublicKey(pkA)
	if err != nil || !found {
		t.Fatalf("FindAgentByPublicKey: found=%v err=%v", found, err)
	}
}

func TestRegisterAgentKey_TTLPositiveSetsFutureExpiry(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	before := time.Now().Unix()
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 60); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	after := time.Now().Unix()

	active, exp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry: %v", err)
	}
	if !active || exp == nil {
		t.Fatalf("expected active=true with non-nil expiresAt")
	}
	// Allow ±2s wall-clock drift across the test boundary.
	if *exp < before+58 || *exp > after+62 {
		t.Fatalf("expiresAt out of expected range: got=%d want [%d,%d]", *exp, before+60, after+60)
	}
}

func TestRegisterAgentKey_TTLNegativeTreatedAsZero(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, -42); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	_, exp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry: %v", err)
	}
	if exp != nil {
		t.Fatalf("expected expiresAt=nil for negative TTL, got %v", *exp)
	}
}

// Load-bearing: an expired key MUST be invisible to FindAgentByPublicKey
// so the noise-layer peer validation fallback rejects the knock.
func TestFindAgentByPublicKey_ExpiredKeyHidden(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 1); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	// Wait past expiry.
	time.Sleep(2500 * time.Millisecond)

	found, err := s.FindAgentByPublicKey(pkA)
	if err != nil {
		t.Fatalf("FindAgentByPublicKey: %v", err)
	}
	if found {
		t.Fatalf("expired key should NOT be visible to FindAgentByPublicKey")
	}

	reg, err := s.IsAgentRegistered("alice", "dev1")
	if err != nil {
		t.Fatalf("IsAgentRegistered: %v", err)
	}
	if reg {
		t.Fatalf("expired key should NOT be visible to IsAgentRegistered")
	}

	rec, err := s.GetAgentKey("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKey: %v", err)
	}
	if rec != nil {
		t.Fatalf("expired key should NOT be returned by GetAgentKey")
	}
}

func TestGetAgentKeyExpiry_ExpiredReturnsFalse(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 1); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	time.Sleep(2500 * time.Millisecond)

	active, exp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry: %v", err)
	}
	if active || exp != nil {
		t.Fatalf("expected active=false exp=nil for expired row, got active=%v exp=%v", active, exp)
	}
}

// Key rotation (same user+device, different pubkey) MUST reset the clock.
func TestRegisterAgentKey_RotationResetsClock(t *testing.T) {
	s, pkA, pkB := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 60); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := s.RegisterAgentKey("alice", "dev1", pkB, 60); err != nil {
		t.Fatalf("RegisterAgentKey (rotation): %v", err)
	}

	before := time.Now().Unix()
	_, exp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry: %v", err)
	}
	if exp == nil {
		t.Fatalf("expected non-nil expiresAt after rotation")
	}
	// Rotation happened ~1.1s into the original 60s window. The new
	// expiry should be ~now+60, i.e. > before+58. Use a generous lower
	// bound to avoid flakes from slow CI.
	if *exp < before+58 {
		t.Fatalf("rotation did not reset clock: expiresAt=%d, expected >= %d", *exp, before+58)
	}
}

// Same key, same user — re-registering is idempotent and MUST NOT
// reset the expiry clock. Otherwise a network blip could indefinitely
// extend a key's validity.
func TestRegisterAgentKey_SameKeyNoOpDoesNotResetClock(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 60); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	_, firstExp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil || firstExp == nil {
		t.Fatalf("first register: %v firstExp=%v", err, firstExp)
	}
	time.Sleep(1100 * time.Millisecond)

	// Re-register with the SAME key — should be a no-op.
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 60); err != nil {
		t.Fatalf("RegisterAgentKey (idempotent): %v", err)
	}
	_, secondExp, err := s.GetAgentKeyExpiry("alice", "dev1")
	if err != nil || secondExp == nil {
		t.Fatalf("second register: %v secondExp=%v", err, secondExp)
	}
	if *firstExp != *secondExp {
		t.Fatalf("idempotent re-register reset the clock: first=%d second=%d", *firstExp, *secondExp)
	}
}

func TestRegisterAgentKey_PublicKeyConflictAcrossUsers(t *testing.T) {
	s, pkA, _ := newTestStore(t)
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 60); err != nil {
		t.Fatalf("RegisterAgentKey alice: %v", err)
	}
	err := s.RegisterAgentKey("bob", "dev1", pkA, 60)
	if !errors.Is(err, common.ErrPublicKeyAlreadyRegistered) {
		t.Fatalf("expected ErrPublicKeyAlreadyRegistered, got %v", err)
	}
}

func TestSweepExpiredDeactivates_ExpiresExpiredOnly(t *testing.T) {
	s, pkA, pkB := newTestStore(t)
	// Two keys: one that will expire, one with no expiry (TTL=0).
	if err := s.RegisterAgentKey("alice", "dev1", pkA, 1); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}
	if err := s.RegisterAgentKey("alice", "dev2", pkB, 0); err != nil {
		t.Fatalf("RegisterAgentKey: %v", err)
	}

	time.Sleep(2500 * time.Millisecond)

	n, err := s.SweepExpiredDeactivates()
	if err != nil {
		t.Fatalf("SweepExpiredDeactivates: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row swept, got %d", n)
	}

	// Sweep must not affect the NULL-expires row.
	active, exp, err := s.GetAgentKeyExpiry("alice", "dev2")
	if err != nil {
		t.Fatalf("GetAgentKeyExpiry dev2: %v", err)
	}
	if !active || exp != nil {
		t.Fatalf("NULL-expires row should remain active with no expiry: active=%v exp=%v", active, exp)
	}

	// After sweep, the expired row's active is 0, so FindAgentByPublicKey
	// is already false (the SQL filter on expires_at already hid it).
	found, err := s.FindAgentByPublicKey(pkA)
	if err != nil {
		t.Fatalf("FindAgentByPublicKey: %v", err)
	}
	if found {
		t.Fatalf("expired+swept key should not be visible")
	}
}

func TestSweepExpiredDeactivates_NoRowsNoError(t *testing.T) {
	s, _, _ := newTestStore(t)
	n, err := s.SweepExpiredDeactivates()
	if err != nil {
		t.Fatalf("SweepExpiredDeactivates: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows swept on empty store, got %d", n)
	}
}

// ── OTP tests ──────────────────────────────────────────────────────────────

func TestGenerateOTP_ValidateOTP_Success(t *testing.T) {
	s := func() *AgentKeyStore {
		s, _, _ := newTestStore(t)
		return s
	}()

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit OTP, got %q", code)
	}

	if err := s.ValidateOTP("alice", "dev1", code, ""); err != nil {
		t.Fatalf("ValidateOTP correct code: %v", err)
	}
}

func TestValidateOTP_WrongCode(t *testing.T) {
	s, _, _ := newTestStore(t)

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	// Wrong code should return ErrOTPInvalid.
	err = s.ValidateOTP("alice", "dev1", "000000", "")
	if !errors.Is(err, common.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid, got %v", err)
	}

	// Correct code must still work after a single wrong guess.
	if err := s.ValidateOTP("alice", "dev1", code, ""); err != nil {
		t.Fatalf("ValidateOTP correct code after wrong guess: %v", err)
	}
}

func TestValidateOTP_AlreadyUsed(t *testing.T) {
	s, _, _ := newTestStore(t)

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	if err := s.ValidateOTP("alice", "dev1", code, ""); err != nil {
		t.Fatalf("first ValidateOTP: %v", err)
	}

	// Second use must return ErrOTPAlreadyUsed.
	err = s.ValidateOTP("alice", "dev1", code, "")
	if !errors.Is(err, common.ErrOTPAlreadyUsed) {
		t.Fatalf("expected ErrOTPAlreadyUsed, got %v", err)
	}
}

func TestValidateOTP_Expired(t *testing.T) {
	s, _, _ := newTestStore(t)

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 1 * time.Second})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	time.Sleep(2500 * time.Millisecond)

	err = s.ValidateOTP("alice", "dev1", code, "")
	if !errors.Is(err, common.ErrOTPExpired) {
		t.Fatalf("expected ErrOTPExpired, got %v", err)
	}
}

func TestValidateOTP_RateLimit(t *testing.T) {
	s, _, _ := newTestStore(t)

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}

	// Exhaust attempts.
	for i := 0; i < MaxOTPAttempts; i++ {
		err = s.ValidateOTP("alice", "dev1", wrong, "")
		if i < MaxOTPAttempts-1 {
			if !errors.Is(err, common.ErrOTPInvalid) {
				t.Fatalf("attempt %d: expected ErrOTPInvalid, got %v", i+1, err)
			}
		} else {
			if !errors.Is(err, common.ErrOTPRateLimited) {
				t.Fatalf("attempt %d: expected ErrOTPRateLimited, got %v", i+1, err)
			}
		}
	}

	// After rate-limit, even the correct code must fail (OTP invalidated).
	err = s.ValidateOTP("alice", "dev1", code, "")
	if !errors.Is(err, common.ErrOTPInvalid) {
		t.Fatalf("after rate-limit: expected ErrOTPInvalid, got %v", err)
	}
}

func TestGenerateOTP_InvalidatesPrevious(t *testing.T) {
	s, _, _ := newTestStore(t)

	opts := OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute, CooldownSeconds: -1}
	code1, err := s.GenerateOTP(opts)
	if err != nil {
		t.Fatalf("GenerateOTP 1: %v", err)
	}

	// Generate a second OTP for the same user+device — invalidates code1.
	code2, err := s.GenerateOTP(opts)
	if err != nil {
		t.Fatalf("GenerateOTP 2: %v", err)
	}
	if code1 == code2 {
		t.Fatal("expected different OTP codes")
	}

	// First OTP should now be used=1 (invalidated by the second GenerateOTP).
	err = s.ValidateOTP("alice", "dev1", code1, "")
	if !errors.Is(err, common.ErrOTPAlreadyUsed) {
		t.Fatalf("expected ErrOTPAlreadyUsed for old OTP, got %v", err)
	}

	// Second OTP should still work.
	if err := s.ValidateOTP("alice", "dev1", code2, ""); err != nil {
		t.Fatalf("ValidateOTP code2: %v", err)
	}
}

func TestValidateOTP_PublicKeyMismatch(t *testing.T) {
	s, _, _ := newTestStore(t)

	const pubKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const pubKeyB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", PublicKey: pubKeyA, TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	// Correct code but wrong public key must be rejected.
	err = s.ValidateOTP("alice", "dev1", code, pubKeyB)
	if !errors.Is(err, common.ErrOTPPublicKeyMismatch) {
		t.Fatalf("expected ErrOTPPublicKeyMismatch, got %v", err)
	}

	// Correct code with correct public key must succeed.
	if err := s.ValidateOTP("alice", "dev1", code, pubKeyA); err != nil {
		t.Fatalf("ValidateOTP with matching pubKey: %v", err)
	}
}

// TestGenerateOTP_PerUserRateLimit verifies that generating OTPs for the
// same userId across different deviceIds is capped at MaxOTPPerUserPerWindow
// within the cooldown window. This prevents an attacker from bypassing the
// per-device cooldown by rotating the (unauthenticated) deviceId field.
func TestGenerateOTP_PerUserRateLimit(t *testing.T) {
	s, _, _ := newTestStore(t)

	// Generate one OTP per deviceId — each is a different device, so the
	// per-device cooldown allows them all. The per-userId cap should
	// reject the (MaxOTPPerUserPerWindow+1)-th request.
	for i := 0; i < MaxOTPPerUserPerWindow; i++ {
		devId := fmt.Sprintf("dev%d", i)
		_, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: devId, TTL: 5 * time.Minute})
		if err != nil {
			t.Fatalf("device %s (iteration %d): expected success, got %v", devId, i+1, err)
		}
	}

	// The next request with yet another deviceId must be rejected by the
	// per-userId rate limit.
	_, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev_overflow", TTL: 5 * time.Minute})
	if !errors.Is(err, common.ErrOTPCooldown) {
		t.Fatalf("expected ErrOTPCooldown after %d devices, got %v", MaxOTPPerUserPerWindow, err)
	}

	// A different user must still be able to request OTP (isolation check).
	_, err = s.GenerateOTP(OTPParams{UserId: "bob", DeviceId: "dev0", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("different user should not be rate-limited: %v", err)
	}
}

// TestGenerateOTP_CooldownDisabledBypassesPerUserLimit verifies that a
// negative CooldownSeconds disables the per-userId and distinct-device
// checks as well (not just the per-device cooldown). This is the contract
// that existing tests rely on.
func TestGenerateOTP_CooldownDisabledBypassesPerUserLimit(t *testing.T) {
	s, _, _ := newTestStore(t)

	opts := OTPParams{UserId: "alice", DeviceId: "dev0", TTL: 5 * time.Minute, CooldownSeconds: -1}
	for i := 0; i < MaxOTPPerUserPerWindow+2; i++ {
		opts.DeviceId = fmt.Sprintf("dev%d", i)
		_, err := s.GenerateOTP(opts)
		if err != nil {
			t.Fatalf("cooldown disabled: iteration %d (device %s): expected success, got %v",
				i+1, opts.DeviceId, err)
		}
	}
}

// ── OTP sweep tests ──────────────────────────────────────────────────────

func TestSweepStaleOTPs_DeletesUsedAndExpired(t *testing.T) {
	s, _, _ := newTestStore(t)

	// Generate two OTPs and use one.
	code1, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP 1: %v", err)
	}
	_, err = s.GenerateOTP(OTPParams{UserId: "bob", DeviceId: "dev1", TTL: 1 * time.Second})
	if err != nil {
		t.Fatalf("GenerateOTP 2: %v", err)
	}

	// Use code1 (marks used=1).
	if err := s.ValidateOTP("alice", "dev1", code1, ""); err != nil {
		t.Fatalf("ValidateOTP code1: %v", err)
	}

	// Wait for code2 to expire.
	time.Sleep(2500 * time.Millisecond)

	// Sweep with 0 retention (delete everything that is already used or expired).
	n, err := s.SweepStaleOTPs(0)
	if err != nil {
		t.Fatalf("SweepStaleOTPs: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 stale OTPs deleted (1 used + 1 expired), got %d", n)
	}

	// Second sweep should be a no-op.
	n, err = s.SweepStaleOTPs(0)
	if err != nil {
		t.Fatalf("SweepStaleOTPs (second): %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows on second sweep, got %d", n)
	}
}

func TestSweepStaleOTPs_PreservesPending(t *testing.T) {
	s, _, _ := newTestStore(t)

	code, err := s.GenerateOTP(OTPParams{UserId: "alice", DeviceId: "dev1", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}

	// Sweep with 0 retention must NOT delete a pending (unused, unexpired) OTP.
	n, err := s.SweepStaleOTPs(0)
	if err != nil {
		t.Fatalf("SweepStaleOTPs: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows deleted (pending OTP preserved), got %d", n)
	}

	// Pending OTP must still validate.
	if err := s.ValidateOTP("alice", "dev1", code, ""); err != nil {
		t.Fatalf("ValidateOTP after sweep: %v", err)
	}
}

// ── WebAuthn tests ────────────────────────────────────────────────────────

// buildCOSEP256Key encodes an ecdsa P-256 public key as a COSE_Key CBOR map
// the way browsers produce it: {1:2, 3:-7, -1:1, -2:x, -3:y}.
func buildCOSEP256Key(pub *ecdsa.PublicKey) []byte {
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xb):], xb)
	copy(y[32-len(yb):], yb)

	var buf []byte
	buf = append(buf, 0xa5)             // map(5)
	buf = append(buf, 0x01, 0x02)       // 1: 2 (kty=EC2)
	buf = append(buf, 0x03, 0x26)       // 3: -7 (alg=ES256)
	buf = append(buf, 0x20, 0x01)       // -1: 1 (crv=P-256)
	buf = append(buf, 0x21, 0x58, 0x20) // -2: bytes(32)
	buf = append(buf, x...)
	buf = append(buf, 0x22, 0x58, 0x20) // -3: bytes(32)
	buf = append(buf, y...)
	return buf
}

// signWebAuthnAssertion produces (authDataB64, clientDataJSONB64, sigB64)
// the way navigator.credentials.get() would for the given challenge.
func signWebAuthnAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte) (string, string, string) {
	t.Helper()
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"https://reg.opennhp.org"}`,
		base64.RawURLEncoding.EncodeToString(challenge))
	authData := make([]byte, 37) // rpIdHash(32) + flags(1) + signCount(4)
	rpIdHash := sha256.Sum256([]byte("reg.opennhp.org"))
	copy(authData[:32], rpIdHash[:])
	authData[32] = 0x01 // UP flag

	cdHash := sha256.Sum256([]byte(clientData))
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return base64.StdEncoding.EncodeToString(authData),
		base64.StdEncoding.EncodeToString([]byte(clientData)),
		base64.StdEncoding.EncodeToString(sig)
}

func TestVerifyWebAuthnAssertion_ValidSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))

	challenge := sha256.Sum256([]byte("123456" + "alice" + "dev1" + "serverPubKey"))
	authB64, cdB64, sigB64 := signWebAuthnAssertion(t, priv, challenge[:])

	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, challenge[:], ""); err != nil {
		t.Fatalf("VerifyWebAuthnAssertion valid: %v", err)
	}
}

func TestVerifyWebAuthnAssertion_WrongChallenge(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))

	signedChallenge := sha256.Sum256([]byte("123456alicedev1server"))
	authB64, cdB64, sigB64 := signWebAuthnAssertion(t, priv, signedChallenge[:])

	// Server expects a different challenge (e.g. attacker replaying an old
	// assertion against a new OTP).
	expected := sha256.Sum256([]byte("999999alicedev1server"))
	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, expected[:], ""); err == nil {
		t.Fatal("expected challenge mismatch error, got nil")
	}
}

func TestVerifyWebAuthnAssertion_WrongKey(t *testing.T) {
	privSigner, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privOther, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Committed credential is privOther's public key; signature from privSigner.
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&privOther.PublicKey))

	challenge := sha256.Sum256([]byte("123456alicedev1server"))
	authB64, cdB64, sigB64 := signWebAuthnAssertion(t, privSigner, challenge[:])

	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, challenge[:], ""); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
}

func TestVerifyWebAuthnAssertion_TamperedClientData(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))

	challenge := sha256.Sum256([]byte("123456alicedev1server"))
	authB64, _, sigB64 := signWebAuthnAssertion(t, priv, challenge[:])

	// Re-encode clientDataJSON with the same challenge but altered content
	// — the signature no longer covers it.
	tampered := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"https://evil.example"}`,
		base64.RawURLEncoding.EncodeToString(challenge[:]))
	cdB64 := base64.StdEncoding.EncodeToString([]byte(tampered))

	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, challenge[:], ""); err == nil {
		t.Fatal("expected verification failure on tampered clientDataJSON, got nil")
	}
}

func TestWebAuthnCredentialStore_RoundTrip(t *testing.T) {
	s, _, _ := newTestStore(t)

	if err := s.StoreWebAuthnCredential("alice", "dev1", "cred-id-1", "cose-key-1"); err != nil {
		t.Fatalf("StoreWebAuthnCredential: %v", err)
	}
	credId, cose, err := s.GetWebAuthnCredential("alice", "dev1")
	if err != nil {
		t.Fatalf("GetWebAuthnCredential: %v", err)
	}
	if credId != "cred-id-1" || cose != "cose-key-1" {
		t.Fatalf("got (%s, %s), want (cred-id-1, cose-key-1)", credId, cose)
	}

	// Upsert on same (user, device) replaces the credential.
	if err := s.StoreWebAuthnCredential("alice", "dev1", "cred-id-2", "cose-key-2"); err != nil {
		t.Fatalf("StoreWebAuthnCredential upsert: %v", err)
	}
	credId, cose, _ = s.GetWebAuthnCredential("alice", "dev1")
	if credId != "cred-id-2" || cose != "cose-key-2" {
		t.Fatalf("upsert got (%s, %s), want (cred-id-2, cose-key-2)", credId, cose)
	}

	// Unknown user returns empty, no error.
	credId, cose, err = s.GetWebAuthnCredential("bob", "devX")
	if err != nil || credId != "" || cose != "" {
		t.Fatalf("unknown user: got (%s, %s, %v), want empty", credId, cose, err)
	}
}

func TestVerifyWebAuthnAssertion_RpIdHash(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))

	challenge := sha256.Sum256([]byte("123456alicedev1server"))
	authB64, cdB64, sigB64 := signWebAuthnAssertion(t, priv, challenge[:])

	// Correct RP ID passes.
	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, challenge[:], "reg.opennhp.org"); err != nil {
		t.Fatalf("correct rpId: %v", err)
	}
	// Wrong RP ID is rejected.
	if err := VerifyWebAuthnAssertion(cose, authB64, cdB64, sigB64, challenge[:], "evil.example"); err == nil {
		t.Fatal("expected rpIdHash mismatch, got nil")
	}
}

func TestVerifyWebAuthnAssertion_UserPresentRequired(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))
	challenge := sha256.Sum256([]byte("123456alicedev1server"))

	// Build an assertion whose UP flag is cleared but is otherwise valid.
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"https://reg.opennhp.org"}`,
		base64.RawURLEncoding.EncodeToString(challenge[:]))
	authData := make([]byte, 37)
	rpIdHash := sha256.Sum256([]byte("reg.opennhp.org"))
	copy(authData[:32], rpIdHash[:])
	// authData[32] deliberately left 0x00 — no user presence.
	cdHash := sha256.Sum256([]byte(clientData))
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])

	err := VerifyWebAuthnAssertion(cose,
		base64.StdEncoding.EncodeToString(authData),
		base64.StdEncoding.EncodeToString([]byte(clientData)),
		base64.StdEncoding.EncodeToString(sig),
		challenge[:], "reg.opennhp.org")
	if err == nil {
		t.Fatal("expected user-present flag error, got nil")
	}
}

func TestVerifyWebAuthnAssertion_ShortAuthData(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := base64.StdEncoding.EncodeToString(buildCOSEP256Key(&priv.PublicKey))
	challenge := sha256.Sum256([]byte("123456alicedev1server"))
	_, cdB64, sigB64 := signWebAuthnAssertion(t, priv, challenge[:])

	short := base64.StdEncoding.EncodeToString(make([]byte, 10))
	if err := VerifyWebAuthnAssertion(cose, short, cdB64, sigB64, challenge[:], ""); err == nil {
		t.Fatal("expected short authData error, got nil")
	}
}

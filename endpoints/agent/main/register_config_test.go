package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteResourceConfig verifies the generated resource.toml binds the
// asp-id/res-id to the named cluster and is written under etc/.
func TestWriteResourceConfig(t *testing.T) {
	dir := t.TempDir()
	if err := writeResourceConfig(dir, "example", "demo", "cluster1"); err != nil {
		t.Fatalf("writeResourceConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "etc", "resource.toml"))
	if err != nil {
		t.Fatalf("read resource.toml: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`AuthServiceId = "example"`,
		`ResourceId    = "demo"`,
		`Cluster       = "cluster1"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("resource.toml missing %q in:\n%s", want, s)
		}
	}
}

// TestWriteRegistrationConfig verifies the generated config.toml carries
// the registered identity, private key, and the selected cipher scheme.
func TestWriteRegistrationConfig(t *testing.T) {
	dir := t.TempDir()
	if err := writeRegistrationConfig(dir, "PRIVKEYB64", "alice@example.com", "opennhp.org", 1); err != nil {
		t.Fatalf("writeRegistrationConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "etc", "config.toml"))
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`PrivateKeyBase64 = "PRIVKEYB64"`,
		`DefaultCipherScheme = 1`,
		`UserId = "alice@example.com"`,
		`OrganizationId = "opennhp.org"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("config.toml missing %q in:\n%s", want, s)
		}
	}
}

// TestWriteRegistrationConfig_CurveScheme pins the curve25519 scheme code (0).
func TestWriteRegistrationConfig_CurveScheme(t *testing.T) {
	dir := t.TempDir()
	if err := writeRegistrationConfig(dir, "K", "u", "", 0); err != nil {
		t.Fatalf("writeRegistrationConfig: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "etc", "config.toml"))
	if !strings.Contains(string(data), "DefaultCipherScheme = 0") {
		t.Fatalf("expected DefaultCipherScheme = 0 for curve25519, got:\n%s", data)
	}
}

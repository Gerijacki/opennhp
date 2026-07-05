package test

import (
	"testing"

	core "github.com/OpenNHP/opennhp/nhp/core"
)

// The tests in this file pin the on-the-wire message type registry: the integer
// value of every header type, its HeaderTypeToString label, and the device type
// that HeaderTypeToDeviceType resolves it to. These values are part of the
// protocol contract, so any accidental change (reordering a constant, inserting
// a new one in the middle, editing a label) shows up here as a failing test
// instead of silently breaking interoperability with already-deployed peers.

type headerTypeCase struct {
	headerType int
	value      int
	label      string
	deviceType int
}

// Expected values reflect the current OpenNHP registry in nhp/core/packet.go.
// Update this table deliberately, in lockstep with a compatibility note, if the
// registry ever changes.
var headerTypeRegistry = []headerTypeCase{
	{core.NHP_KPL, 0, "NHP-KPL", core.NHP_NO_DEVICE},
	{core.NHP_KNK, 1, "NHP-KNK", core.NHP_AGENT},
	{core.NHP_ACK, 2, "NHP-ACK", core.NHP_SERVER},
	{core.NHP_AOP, 3, "NHP-AOP", core.NHP_SERVER},
	{core.NHP_ART, 4, "NHP-ART", core.NHP_AC},
	{core.NHP_LST, 5, "NHP-LST", core.NHP_AGENT},
	{core.NHP_LRT, 6, "NHP-LRT", core.NHP_SERVER},
	{core.NHP_COK, 7, "NHP-COK", core.NHP_SERVER},
	{core.NHP_RKN, 8, "NHP-RKN", core.NHP_AGENT},
	{core.NHP_RLY, 9, "NHP-RLY", core.NHP_RELAY},
	{core.NHP_AOL, 10, "NHP-AOL", core.NHP_AC},
	{core.NHP_AAK, 11, "NHP-AAK", core.NHP_SERVER},
	{core.NHP_OTP, 12, "NHP-OTP", core.NHP_AGENT},
	{core.NHP_REG, 13, "NHP-REG", core.NHP_AGENT},
	{core.NHP_RAK, 14, "NHP-RAK", core.NHP_SERVER},
	{core.NHP_ACC, 15, "NHP-ACC", core.NHP_AGENT},
	{core.NHP_EXT, 16, "NHP-EXT", core.NHP_AGENT},
	{core.NHP_DRG, 17, "NHP_DRG", core.NHP_DB},
	{core.NHP_DAK, 18, "NHP_DAK", core.NHP_SERVER},
	{core.NHP_DAR, 19, "NHP_DAR", core.DHP_AGENT},
	{core.NHP_DAG, 20, "NHP_DAG", core.NHP_SERVER},
	{core.NHP_DSA, 21, "NHP_DSA", core.NHP_SERVER},
	{core.NHP_DAV, 22, "NHP_DAV", core.DHP_AGENT},
	{core.NHP_DWR, 23, "NHP_DWR", core.NHP_SERVER},
	{core.NHP_DWA, 24, "NHP_DWA", core.NHP_DB},
	{core.NHP_DOL, 25, "NHP_DOL", core.NHP_DB},
	{core.NHP_DBA, 26, "NHP_DBA", core.NHP_SERVER},
	{core.DHP_KNK, 27, "DHP-KNK", core.DHP_AGENT},
}

func TestHeaderTypeValues(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if tc.headerType != tc.value {
			t.Errorf("header type %q: got value %d, want %d", tc.label, tc.headerType, tc.value)
		}
	}
}

func TestHeaderTypeToString(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if got := core.HeaderTypeToString(tc.headerType); got != tc.label {
			t.Errorf("HeaderTypeToString(%d) = %q, want %q", tc.headerType, got, tc.label)
		}
	}
}

func TestHeaderTypeToStringOutOfRange(t *testing.T) {
	for _, tp := range []int{-1, len(headerTypeRegistry), 1000} {
		if got := core.HeaderTypeToString(tp); got != "UNKNOWN" {
			t.Errorf("HeaderTypeToString(%d) = %q, want %q", tp, got, "UNKNOWN")
		}
	}
}

func TestHeaderTypeToDeviceType(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if got := core.HeaderTypeToDeviceType(tc.headerType); got != tc.deviceType {
			t.Errorf("HeaderTypeToDeviceType(%q) = %d, want %d", tc.label, got, tc.deviceType)
		}
	}
}

// The registry must stay contiguous starting at zero; a gap would mean a
// constant was removed without renumbering the rest, which shifts every value
// after it on the wire.
func TestHeaderTypeRegistryContiguous(t *testing.T) {
	for i, tc := range headerTypeRegistry {
		if tc.value != i {
			t.Fatalf("registry not contiguous at index %d: %q has value %d", i, tc.label, tc.value)
		}
	}
}

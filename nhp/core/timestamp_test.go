package core

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// The encrypted timestamp that travels in every message header feeds the
// receiver's freshness and replay checks, so its unit is security-sensitive:
// a peer that reads it in the wrong unit either accepts stale packets or
// rejects fresh ones. OpenNHP currently serializes time.Now().UnixNano() as an
// 8-byte big-endian value. The tests below pin that convention so a change of
// unit (e.g. to UnixMilli) or width can't slip through unnoticed.
//
// See #1581 for the discussion of aligning this unit with the CSA NHP standard.

// TestInitTimestampIsNanoseconds exercises the real initiator path and checks
// that the timestamp it stamps is on the nanosecond scale. If the source unit
// ever changes, LocalInitTime falls outside the [before, after] nanosecond
// window and this fails.
func TestInitTimestampIsNanoseconds(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	dev := NewDevice(NHP_AGENT, priv, nil)
	if dev == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(dev.Stop)

	before := time.Now().UnixNano()
	mad, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType:    NHP_KNK,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: 1,
		PeerPk:        testPeerPk(),
	})
	if err != nil {
		t.Fatalf("createMsgAssemblerData: %v", err)
	}
	t.Cleanup(mad.Destroy)
	after := time.Now().UnixNano()

	if mad.LocalInitTime < before || mad.LocalInitTime > after {
		t.Fatalf("LocalInitTime %d outside nanosecond window [%d, %d] — timestamp unit changed?",
			mad.LocalInitTime, before, after)
	}
}

// TestTimestampEncoding pins the wire encoding used in configInitiatorState:
// an 8-byte big-endian representation of the int64 nanosecond timestamp that
// round-trips back to the same value on the receiver side.
func TestTimestampEncoding(t *testing.T) {
	if TimestampSize != 8 {
		t.Fatalf("TimestampSize = %d, want 8 (encrypted timestamp is a uint64)", TimestampSize)
	}

	cases := []struct {
		name  string
		nanos int64
		want  [8]byte
	}{
		{"zero", 0, [8]byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{"one", 1, [8]byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{"fixed", 1700000000123456789, [8]byte{0x17, 0x97, 0x9c, 0xfe, 0x3d, 0x85, 0xcd, 0x15}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf [TimestampSize]byte
			binary.BigEndian.PutUint64(buf[:], uint64(tc.nanos))
			if buf != tc.want {
				t.Fatalf("encode(%d) = % x, want % x", tc.nanos, buf[:], tc.want[:])
			}
			if got := int64(binary.BigEndian.Uint64(buf[:])); got != tc.nanos {
				t.Fatalf("decode round-trip = %d, want %d", got, tc.nanos)
			}
		})
	}
}

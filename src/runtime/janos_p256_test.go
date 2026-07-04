// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"testing"
)

// TestJanosP256FieldBytesRoundTrip: SetBytes(Bytes(x)) == x for a
// few canonical values.
func TestJanosP256FieldBytesRoundTrip(t *testing.T) {
	cases := [][]byte{
		makeBE32(0x01),
		makeBE32(0x42),
		// p - 1 (the highest canonical value).
		{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
	}
	for i, in := range cases {
		out, ok := runtime.P256FieldFromBytesForTest(in)
		if !ok {
			t.Errorf("case %d: SetBytes rejected valid input %x", i, in)
			continue
		}
		if !bytesEq(in, out[:]) {
			t.Errorf("case %d: round-trip mismatch\nwant %x\ngot  %x", i, in, out)
		}
	}
}

// TestJanosP256FieldRejectNonCanonical: SetBytes must refuse values
// >= p.  We test with p (which is p-1 + 1) and 2p-1.
func TestJanosP256FieldRejectNonCanonical(t *testing.T) {
	// p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	p := []byte{
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	if _, ok := runtime.P256FieldFromBytesForTest(p); ok {
		t.Error("SetBytes accepted p (non-canonical: equal to modulus)")
	}
	// All ones = 2^256 - 1, definitely >= p.
	allOnes := make([]byte, 32)
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	if _, ok := runtime.P256FieldFromBytesForTest(allOnes); ok {
		t.Error("SetBytes accepted 2^256 - 1 (non-canonical)")
	}
}

// TestJanosP256FieldInvertRoundTrip: x * (1/x) == 1 for several
// nonzero values.
func TestJanosP256FieldInvertRoundTrip(t *testing.T) {
	xs := [][]byte{
		makeBE32(0x01),
		makeBE32(0x42),
		makeBE32(0x100),
	}
	one := runtime.P256FieldOneForTest()
	for i, x := range xs {
		inv, ok := runtime.P256FieldInvertForTest(x)
		if !ok {
			t.Errorf("case %d: Invert rejected valid input", i)
			continue
		}
		got, ok := runtime.P256FieldMulForTest(x, inv[:])
		if !ok {
			t.Errorf("case %d: Mul rejected valid inputs", i)
			continue
		}
		if got != one {
			t.Errorf("case %d: x * (1/x) != 1\nwant %x\ngot  %x", i, one, got)
		}
	}
}

// makeBE32 returns the 32-byte big-endian encoding of the small
// integer v.
func makeBE32(v uint64) []byte {
	out := make([]byte, 32)
	out[31] = byte(v)
	out[30] = byte(v >> 8)
	out[29] = byte(v >> 16)
	out[28] = byte(v >> 24)
	out[27] = byte(v >> 32)
	out[26] = byte(v >> 40)
	out[25] = byte(v >> 48)
	out[24] = byte(v >> 56)
	return out
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

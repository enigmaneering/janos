// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package janos_ed25519

import (
	"testing"
)

// oneScalar returns the scalar 1 (as a fresh value).
func oneScalar(t *testing.T) *Scalar {
	t.Helper()
	one := new(Scalar)
	buf := [32]byte{0x01}
	if _, ok := one.SetCanonicalBytes(buf[:]); !ok {
		t.Fatal("SetCanonicalBytes(1) rejected")
	}
	return one
}

// scalarFromByte returns the scalar equal to the given byte value.
func scalarFromByte(t *testing.T, b byte) *Scalar {
	t.Helper()
	s := new(Scalar)
	buf := [32]byte{b}
	if _, ok := s.SetCanonicalBytes(buf[:]); !ok {
		t.Fatalf("SetCanonicalBytes(%d) rejected", b)
	}
	return s
}

// TestScalarAddIdentity checks x + 0 == x.
func TestScalarAddIdentity(t *testing.T) {
	x := scalarFromByte(t, 42)
	zero := new(Scalar)
	var r Scalar
	r.Add(x, zero)
	if r.Equal(x) != 1 {
		t.Fatal("x + 0 != x")
	}
}

// TestScalarMultiplyIdentity checks x * 1 == x.
func TestScalarMultiplyIdentity(t *testing.T) {
	x := scalarFromByte(t, 42)
	one := oneScalar(t)
	var r Scalar
	r.Multiply(x, one)
	if r.Equal(x) != 1 {
		xb := x.Bytes()
		rb := r.Bytes()
		t.Fatalf("x * 1 != x\nx = %x\nr = %x", xb, rb)
	}
}

// TestScalarSubtractSelf checks x - x == 0.
func TestScalarSubtractSelf(t *testing.T) {
	x := scalarFromByte(t, 42)
	zero := new(Scalar)
	var r Scalar
	r.Subtract(x, x)
	if r.Equal(zero) != 1 {
		t.Fatal("x - x != 0")
	}
}

// TestScalarNegateTwice checks -(-x) == x.
func TestScalarNegateTwice(t *testing.T) {
	x := scalarFromByte(t, 42)
	var negX, negNegX Scalar
	negX.Negate(x)
	negNegX.Negate(&negX)
	if negNegX.Equal(x) != 1 {
		t.Fatal("-(-x) != x")
	}
}

// TestScalarMultiplyCommutative checks x*y == y*x for several pairs.
func TestScalarMultiplyCommutative(t *testing.T) {
	a := scalarFromByte(t, 17)
	b := scalarFromByte(t, 23)
	var xy, yx Scalar
	xy.Multiply(a, b)
	yx.Multiply(b, a)
	if xy.Equal(&yx) != 1 {
		t.Fatal("x*y != y*x")
	}
}

// TestScalarDistributive checks a*(b+c) == a*b + a*c.
func TestScalarDistributive(t *testing.T) {
	a := scalarFromByte(t, 5)
	b := scalarFromByte(t, 7)
	c := scalarFromByte(t, 11)
	var lhs, sum, ab, ac, rhs Scalar
	sum.Add(b, c)
	lhs.Multiply(a, &sum)
	ab.Multiply(a, b)
	ac.Multiply(a, c)
	rhs.Add(&ab, &ac)
	if lhs.Equal(&rhs) != 1 {
		t.Fatal("a*(b+c) != a*b + a*c")
	}
}

// TestScalarBytesRoundTrip checks SetCanonicalBytes(Bytes(x)) == x.
func TestScalarBytesRoundTrip(t *testing.T) {
	cases := [][]byte{
		{0x01},
		{0x2a},
		{0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
			0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
			0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
			0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00},
	}
	for i, in := range cases {
		var buf [32]byte
		copy(buf[:], in)
		x := new(Scalar)
		if _, ok := x.SetCanonicalBytes(buf[:]); !ok {
			t.Fatalf("case %d: rejected valid input", i)
		}
		out := x.Bytes()
		if out != buf {
			t.Errorf("case %d: bytes round-trip mismatch\nwant %x\ngot  %x", i, buf, out)
		}
	}
}

// TestScalarRejectNonCanonical verifies SetCanonicalBytes rejects
// values >= l.  scalarMinusOneBytes represents l-1, which IS
// canonical; l would be one greater and should be rejected.
func TestScalarRejectNonCanonical(t *testing.T) {
	if !isReduced(scalarMinusOneBytes[:]) {
		t.Fatal("l-1 should be canonical (< l)")
	}
	// Build l = (l-1) + 1 in little endian.
	l := scalarMinusOneBytes
	carry := byte(1)
	for i := 0; i < len(l) && carry != 0; i++ {
		sum := uint16(l[i]) + uint16(carry)
		l[i] = byte(sum)
		carry = byte(sum >> 8)
	}
	if isReduced(l[:]) {
		t.Fatal("l should be rejected (== l, not < l)")
	}
}

// TestScalarUniformBytesLength ensures wrong-length inputs are
// rejected without altering the receiver.
func TestScalarUniformBytesLength(t *testing.T) {
	s := scalarFromByte(t, 42)
	before := s.Bytes()
	if _, ok := s.SetUniformBytes(make([]byte, 63)); ok {
		t.Error("SetUniformBytes accepted 63-byte input")
	}
	if _, ok := s.SetUniformBytes(make([]byte, 65)); ok {
		t.Error("SetUniformBytes accepted 65-byte input")
	}
	after := s.Bytes()
	if before != after {
		t.Error("SetUniformBytes mutated receiver on rejected input")
	}
}

// TestScalarClampingBits checks that SetBytesWithClamping applies the
// three RFC 8032 §5.1.5 bit-fiddles.  We construct a known input,
// clamp it, then verify the reduced-scalar bytes match what you'd
// get from clamping-then-uniform-reducing manually.
func TestScalarClampingBits(t *testing.T) {
	// All-ones input.  Post-clamp bit pattern is:
	//   byte 0:  0xff & 0xf8 = 0xf8
	//   byte 31: (0xff & 0x3f) | 0x40 = 0x7f
	//   others:  unchanged 0xff
	var in [32]byte
	for i := range in {
		in[i] = 0xff
	}
	var clamped [64]byte
	copy(clamped[:], in[:])
	clamped[0] &= 248
	clamped[31] &= 63
	clamped[31] |= 64

	expected := new(Scalar)
	if _, ok := expected.SetUniformBytes(clamped[:]); !ok {
		t.Fatal("SetUniformBytes rejected clamped 64-byte input")
	}

	got := new(Scalar)
	if _, ok := got.SetBytesWithClamping(in[:]); !ok {
		t.Fatal("SetBytesWithClamping rejected 32-byte input")
	}

	if got.Equal(expected) != 1 {
		t.Errorf("SetBytesWithClamping != manual clamp + SetUniformBytes\nwant %x\ngot  %x",
			expected.Bytes(), got.Bytes())
	}
}

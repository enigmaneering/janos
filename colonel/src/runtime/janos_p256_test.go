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

// TestJanosP256ScalarRoundTrip: SetBytesBE(v).Bytes() == v for
// values already < n.
func TestJanosP256ScalarRoundTrip(t *testing.T) {
	cases := [][]byte{
		makeBE32(0x01),
		makeBE32(0x100),
		// A largish value still < n
		{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
	}
	for i, v := range cases {
		out, ok := runtime.P256ScalarRoundTripForTest(v)
		if !ok {
			t.Errorf("case %d: SetBytesBE rejected", i)
			continue
		}
		if !bytesEq(v, out[:]) {
			t.Errorf("case %d: round-trip mismatch\nwant %x\ngot  %x", i, v, out)
		}
	}
}

// TestJanosP256ScalarInvertRoundTrip: x * (1/x) == 1 mod n for
// several nonzero x.
func TestJanosP256ScalarInvertRoundTrip(t *testing.T) {
	xs := [][]byte{
		makeBE32(0x02),
		makeBE32(0x03),
		makeBE32(0xdead),
	}
	one := makeBE32(0x01)
	for i, x := range xs {
		inv, ok := runtime.P256ScalarInvertForTest(x)
		if !ok {
			t.Errorf("case %d: Invert rejected", i)
			continue
		}
		got, ok := runtime.P256ScalarMulForTest(x, inv[:])
		if !ok {
			t.Errorf("case %d: Mul rejected", i)
			continue
		}
		if !bytesEq(got[:], one) {
			t.Errorf("case %d: x * (1/x) mod n != 1\nwant %x\ngot  %x", i, one, got)
		}
	}
}

// TestJanosP256ScalarMulCommutative: a*b == b*a mod n.
func TestJanosP256ScalarMulCommutative(t *testing.T) {
	a := makeBE32(0x0f)
	b := makeBE32(0x11)
	ab, _ := runtime.P256ScalarMulForTest(a, b)
	ba, _ := runtime.P256ScalarMulForTest(b, a)
	if ab != ba {
		t.Errorf("a*b != b*a\nab = %x\nba = %x", ab, ba)
	}
}

// TestJanosP256ScalarSquareViaMul: MontMul(x, x) should equal
// squaring.  If this fails when out=a=b are aliased, MontMul has
// a state bug when all three args point at the same array.
func TestJanosP256ScalarSquareViaMul(t *testing.T) {
	// 2*2 = 4
	got, _ := runtime.P256ScalarMulForTest(makeBE32(0x02), makeBE32(0x02))
	want := makeBE32(0x04)
	if !bytesEq(got[:], want) {
		t.Errorf("2*2\nwant %x\ngot  %x", want, got)
	}
	// 5*5 = 25
	got, _ = runtime.P256ScalarMulForTest(makeBE32(0x05), makeBE32(0x05))
	want = makeBE32(25)
	if !bytesEq(got[:], want) {
		t.Errorf("5*5\nwant %x\ngot  %x", want, got)
	}
}

// TestJanosP256ScalarSimpleMul: 2*3 = 6.  Sanity check that MontMul
// produces arithmetically-correct results, not just self-consistent
// ones.  If this fails, the Montgomery reduction constants
// (NInv0, RR) are wrong.
func TestJanosP256ScalarSimpleMul(t *testing.T) {
	got, _ := runtime.P256ScalarMulForTest(makeBE32(0x02), makeBE32(0x03))
	want := makeBE32(0x06)
	if !bytesEq(got[:], want) {
		t.Errorf("2*3\nwant %x\ngot  %x", want, got)
	}
}

// TestJanosP256ScalarVectors: verify against a table of known-good
// (x, y, x*y mod n) triples and (x, x^-1 mod n) pairs computed with
// math/big.  Covers small, medium, near-n, and pseudo-random inputs
// — the previous 3-case tests were thin coverage that let a
// carry-propagation bug slip through even after 2*3 = 6 passed.
func TestJanosP256ScalarVectors(t *testing.T) {
	invert := [...]struct{ x, xInv string }{
		{"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000001"},
		{"0000000000000000000000000000000000000000000000000000000000000002",
			"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"},
		{"0000000000000000000000000000000000000000000000000000000000000003",
			"aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"},
		{"000000000000000000000000000000000000000000000000000000000000dead",
			"f42bd00425d5d4c1ca4b4b175b591a465f74446f47df42584ba04b757edc3a24"},
		{"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
			"914d47eadd1a84ad261d231b5054aea577dd02ac01d455bf3590f79f49acf5de"},
		{"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"},
		{"deadbeefcafebabe0123456789abcdeffedcba9876543210cafef00dbaadf00d",
			"170a4b20887689501d7227346921e6a896789603922c2494b5caacaaa5126e08"},
		{"1000000000000000000000000000000000000000000000000000000000000000",
			"0d06633a905c1e8a7f8b6041e607725d40855e124ad943df2b61cee7d744e7aa"},
	}
	for i, v := range invert {
		x := unhex32(t, v.x)
		want := unhex32(t, v.xInv)
		got, ok := runtime.P256ScalarInvertForTest(x)
		if !ok {
			t.Errorf("invert case %d: rejected", i)
			continue
		}
		if !bytesEq(got[:], want) {
			t.Errorf("invert case %d\nx    %s\nwant %s\ngot  %x", i, v.x, v.xInv, got)
		}
	}

	mul := [...]struct{ x, y, xy string }{
		{"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000002",
			"0000000000000000000000000000000000000000000000000000000000000002"},
		{"0000000000000000000000000000000000000000000000000000000000000002",
			"0000000000000000000000000000000000000000000000000000000000000003",
			"0000000000000000000000000000000000000000000000000000000000000006"},
		{"000000000000000000000000000000000000000000000000000000000000dead",
			"deadbeefcafebabe0123456789abcdeffedcba9876543210cafef00dbaadf00d",
			"26febbc6141435b25b05b05b05b07cf6e64a129ba4798fb6ad21f012be07a0c8"},
		{"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
			"7fffffff0000000100000000000000005f8f8c3a4f734e6713d09b7c944804b1"},
		{"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
			"1000000000000000000000000000000000000000000000000000000000000000",
			"efffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"},
		{"deadbeefcafebabe0123456789abcdeffedcba9876543210cafef00dbaadf00d",
			"deadbeefcafebabe0123456789abcdeffedcba9876543210cafef00dbaadf00d",
			"809ca5999e815e92769eb5897889e12875271a393594e7e9836c31c03b092a24"},
		{"1000000000000000000000000000000000000000000000000000000000000000",
			"1000000000000000000000000000000000000000000000000000000000000000",
			"fe66e12c96f3d9571e2845b2392b6bec16b3c631e8132cb790557b7a0c28d8f5"},
	}
	for i, v := range mul {
		x := unhex32(t, v.x)
		y := unhex32(t, v.y)
		want := unhex32(t, v.xy)
		got, ok := runtime.P256ScalarMulForTest(x, y)
		if !ok {
			t.Errorf("mul case %d: rejected", i)
			continue
		}
		if !bytesEq(got[:], want) {
			t.Errorf("mul case %d\nx    %s\ny    %s\nwant %s\ngot  %x", i, v.x, v.y, v.xy, got)
		}
	}
}

// TestJanosP256PointGeneratorOnCurve: the hardcoded generator G
// must satisfy y² = x³ − 3x + b.  If this fails, the Montgomery-
// form limbs of Gx or Gy (or b) are wrong.
func TestJanosP256PointGeneratorOnCurve(t *testing.T) {
	if !runtime.P256GeneratorIsOnCurveForTest() {
		t.Fatal("hardcoded P-256 generator is not on the curve")
	}
}

// TestJanosP256PointAddDoubleConsistent: Add(G, G) affine == 2G
// affine.  Independently verifies both the addition and doubling
// formulas since either could produce a wrong Z-scaled result that
// still round-trips through the OTHER formula's Z.
func TestJanosP256PointAddDoubleConsistent(t *testing.T) {
	if !runtime.P256AddDoubleConsistentForTest() {
		t.Fatal("G + G != 2G — Add and Double disagree")
	}
}

// TestJanosP256PointAddInfinity: Add(G, infinity) == G.
func TestJanosP256PointAddInfinity(t *testing.T) {
	if !runtime.P256AddInfinityForTest() {
		t.Fatal("G + O != G")
	}
}

// TestJanosP256PointNegatePlusIsInfinity: G + (-G) is the identity.
func TestJanosP256PointNegatePlusIsInfinity(t *testing.T) {
	if !runtime.P256NegatePlusPointIsInfinityForTest() {
		t.Fatal("G + (-G) != infinity")
	}
}

// TestJanosP256ScalarBaseMultVectors: verify against math/big-derived
// (k, kG.x, kG.y) triples spanning k = 1, 2, 3, 4, 15, 255, 0xdeadbeef,
// mid-range, and n - 1.  The last case is a nice sanity check because
// (n-1)*G = -G, so kG.x should equal Gx and kG.y should equal (p - Gy).
func TestJanosP256ScalarBaseMultVectors(t *testing.T) {
	vecs := [...]struct{ k, x, y string }{
		{"0000000000000000000000000000000000000000000000000000000000000001",
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
			"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"},
		{"0000000000000000000000000000000000000000000000000000000000000002",
			"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
			"07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"},
		{"0000000000000000000000000000000000000000000000000000000000000003",
			"5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
			"8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"},
		{"0000000000000000000000000000000000000000000000000000000000000004",
			"e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
			"e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6"},
		{"000000000000000000000000000000000000000000000000000000000000000f",
			"f0454dc6971abae7adfb378999888265ae03af92de3a0ef163668c63e59b9d5f",
			"b5b93ee3592e2d1f4e6594e51f9643e62a3b21ce75b5fa3f47e59cde0d034f36"},
		{"00000000000000000000000000000000000000000000000000000000000000ff",
			"f44b39759a2e6db723a6f90249972dfd08e95380f1fca470eacd1d03e5edf214",
			"befafccf223ca065f0a0db4eea93ff06a2116fca81f7a4a9436a8d917a02dede"},
		{"00000000000000000000000000000000000000000000000000000000deadbeef",
			"b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c18394",
			"2a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e"},
		{"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5",
			"fd40f20ff754ebfddf2f2ab8b6bbc6b03791816107e77c7449882b875992d639",
			"a744fae37069cb4beeb7ee9d518393788d2f5f19c5310bfbe6bf302bbd320de7"},
		{"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
			"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
			"b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"},
	}
	for i, v := range vecs {
		k := unhex32(t, v.k)
		gotX, gotY, ok := runtime.P256ScalarBaseMultForTest(k)
		if !ok {
			t.Errorf("case %d: ScalarBaseMult returned infinity or bad input", i)
			continue
		}
		wantX := unhex32(t, v.x)
		wantY := unhex32(t, v.y)
		if !bytesEq(gotX[:], wantX) {
			t.Errorf("case %d: kG.x mismatch\nk    %s\nwant %s\ngot  %x", i, v.k, v.x, gotX)
		}
		if !bytesEq(gotY[:], wantY) {
			t.Errorf("case %d: kG.y mismatch\nk    %s\nwant %s\ngot  %x", i, v.k, v.y, gotY)
		}
	}
}

// TestJanosP256PointUncompressedRoundTrip: parse the generator's
// SEC1 X||Y form and check the affine coordinates come back
// unchanged.  Also exercises isOnCurve since SetUncompressedBytes
// runs it internally.
func TestJanosP256PointUncompressedRoundTrip(t *testing.T) {
	gX := unhex32(t, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	gY := unhex32(t, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	var xy [64]byte
	copy(xy[:32], gX)
	copy(xy[32:], gY)

	gotX, gotY, ok := runtime.P256UncompressedRoundTripForTest(xy[:])
	if !ok {
		t.Fatal("SetUncompressedBytes rejected valid generator encoding")
	}
	if !bytesEq(gotX[:], gX) {
		t.Errorf("x mismatch:\nwant %x\ngot  %x", gX, gotX)
	}
	if !bytesEq(gotY[:], gY) {
		t.Errorf("y mismatch:\nwant %x\ngot  %x", gY, gotY)
	}
}

// TestJanosP256PointRejectOffCurve: (Gx, Gy+1) is not on the curve,
// so SetUncompressedBytes must refuse it.
func TestJanosP256PointRejectOffCurve(t *testing.T) {
	gX := unhex32(t, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	// Gy + 1
	badY := unhex32(t, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6")
	var xy [64]byte
	copy(xy[:32], gX)
	copy(xy[32:], badY)

	if _, _, ok := runtime.P256UncompressedRoundTripForTest(xy[:]); ok {
		t.Error("accepted an off-curve point (Gx, Gy+1)")
	}
}

// unhex32 decodes a 64-character hex string into 32 bytes, failing
// the test if the length or characters are wrong.  Runtime tests
// can't import encoding/hex, so we roll a tiny decoder.
func unhex32(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) != 64 {
		t.Fatalf("unhex32: want 64 chars, got %d", len(s))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = hexNibble(t, s[2*i])<<4 | hexNibble(t, s[2*i+1])
	}
	return out
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	t.Fatalf("bad hex char %q", c)
	return 0
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// JanOS: P-256 scalar arithmetic (mod n, the curve order).
//
// The stdlib pure-Go path for P-256 scalar operations is stubbed out
// as "unimplemented" (see crypto/internal/fips140/nistec/p256_ordinv_noasm.go)
// — the fast path lives in assembly.  The runtime needs pure Go, so we
// implement CIOS Montgomery multiplication mod n directly.
//
// n = 0xffffffff00000000_ffffffffffffffff_bce6faada7179e84_f3b9cac2fc632551
//
// Scalars are represented in the Montgomery domain (value × R mod n
// where R = 2^256) as 4 little-endian uint64 limbs.  Conversions in
// and out happen at SetBytes / Bytes boundaries.
//
// Verify is not constant-time — but ECDSA verification only takes
// public inputs (signature, hash, public key), so timing side-channels
// aren't a concern here.

package runtime

import "math/bits"

// P-256 curve order, little-endian limbs.
var p256ScalarN = [4]uint64{
	0xf3b9cac2fc632551,
	0xbce6faada7179e84,
	0xffffffffffffffff,
	0xffffffff00000000,
}

// -n^-1 mod 2^64.  Precomputed constant used by the Montgomery
// reduction step.
const p256ScalarNInv0 = 0xccd1c8aaee00bc4f

// R^2 mod n where R = 2^256, in little-endian limb form.  Used to
// convert values into the Montgomery domain.
var p256ScalarRR = [4]uint64{
	0x83244c95be79eea2,
	0x4699799c49bd6fa6,
	0x2845b2392b6bec59,
	0x66e12d94f3d95620,
}

// janosP256Scalar is an integer modulo n.  The zero value is a valid
// zero scalar.  Values are held in the Montgomery domain internally
// and converted at Bytes / SetBytesBE boundaries.
type janosP256Scalar struct {
	limbs [4]uint64
}

// p256ScalarMontMul computes out = (a * b * R^-1) mod n via CIOS
// Montgomery multiplication (Koç, Acar & Kaliski 1996 §2.3).
//
// The accumulator t has s+2 = 6 words: t[0..3] for the current
// residue, t[4] and t[5] to absorb overflow from the multiply-add
// and reduction steps.  A running carry is carried as a 2-word
// value (cLo, cHi) inside each inner loop so we never drop bits
// when hi from bits.Mul64 lands near 2^64-1.  A single-word carry
// there was the previous bug: 2*3=6 worked but exponentiation
// silently corrupted its accumulator.
//
// Per outer iteration i:
//
//	t += a * b[i]                         // (multiply-add)
//	m := t[0] * NInv0 mod 2^64
//	t += m * n                            // (Montgomery reduction, forces t[0]==0)
//	t >>= 64                              // shift the zero out
//
// After 4 iterations, t < 2n; a conditional subtraction brings the
// result into [0, n).
func p256ScalarMontMul(out, a, b *[4]uint64) {
	var t [6]uint64

	for i := 0; i < 4; i++ {
		// t += a * b[i]
		var cLo, cHi uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a[j], b[i])
			var c uint64
			// Add lo to t[j]; propagate into hi.  hi<=2^64-2 out
			// of Mul64, so hi + c1 <= 2^64-1 — safe to discard
			// the outer add's carry-out here.
			lo, c = bits.Add64(lo, t[j], 0)
			hi, _ = bits.Add64(hi, 0, c)
			// Add the running carry (cLo:cHi), capturing its
			// overflow into a new 2-word carry.
			lo, c = bits.Add64(lo, cLo, 0)
			hi, cc := bits.Add64(hi, cHi, c)
			t[j] = lo
			cLo = hi
			cHi = cc
		}
		// Drain the remaining carry into t[4], then t[5].
		var cc uint64
		t[4], cc = bits.Add64(t[4], cLo, 0)
		t[5], _ = bits.Add64(t[5], cHi, cc)

		// Montgomery reduction: m = t[0] * NInv0 mod 2^64
		m := t[0] * p256ScalarNInv0

		// t += m * n.  After this loop t[0] is guaranteed to be 0.
		cLo, cHi = 0, 0
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(m, p256ScalarN[j])
			var c uint64
			lo, c = bits.Add64(lo, t[j], 0)
			hi, _ = bits.Add64(hi, 0, c)
			lo, c = bits.Add64(lo, cLo, 0)
			hi, cc := bits.Add64(hi, cHi, c)
			t[j] = lo
			cLo = hi
			cHi = cc
		}
		t[4], cc = bits.Add64(t[4], cLo, 0)
		t[5], _ = bits.Add64(t[5], cHi, cc)

		// Shift right by 64 bits: t[0] is now 0.
		t[0] = t[1]
		t[1] = t[2]
		t[2] = t[3]
		t[3] = t[4]
		t[4] = t[5]
		t[5] = 0
	}

	// Final conditional subtraction: if t >= n, subtract n.
	var borrow uint64
	var sub [4]uint64
	sub[0], borrow = bits.Sub64(t[0], p256ScalarN[0], 0)
	sub[1], borrow = bits.Sub64(t[1], p256ScalarN[1], borrow)
	sub[2], borrow = bits.Sub64(t[2], p256ScalarN[2], borrow)
	sub[3], borrow = bits.Sub64(t[3], p256ScalarN[3], borrow)

	// If t[4] is nonzero, t >= 2^256 > n, so we must subtract even
	// if the 256-bit compare would suggest otherwise.  Fold t[4]
	// into the borrow decision.
	var mask uint64
	if borrow == 0 || t[4] != 0 {
		mask = ^uint64(0)
	}
	out[0] = (sub[0] & mask) | (t[0] &^ mask)
	out[1] = (sub[1] & mask) | (t[1] &^ mask)
	out[2] = (sub[2] & mask) | (t[2] &^ mask)
	out[3] = (sub[3] & mask) | (t[3] &^ mask)
}

// p256ScalarMontSqr repeats out = out * out * R^-1 mod n, n times.
// n >= 1.
func p256ScalarMontSqr(out, in *[4]uint64, n int) {
	p256ScalarMontMul(out, in, in)
	for i := 1; i < n; i++ {
		p256ScalarMontMul(out, out, out)
	}
}

// SetBytesBE decodes a 32-byte big-endian value and reduces it mod n.
// Returns (s, true) on success, or (nil, false) if the input length
// is wrong.  Callers that need to enforce s < n for ECDSA r/s should
// check the return of geqN before calling — this method itself
// silently reduces.
func (s *janosP256Scalar) SetBytesBE(b []byte) (*janosP256Scalar, bool) {
	if len(b) != 32 {
		return nil, false
	}
	// Little-endian limbs from big-endian bytes.
	s.limbs[3] = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	s.limbs[2] = uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	s.limbs[1] = uint64(b[16])<<56 | uint64(b[17])<<48 | uint64(b[18])<<40 | uint64(b[19])<<32 |
		uint64(b[20])<<24 | uint64(b[21])<<16 | uint64(b[22])<<8 | uint64(b[23])
	s.limbs[0] = uint64(b[24])<<56 | uint64(b[25])<<48 | uint64(b[26])<<40 | uint64(b[27])<<32 |
		uint64(b[28])<<24 | uint64(b[29])<<16 | uint64(b[30])<<8 | uint64(b[31])

	// Reduce mod n if needed.  Input can be up to 2^256 - 1 which is
	// slightly more than n; at most one subtraction is required.
	var borrow uint64
	var sub [4]uint64
	sub[0], borrow = bits.Sub64(s.limbs[0], p256ScalarN[0], 0)
	sub[1], borrow = bits.Sub64(s.limbs[1], p256ScalarN[1], borrow)
	sub[2], borrow = bits.Sub64(s.limbs[2], p256ScalarN[2], borrow)
	sub[3], borrow = bits.Sub64(s.limbs[3], p256ScalarN[3], borrow)
	if borrow == 0 {
		s.limbs = sub
	}

	// Convert to Montgomery domain: s := s * R (via MontMul with R^2).
	p256ScalarMontMul(&s.limbs, &s.limbs, &p256ScalarRR)
	return s, true
}

// Bytes returns the 32-byte big-endian encoding of s (out of the
// Montgomery domain).
func (s *janosP256Scalar) Bytes() [32]byte {
	// Convert out of Montgomery: s * R^-1 (equivalent to MontMul with 1).
	var one = [4]uint64{1, 0, 0, 0}
	var t [4]uint64
	p256ScalarMontMul(&t, &s.limbs, &one)

	var out [32]byte
	// Big-endian from little-endian limbs.
	beWriteUint64(out[0:8], t[3])
	beWriteUint64(out[8:16], t[2])
	beWriteUint64(out[16:24], t[1])
	beWriteUint64(out[24:32], t[0])
	return out
}

func beWriteUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// IsZero reports whether s == 0.
func (s *janosP256Scalar) IsZero() bool {
	return s.limbs[0]|s.limbs[1]|s.limbs[2]|s.limbs[3] == 0
}

// Mul sets s = a * b mod n and returns s.
func (s *janosP256Scalar) Mul(a, b *janosP256Scalar) *janosP256Scalar {
	p256ScalarMontMul(&s.limbs, &a.limbs, &b.limbs)
	return s
}

// p256ScalarNMinus2 is n-2 in little-endian limbs.  Used as the
// exponent for Fermat-based inversion (x^(n-2) = x^-1 mod n).
var p256ScalarNMinus2 = [4]uint64{
	0xf3b9cac2fc63254f, // n[0] - 2
	0xbce6faada7179e84,
	0xffffffffffffffff,
	0xffffffff00000000,
}

// Invert sets s = 1/x mod n via Fermat's little theorem
// (x^(n-2) = x^-1 mod n).  If x == 0, s = 0.
//
// Uses left-to-right binary square-and-multiply.  Not constant-time
// on n-2 — but n-2 is a public constant, and verify only touches
// public inputs anyway, so timing side-channels don't matter here.
//
// Stdlib uses a shorter addition chain (38 mul + 254 sqr) for
// performance; the naive square-and-multiply uses 256 sqr + up to
// 256 mul, which is a few microseconds difference on modern
// hardware.  We take the extra cost in exchange for a routine that
// is trivially reviewable.
func (s *janosP256Scalar) Invert(x *janosP256Scalar) *janosP256Scalar {
	if x.IsZero() {
		s.limbs = [4]uint64{}
		return s
	}
	// result starts at Mont(1) = R mod n.  We obtain it via
	// MontMul(RR, 1_untyped) = RR * 1 * R^-1 = R^2 * R^-1 = R.
	var result [4]uint64
	oneUntyped := [4]uint64{1, 0, 0, 0}
	p256ScalarMontMul(&result, &p256ScalarRR, &oneUntyped)

	base := x.limbs // Mont(x)

	// Iterate exponent bits MSB → LSB.
	for limbIdx := 3; limbIdx >= 0; limbIdx-- {
		limb := p256ScalarNMinus2[limbIdx]
		for bit := 63; bit >= 0; bit-- {
			p256ScalarMontMul(&result, &result, &result) // square
			if (limb>>bit)&1 == 1 {
				p256ScalarMontMul(&result, &result, &base) // multiply
			}
		}
	}
	s.limbs = result
	return s
}

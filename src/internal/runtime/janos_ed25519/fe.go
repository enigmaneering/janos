// Copyright (c) 2017 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package janos_ed25519 provides Ed25519 signature verification for
// use by the JanOS runtime.  It sits at the internal/runtime layer so
// package runtime can import it while the (much larger) crypto/ed25519
// stays above.
//
// Verification-only: signing is a linker/tooling concern; the runtime
// only needs to check that the running binary's certificate slot bears
// a valid Ed25519 signature.
//
// This file implements the GF(2^255-19) field element type, ported
// from crypto/internal/fips140/edwards25519/field.
package janos_ed25519

import (
	"internal/byteorder"
	"math/bits"
)

// Element represents an element of the field GF(2^255-19).  This type
// is not cryptographically secure on its own; it is exposed only to
// support Point coordinate arithmetic.
//
// The zero value is a valid zero element.  All operation receivers
// and arguments are allowed to alias.
type Element struct {
	// t represents t.l0 + t.l1*2^51 + t.l2*2^102 + t.l3*2^153 + t.l4*2^204.
	// Between operations all limbs are at most slightly above 2^51.
	l0, l1, l2, l3, l4 uint64
}

const maskLow51Bits uint64 = (1 << 51) - 1

var feZero = &Element{0, 0, 0, 0, 0}
var feOne = &Element{1, 0, 0, 0, 0}

// Zero sets v = 0 and returns v.
func (v *Element) Zero() *Element { *v = *feZero; return v }

// One sets v = 1 and returns v.
func (v *Element) One() *Element { *v = *feOne; return v }

// Set sets v = a and returns v.
func (v *Element) Set(a *Element) *Element { *v = *a; return v }

// reduce reduces v modulo 2^255-19 and returns it.
func (v *Element) reduce() *Element {
	v.carryPropagate()
	c := (v.l0 + 19) >> 51
	c = (v.l1 + c) >> 51
	c = (v.l2 + c) >> 51
	c = (v.l3 + c) >> 51
	c = (v.l4 + c) >> 51
	v.l0 += 19 * c
	v.l1 += v.l0 >> 51
	v.l0 &= maskLow51Bits
	v.l2 += v.l1 >> 51
	v.l1 &= maskLow51Bits
	v.l3 += v.l2 >> 51
	v.l2 &= maskLow51Bits
	v.l4 += v.l3 >> 51
	v.l3 &= maskLow51Bits
	v.l4 &= maskLow51Bits
	return v
}

// Add sets v = a + b and returns v.
func (v *Element) Add(a, b *Element) *Element {
	v.l0 = a.l0 + b.l0
	v.l1 = a.l1 + b.l1
	v.l2 = a.l2 + b.l2
	v.l3 = a.l3 + b.l3
	v.l4 = a.l4 + b.l4
	return v.carryPropagate()
}

// Subtract sets v = a - b and returns v.  We first add 2*p to a to
// avoid underflow, then subtract b (which can be up to 2^255 + 2^13*19).
func (v *Element) Subtract(a, b *Element) *Element {
	v.l0 = (a.l0 + 0xFFFFFFFFFFFDA) - b.l0
	v.l1 = (a.l1 + 0xFFFFFFFFFFFFE) - b.l1
	v.l2 = (a.l2 + 0xFFFFFFFFFFFFE) - b.l2
	v.l3 = (a.l3 + 0xFFFFFFFFFFFFE) - b.l3
	v.l4 = (a.l4 + 0xFFFFFFFFFFFFE) - b.l4
	return v.carryPropagate()
}

// Negate sets v = -a and returns v.
func (v *Element) Negate(a *Element) *Element { return v.Subtract(feZero, a) }

// SetBytes sets v to x, where x is a 32-byte little-endian encoding.
// Returns v and true on success, or (nil, false) if x is not 32 bytes.
//
// Consistent with RFC 7748, the most significant bit is ignored and
// non-canonical values (2^255-19 through 2^255-1) are accepted.  This
// is laxer than RFC 8032 but matches every Ed25519 implementation in
// the wild.
func (v *Element) SetBytes(x []byte) (*Element, bool) {
	if len(x) != 32 {
		return nil, false
	}
	v.l0 = byteorder.LEUint64(x[0:8]) & maskLow51Bits
	v.l1 = (byteorder.LEUint64(x[6:14]) >> 3) & maskLow51Bits
	v.l2 = (byteorder.LEUint64(x[12:20]) >> 6) & maskLow51Bits
	v.l3 = (byteorder.LEUint64(x[19:27]) >> 1) & maskLow51Bits
	v.l4 = (byteorder.LEUint64(x[24:32]) >> 12) & maskLow51Bits
	return v, true
}

// Bytes returns the canonical 32-byte little-endian encoding of v.
func (v *Element) Bytes() [32]byte {
	var out [32]byte
	t := *v
	t.reduce()
	// Pack five 51-bit limbs into four 64-bit words:
	//  255    204    153    102     51      0
	//    ├──l4──┼──l3──┼──l2──┼──l1──┼──l0──┤
	//   ├───u3───┼───u2───┼───u1───┼───u0───┤
	// 256      192      128       64        0
	u0 := t.l1<<51 | t.l0
	u1 := t.l2<<(102-64) | t.l1>>(64-51)
	u2 := t.l3<<(153-128) | t.l2>>(128-102)
	u3 := t.l4<<(204-192) | t.l3>>(192-153)
	byteorder.LEPutUint64(out[0*8:], u0)
	byteorder.LEPutUint64(out[1*8:], u1)
	byteorder.LEPutUint64(out[2*8:], u2)
	byteorder.LEPutUint64(out[3*8:], u3)
	return out
}

// Equal returns 1 if v == u and 0 otherwise, in constant time.
func (v *Element) Equal(u *Element) int {
	sa := u.Bytes()
	sv := v.Bytes()
	var x byte
	for i := range sa {
		x |= sa[i] ^ sv[i]
	}
	// Constant-time reduction of a nonzero byte to 1 and zero to 0:
	// x != 0 -> at least one bit set; use OR-fold + subtract.
	x |= x >> 4
	x |= x >> 2
	x |= x >> 1
	return int((x & 1) ^ 1)
}

// mask64Bits returns ^0 if cond == 1 and 0 if cond == 0.
func mask64Bits(cond int) uint64 { return ^(uint64(cond) - 1) }

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	m := mask64Bits(cond)
	v.l0 = (m & a.l0) | (^m & b.l0)
	v.l1 = (m & a.l1) | (^m & b.l1)
	v.l2 = (m & a.l2) | (^m & b.l2)
	v.l3 = (m & a.l3) | (^m & b.l3)
	v.l4 = (m & a.l4) | (^m & b.l4)
	return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0.
func (v *Element) Swap(u *Element, cond int) {
	m := mask64Bits(cond)
	t := m & (v.l0 ^ u.l0)
	v.l0 ^= t
	u.l0 ^= t
	t = m & (v.l1 ^ u.l1)
	v.l1 ^= t
	u.l1 ^= t
	t = m & (v.l2 ^ u.l2)
	v.l2 ^= t
	u.l2 ^= t
	t = m & (v.l3 ^ u.l3)
	v.l3 ^= t
	u.l3 ^= t
	t = m & (v.l4 ^ u.l4)
	v.l4 ^= t
	u.l4 ^= t
}

// IsNegative returns 1 if v is negative and 0 otherwise.
func (v *Element) IsNegative() int {
	b := v.Bytes()
	return int(b[0] & 1)
}

// Absolute sets v = |u| and returns v.
func (v *Element) Absolute(u *Element) *Element {
	return v.Select(new(Element).Negate(u), u, u.IsNegative())
}

// Multiply sets v = x * y and returns v.
func (v *Element) Multiply(x, y *Element) *Element { feMul(v, x, y); return v }

// Square sets v = x * x and returns v.
func (v *Element) Square(x *Element) *Element { feSquare(v, x); return v }

// Mult32 sets v = x * y and returns v.  y is at most 32 bits.
func (v *Element) Mult32(x *Element, y uint32) *Element {
	x0lo, x0hi := mul51(x.l0, y)
	x1lo, x1hi := mul51(x.l1, y)
	x2lo, x2hi := mul51(x.l2, y)
	x3lo, x3hi := mul51(x.l3, y)
	x4lo, x4hi := mul51(x.l4, y)
	v.l0 = x0lo + 19*x4hi
	v.l1 = x1lo + x0hi
	v.l2 = x2lo + x1hi
	v.l3 = x3lo + x2hi
	v.l4 = x4lo + x3hi
	return v
}

// mul51 returns lo + hi*2^51 = a*b, where b is at most 32 bits.
func mul51(a uint64, b uint32) (lo, hi uint64) {
	mh, ml := bits.Mul64(a, uint64(b))
	lo = ml & maskLow51Bits
	hi = (mh << 13) | (ml >> 51)
	return
}

// Invert sets v = 1/z mod p and returns v.  If z == 0, v = 0.
// Uses the same fixed-window exponentiation as Curve25519: 255
// squarings + 11 multiplications realizing p - 2 = 2^255 - 21.
func (v *Element) Invert(z *Element) *Element {
	var z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t Element
	z2.Square(z)
	t.Square(&z2)
	t.Square(&t)
	z9.Multiply(&t, z)
	z11.Multiply(&z9, &z2)
	t.Square(&z11)
	z2_5_0.Multiply(&t, &z9)

	t.Square(&z2_5_0)
	for i := 0; i < 4; i++ {
		t.Square(&t)
	}
	z2_10_0.Multiply(&t, &z2_5_0)

	t.Square(&z2_10_0)
	for i := 0; i < 9; i++ {
		t.Square(&t)
	}
	z2_20_0.Multiply(&t, &z2_10_0)

	t.Square(&z2_20_0)
	for i := 0; i < 19; i++ {
		t.Square(&t)
	}
	t.Multiply(&t, &z2_20_0)

	t.Square(&t)
	for i := 0; i < 9; i++ {
		t.Square(&t)
	}
	z2_50_0.Multiply(&t, &z2_10_0)

	t.Square(&z2_50_0)
	for i := 0; i < 49; i++ {
		t.Square(&t)
	}
	z2_100_0.Multiply(&t, &z2_50_0)

	t.Square(&z2_100_0)
	for i := 0; i < 99; i++ {
		t.Square(&t)
	}
	t.Multiply(&t, &z2_100_0)

	t.Square(&t)
	for i := 0; i < 49; i++ {
		t.Square(&t)
	}
	t.Multiply(&t, &z2_50_0)

	t.Square(&t)
	t.Square(&t)
	t.Square(&t)
	t.Square(&t)
	t.Square(&t)

	return v.Multiply(&t, &z11)
}

// Pow22523 sets v = x^((p-5)/8) and returns v.  (p-5)/8 = 2^252-3.
// Used inside SqrtRatio.
func (v *Element) Pow22523(x *Element) *Element {
	var t0, t1, t2 Element
	t0.Square(x)
	t1.Square(&t0)
	t1.Square(&t1)
	t1.Multiply(x, &t1)
	t0.Multiply(&t0, &t1)
	t0.Square(&t0)
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 5; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 10; i++ {
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)
	t2.Square(&t1)
	for i := 1; i < 20; i++ {
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)
	t1.Square(&t1)
	for i := 1; i < 10; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t1.Square(&t0)
	for i := 1; i < 50; i++ {
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)
	t2.Square(&t1)
	for i := 1; i < 100; i++ {
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)
	t1.Square(&t1)
	for i := 1; i < 50; i++ {
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)
	t0.Square(&t0)
	t0.Square(&t0)
	return v.Multiply(&t0, x)
}

// sqrtM1 = 2^((p-1)/4), which squares to -1 by Euler's criterion.
var sqrtM1 = &Element{1718705420411056, 234908883556509,
	2233514472574048, 2117202627021982, 765476049583133}

// SqrtRatio sets r to the non-negative square root of u/v.  If u/v is
// square in the field, returns (r, 1).  If not square, sets r per §4.3
// of draft-irtf-cfrg-ristretto255-decaf448-00 and returns (r, 0).
func (r *Element) SqrtRatio(u, v *Element) (out *Element, wasSquare int) {
	t0 := new(Element)
	// r = (u * v^3) * (u * v^7)^((p-5)/8)
	v2 := new(Element).Square(v)
	uv3 := new(Element).Multiply(u, t0.Multiply(v2, v))
	uv7 := new(Element).Multiply(uv3, t0.Square(v2))
	rr := new(Element).Multiply(uv3, t0.Pow22523(uv7))

	check := new(Element).Multiply(v, t0.Square(rr))

	uNeg := new(Element).Negate(u)
	correctSignSqrt := check.Equal(u)
	flippedSignSqrt := check.Equal(uNeg)
	flippedSignSqrtI := check.Equal(t0.Multiply(uNeg, sqrtM1))

	rPrime := new(Element).Multiply(rr, sqrtM1)
	rr.Select(rPrime, rr, flippedSignSqrt|flippedSignSqrtI)

	r.Absolute(rr)
	return r, correctSignSqrt | flippedSignSqrt
}

// -----------------------------------------------------------------
// Below: fast pure-Go implementations of the field multiplication,
// squaring, and carry-propagation primitives, ported from
// crypto/internal/fips140/edwards25519/field/fe_generic.go.

// uint128 holds a 128-bit number as two 64-bit limbs.
type uint128 struct{ lo, hi uint64 }

func mul(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func addMul(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

// mul19 returns v * 19 without a mul instruction.
func mul19(v uint64) uint64 { return v + (v+v<<3)<<1 }

func addMul19(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(mul19(a), b)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

func addMul38(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(mul19(a), b*2)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

func shiftRightBy51(a uint128) uint64 { return (a.hi << (64 - 51)) | (a.lo >> 51) }

func feMul(v, a, b *Element) {
	a0, a1, a2, a3, a4 := a.l0, a.l1, a.l2, a.l3, a.l4
	b0, b1, b2, b3, b4 := b.l0, b.l1, b.l2, b.l3, b.l4

	r0 := mul(a0, b0)
	r0 = addMul19(r0, a1, b4)
	r0 = addMul19(r0, a2, b3)
	r0 = addMul19(r0, a3, b2)
	r0 = addMul19(r0, a4, b1)

	r1 := mul(a0, b1)
	r1 = addMul(r1, a1, b0)
	r1 = addMul19(r1, a2, b4)
	r1 = addMul19(r1, a3, b3)
	r1 = addMul19(r1, a4, b2)

	r2 := mul(a0, b2)
	r2 = addMul(r2, a1, b1)
	r2 = addMul(r2, a2, b0)
	r2 = addMul19(r2, a3, b4)
	r2 = addMul19(r2, a4, b3)

	r3 := mul(a0, b3)
	r3 = addMul(r3, a1, b2)
	r3 = addMul(r3, a2, b1)
	r3 = addMul(r3, a3, b0)
	r3 = addMul19(r3, a4, b4)

	r4 := mul(a0, b4)
	r4 = addMul(r4, a1, b3)
	r4 = addMul(r4, a2, b2)
	r4 = addMul(r4, a3, b1)
	r4 = addMul(r4, a4, b0)

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + mul19(c4)
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	v.l0 = rr0&maskLow51Bits + mul19(rr4>>51)
	v.l1 = rr1&maskLow51Bits + rr0>>51
	v.l2 = rr2&maskLow51Bits + rr1>>51
	v.l3 = rr3&maskLow51Bits + rr2>>51
	v.l4 = rr4&maskLow51Bits + rr3>>51
}

func feSquare(v, a *Element) {
	l0, l1, l2, l3, l4 := a.l0, a.l1, a.l2, a.l3, a.l4

	r0 := mul(l0, l0)
	r0 = addMul38(r0, l1, l4)
	r0 = addMul38(r0, l2, l3)

	r1 := mul(l0*2, l1)
	r1 = addMul38(r1, l2, l4)
	r1 = addMul19(r1, l3, l3)

	r2 := mul(l0*2, l2)
	r2 = addMul(r2, l1, l1)
	r2 = addMul38(r2, l3, l4)

	r3 := mul(l0*2, l3)
	r3 = addMul(r3, l1*2, l2)
	r3 = addMul19(r3, l4, l4)

	r4 := mul(l0*2, l4)
	r4 = addMul(r4, l1*2, l3)
	r4 = addMul(r4, l2, l2)

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	rr0 := r0.lo&maskLow51Bits + mul19(c4)
	rr1 := r1.lo&maskLow51Bits + c0
	rr2 := r2.lo&maskLow51Bits + c1
	rr3 := r3.lo&maskLow51Bits + c2
	rr4 := r4.lo&maskLow51Bits + c3

	v.l0 = rr0&maskLow51Bits + mul19(rr4>>51)
	v.l1 = rr1&maskLow51Bits + rr0>>51
	v.l2 = rr2&maskLow51Bits + rr1>>51
	v.l3 = rr3&maskLow51Bits + rr2>>51
	v.l4 = rr4&maskLow51Bits + rr3>>51
}

// carryPropagate brings the limbs below 52 bits by applying the
// reduction identity (a*2^255 + b = a*19 + b) to the l4 carry.
func (v *Element) carryPropagate() *Element {
	l0 := v.l0
	v.l0 = v.l0&maskLow51Bits + mul19(v.l4>>51)
	v.l4 = v.l4&maskLow51Bits + v.l3>>51
	v.l3 = v.l3&maskLow51Bits + v.l2>>51
	v.l2 = v.l2&maskLow51Bits + v.l1>>51
	v.l1 = v.l1&maskLow51Bits + l0>>51
	return v
}

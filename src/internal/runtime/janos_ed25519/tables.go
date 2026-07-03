// Copyright (c) 2019 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from crypto/internal/fips140/edwards25519/tables.go.
// Only structural change from upstream: constanttime.ByteEq is
// replaced with an inline constant-time helper because the compiler
// intrinsic is not available at this layer.

package janos_ed25519

// projLookupTable is a dynamic lookup table for variable-base,
// constant-time scalar mults.
type projLookupTable struct{ points [8]projCached }

// affineLookupTable is a precomputed lookup table for fixed-base,
// constant-time scalar mults.
type affineLookupTable struct{ points [8]affineCached }

// nafLookupTable5 is a dynamic lookup table for variable-base,
// variable-time scalar mults.
type nafLookupTable5 struct{ points [8]projCached }

// nafLookupTable8 is a precomputed lookup table for fixed-base,
// variable-time scalar mults.
type nafLookupTable8 struct{ points [64]affineCached }

// -- Constructors -------------------------------------------------

// FromP3 builds a lookup table at runtime.  Fast.
// Goal: v.points[i] = (i+1)*Q, i.e. Q, 2Q, ..., 8Q.
func (v *projLookupTable) FromP3(q *Point) {
	v.points[0].FromP3(q)
	tmpP3 := Point{}
	tmpP1xP1 := projP1xP1{}
	for i := 0; i < 7; i++ {
		v.points[i+1].FromP3(tmpP3.fromP1xP1(tmpP1xP1.Add(q, &v.points[i])))
	}
}

// FromP3 builds a lookup table at runtime.  Not optimised for speed;
// fixed-base tables should be precomputed.
func (v *affineLookupTable) FromP3(q *Point) {
	v.points[0].FromP3(q)
	tmpP3 := Point{}
	tmpP1xP1 := projP1xP1{}
	for i := 0; i < 7; i++ {
		v.points[i+1].FromP3(tmpP3.fromP1xP1(tmpP1xP1.AddAffine(q, &v.points[i])))
	}
}

// FromP3 builds a NAF-5 lookup table at runtime.  Fast.
// Goal: v.points[i] = (2*i+1)*Q, i.e. Q, 3Q, 5Q, ..., 15Q.
func (v *nafLookupTable5) FromP3(q *Point) {
	v.points[0].FromP3(q)
	q2 := Point{}
	q2.Add(q, q)
	tmpP3 := Point{}
	tmpP1xP1 := projP1xP1{}
	for i := 0; i < 7; i++ {
		v.points[i+1].FromP3(tmpP3.fromP1xP1(tmpP1xP1.Add(&q2, &v.points[i])))
	}
}

// FromP3 builds a NAF-8 lookup table at runtime.  Not optimised for
// speed; fixed-base tables should be precomputed.
func (v *nafLookupTable8) FromP3(q *Point) {
	v.points[0].FromP3(q)
	q2 := Point{}
	q2.Add(q, q)
	tmpP3 := Point{}
	tmpP1xP1 := projP1xP1{}
	for i := 0; i < 63; i++ {
		v.points[i+1].FromP3(tmpP3.fromP1xP1(tmpP1xP1.AddAffine(&q2, &v.points[i])))
	}
}

// -- Selectors ----------------------------------------------------

// byteEqCT returns 1 if x == y and 0 otherwise, in constant time.
// Standard XOR+fold pattern.  The stdlib uses crypto/internal/constanttime.ByteEq,
// which is a compiler intrinsic; we can't reach that at this layer.
func byteEqCT(x, y uint8) int {
	d := uint32(x ^ y)
	d |= d >> 4
	d |= d >> 2
	d |= d >> 1
	return int((d & 1) ^ 1)
}

// SelectInto sets dest = x*Q for -8 <= x <= 8, in constant time.
func (v *projLookupTable) SelectInto(dest *projCached, x int8) {
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	dest.Zero()
	for j := 1; j <= 8; j++ {
		cond := byteEqCT(xabs, uint8(j))
		dest.Select(&v.points[j-1], dest, cond)
	}
	dest.CondNeg(int(xmask & 1))
}

// SelectInto sets dest = x*Q for -8 <= x <= 8, in constant time.
func (v *affineLookupTable) SelectInto(dest *affineCached, x int8) {
	xmask := x >> 7
	xabs := uint8((x + xmask) ^ xmask)

	dest.Zero()
	for j := 1; j <= 8; j++ {
		cond := byteEqCT(xabs, uint8(j))
		dest.Select(&v.points[j-1], dest, cond)
	}
	dest.CondNeg(int(xmask & 1))
}

// SelectInto sets dest = x*Q for odd x, 0 < x < 2^4 (variable time).
func (v *nafLookupTable5) SelectInto(dest *projCached, x int8) {
	*dest = v.points[x/2]
}

// SelectInto sets dest = x*Q for odd x, 0 < x < 2^7 (variable time).
func (v *nafLookupTable8) SelectInto(dest *affineCached, x int8) {
	*dest = v.points[x/2]
}

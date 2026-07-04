// Copyright 2022 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// JanOS: P-256 point arithmetic in projective coordinates.
//
// Points are (X:Y:Z) with affine (x, y) = (X/Z, Y/Z).  The point at
// infinity is (0:1:0).  Addition and doubling use the complete
// formulas of Renes, Costello & Batina 2015 (eprint 2015/1060, §A.2)
// which have no exceptional cases — the identity element, sums of
// inverses, and doublings are all handled by the same formula.
//
// Ported from crypto/internal/fips140/nistec/p256.go with adaptations
// for the runtime:
//   - No heap allocation (no `new(...)`).  Temporaries live on the
//     stack via value-typed janosP256Element.
//   - No sync.Once.  The curve constant b, generator G, and Mont(1)
//     are stored as pre-computed Montgomery-form byte constants.
//   - No unsafe / precomputed base-point tables.  ScalarMult uses
//     variable-time left-to-right double-and-add.  ECDSA verify only
//     touches public inputs (r, s, pk, digest), so timing side-
//     channels are not a concern here.
//
// The runtime code below is used only for verifying the JANOSCRT
// slot's Release entry at schedinit time.

package runtime

// janosP256Point is a P-256 point in projective coordinates.
type janosP256Point struct {
	x, y, z janosP256Element
}

// Curve constants pre-computed in Montgomery form (see scratchpad
// gen_b_mont.go for the derivation).

var p256BMont = janosP256Element{x: p256MontgomeryDomainFieldElement{
	0xd89cdf6229c4bddf,
	0xacf005cd78843090,
	0xe5a220abf7212ed6,
	0xdc30061d04874834,
}}

var p256GxMont = janosP256Element{x: p256MontgomeryDomainFieldElement{
	0x79e730d418a9143c,
	0x75ba95fc5fedb601,
	0x79fb732b77622510,
	0x18905f76a53755c6,
}}

var p256GyMont = janosP256Element{x: p256MontgomeryDomainFieldElement{
	0xddf25357ce95560a,
	0x8b4ab8e4ba19e45c,
	0xd2e88688dd21f325,
	0x8571ff1825885d85,
}}

// SetInfinity sets p to the identity element (point at infinity):
// (0 : 1 : 0) in projective form.
func (p *janosP256Point) SetInfinity() *janosP256Point {
	p.x = janosP256Element{}
	p.y.One()
	p.z = janosP256Element{}
	return p
}

// SetGenerator sets p to the P-256 generator G.
func (p *janosP256Point) SetGenerator() *janosP256Point {
	p.x = p256GxMont
	p.y = p256GyMont
	p.z.One()
	return p
}

// Set copies q into p.
func (p *janosP256Point) Set(q *janosP256Point) *janosP256Point {
	p.x.Set(&q.x)
	p.y.Set(&q.y)
	p.z.Set(&q.z)
	return p
}

// IsInfinity reports whether p is the point at infinity.
func (p *janosP256Point) IsInfinity() bool {
	return p.z.IsZero() == 1
}

// SetUncompressedBytes parses a 64-byte X||Y big-endian encoding
// (the SEC1 uncompressed form without the leading 0x04 tag — this is
// how the JANOSCRT slot stores public keys) and sets p accordingly.
// Returns (p, true) on success; (nil, false) if the encoding is
// malformed or the point is not on the curve.
func (p *janosP256Point) SetUncompressedBytes(b []byte) (*janosP256Point, bool) {
	if len(b) != 64 {
		return nil, false
	}
	if _, ok := p.x.SetBytes(b[:32]); !ok {
		return nil, false
	}
	if _, ok := p.y.SetBytes(b[32:]); !ok {
		return nil, false
	}
	p.z.One()
	if !p.isOnCurve() {
		return nil, false
	}
	return p, true
}

// isOnCurve reports whether the affine point (p.x, p.y) satisfies
// y² = x³ − 3x + b.  Assumes z == 1 (call SetUncompressedBytes first).
func (p *janosP256Point) isOnCurve() bool {
	// rhs = x³ − 3x + b
	var rhs, threeX, tmp janosP256Element
	rhs.Square(&p.x)
	rhs.Mul(&rhs, &p.x)
	threeX.Add(&p.x, &p.x)
	threeX.Add(&threeX, &p.x)
	rhs.Sub(&rhs, &threeX)
	rhs.Add(&rhs, &p256BMont)

	// lhs = y²
	tmp.Square(&p.y)
	return rhs.Equal(&tmp) == 1
}

// AffineX returns the x-coordinate of p as a 32-byte big-endian
// value, converting out of projective form via one field inversion.
// If p is the point at infinity, returns ([32]byte{}, false).
func (p *janosP256Point) AffineX() ([janosP256ElementLen]byte, bool) {
	if p.IsInfinity() {
		return [janosP256ElementLen]byte{}, false
	}
	var zinv, x janosP256Element
	zinv.Invert(&p.z)
	x.Mul(&p.x, &zinv)
	return x.Bytes(), true
}

// Add sets q = p1 + p2 using the complete addition formula for
// short Weierstrass curves with a = −3 (Renes-Costello-Batina §A.2,
// Algorithm 4).  The operands may overlap.
func (q *janosP256Point) Add(p1, p2 *janosP256Point) *janosP256Point {
	var t0, t1, t2, t3, t4, x3, y3, z3 janosP256Element

	t0.Mul(&p1.x, &p2.x) // t0 := X1 * X2
	t1.Mul(&p1.y, &p2.y) // t1 := Y1 * Y2
	t2.Mul(&p1.z, &p2.z) // t2 := Z1 * Z2
	t3.Add(&p1.x, &p1.y) // t3 := X1 + Y1
	t4.Add(&p2.x, &p2.y) // t4 := X2 + Y2
	t3.Mul(&t3, &t4)     // t3 := t3 * t4
	t4.Add(&t0, &t1)     // t4 := t0 + t1
	t3.Sub(&t3, &t4)     // t3 := t3 - t4
	t4.Add(&p1.y, &p1.z) // t4 := Y1 + Z1
	x3.Add(&p2.y, &p2.z) // X3 := Y2 + Z2
	t4.Mul(&t4, &x3)     // t4 := t4 * X3
	x3.Add(&t1, &t2)     // X3 := t1 + t2
	t4.Sub(&t4, &x3)     // t4 := t4 - X3
	x3.Add(&p1.x, &p1.z) // X3 := X1 + Z1
	y3.Add(&p2.x, &p2.z) // Y3 := X2 + Z2
	x3.Mul(&x3, &y3)     // X3 := X3 * Y3
	y3.Add(&t0, &t2)     // Y3 := t0 + t2
	y3.Sub(&x3, &y3)     // Y3 := X3 - Y3
	z3.Mul(&p256BMont, &t2)
	x3.Sub(&y3, &z3) // X3 := Y3 - Z3
	z3.Add(&x3, &x3) // Z3 := X3 + X3
	x3.Add(&x3, &z3) // X3 := X3 + Z3
	z3.Sub(&t1, &x3) // Z3 := t1 - X3
	x3.Add(&t1, &x3) // X3 := t1 + X3
	y3.Mul(&p256BMont, &y3)
	t1.Add(&t2, &t2) // t1 := t2 + t2
	t2.Add(&t1, &t2) // t2 := t1 + t2
	y3.Sub(&y3, &t2) // Y3 := Y3 - t2
	y3.Sub(&y3, &t0) // Y3 := Y3 - t0
	t1.Add(&y3, &y3) // t1 := Y3 + Y3
	y3.Add(&t1, &y3) // Y3 := t1 + Y3
	t1.Add(&t0, &t0) // t1 := t0 + t0
	t0.Add(&t1, &t0) // t0 := t1 + t0
	t0.Sub(&t0, &t2) // t0 := t0 - t2
	t1.Mul(&t4, &y3) // t1 := t4 * Y3
	t2.Mul(&t0, &y3) // t2 := t0 * Y3
	y3.Mul(&x3, &z3) // Y3 := X3 * Z3
	y3.Add(&y3, &t2) // Y3 := Y3 + t2
	x3.Mul(&t3, &x3) // X3 := t3 * X3
	x3.Sub(&x3, &t1) // X3 := X3 - t1
	z3.Mul(&t4, &z3) // Z3 := t4 * Z3
	t1.Mul(&t3, &t0) // t1 := t3 * t0
	z3.Add(&z3, &t1) // Z3 := Z3 + t1

	q.x.Set(&x3)
	q.y.Set(&y3)
	q.z.Set(&z3)
	return q
}

// Double sets q = 2*p using the complete doubling formula
// (Renes-Costello-Batina §A.2, Algorithm 6).
func (q *janosP256Point) Double(p *janosP256Point) *janosP256Point {
	var t0, t1, t2, t3, x3, y3, z3 janosP256Element

	t0.Square(&p.x)    // t0 := X^2
	t1.Square(&p.y)    // t1 := Y^2
	t2.Square(&p.z)    // t2 := Z^2
	t3.Mul(&p.x, &p.y) // t3 := X * Y
	t3.Add(&t3, &t3)   // t3 := t3 + t3
	z3.Mul(&p.x, &p.z) // Z3 := X * Z
	z3.Add(&z3, &z3)   // Z3 := Z3 + Z3
	y3.Mul(&p256BMont, &t2)
	y3.Sub(&y3, &z3) // Y3 := Y3 - Z3
	x3.Add(&y3, &y3) // X3 := Y3 + Y3
	y3.Add(&x3, &y3) // Y3 := X3 + Y3
	x3.Sub(&t1, &y3) // X3 := t1 - Y3
	y3.Add(&t1, &y3) // Y3 := t1 + Y3
	y3.Mul(&x3, &y3) // Y3 := X3 * Y3
	x3.Mul(&x3, &t3) // X3 := X3 * t3
	t3.Add(&t2, &t2) // t3 := t2 + t2
	t2.Add(&t2, &t3) // t2 := t2 + t3
	z3.Mul(&p256BMont, &z3)
	z3.Sub(&z3, &t2)   // Z3 := Z3 - t2
	z3.Sub(&z3, &t0)   // Z3 := Z3 - t0
	t3.Add(&z3, &z3)   // t3 := Z3 + Z3
	z3.Add(&z3, &t3)   // Z3 := Z3 + t3
	t3.Add(&t0, &t0)   // t3 := t0 + t0
	t0.Add(&t3, &t0)   // t0 := t3 + t0
	t0.Sub(&t0, &t2)   // t0 := t0 - t2
	t0.Mul(&t0, &z3)   // t0 := t0 * Z3
	y3.Add(&y3, &t0)   // Y3 := Y3 + t0
	t0.Mul(&p.y, &p.z) // t0 := Y * Z
	t0.Add(&t0, &t0)   // t0 := t0 + t0
	z3.Mul(&t0, &z3)   // Z3 := t0 * Z3
	x3.Sub(&x3, &z3)   // X3 := X3 - Z3
	z3.Mul(&t0, &t1)   // Z3 := t0 * t1
	z3.Add(&z3, &z3)   // Z3 := Z3 + Z3
	z3.Add(&z3, &z3)   // Z3 := Z3 + Z3

	q.x.Set(&x3)
	q.y.Set(&y3)
	q.z.Set(&z3)
	return q
}

// Negate sets p = -p.  In projective form, negation flips the sign
// of Y (leaving X and Z unchanged).
func (p *janosP256Point) Negate() *janosP256Point {
	var negY janosP256Element
	negY.Sub(&negY, &p.y)
	p.y.Set(&negY)
	return p
}

// ScalarMult sets p = k * base, where k is a 32-byte big-endian
// scalar and base is any P-256 point (including the generator).
// Uses variable-time left-to-right double-and-add.  Both operands
// may alias.
//
// This is not constant-time — but ECDSA verify only takes public
// inputs (signature, digest, public key), so timing side channels
// are not a concern.
func (p *janosP256Point) ScalarMult(base *janosP256Point, k []byte) (*janosP256Point, bool) {
	if len(k) != 32 {
		return nil, false
	}
	// Copy base into a local so aliasing with p is safe.
	var b janosP256Point
	b.Set(base)

	var result janosP256Point
	result.SetInfinity()

	// Iterate bits MSB → LSB across the 32-byte big-endian scalar.
	for i := 0; i < 32; i++ {
		byteVal := k[i]
		for bit := 7; bit >= 0; bit-- {
			result.Double(&result)
			if (byteVal>>bit)&1 == 1 {
				result.Add(&result, &b)
			}
		}
	}
	p.Set(&result)
	return p, true
}

// ScalarBaseMult sets p = k * G.  Convenience wrapper over
// ScalarMult(G, k).
func (p *janosP256Point) ScalarBaseMult(k []byte) (*janosP256Point, bool) {
	var g janosP256Point
	g.SetGenerator()
	return p.ScalarMult(&g, k)
}

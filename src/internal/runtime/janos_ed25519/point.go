// Copyright (c) 2017 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from crypto/internal/fips140/edwards25519/edwards25519.go.
// Differences from upstream:
//   - Package name is janos_ed25519 and all field.Element references
//     become plain Element (they live in the same package).
//   - SetBytes returns (*Point, bool) rather than (*Point, error);
//     errors sits above internal/runtime.

package janos_ed25519

// projP1xP1 is an Edwards point in "P1xP1" completed coordinates
// (X, Y, Z, T) as used by the extended coordinate addition formulas.
type projP1xP1 struct{ X, Y, Z, T Element }

// projP2 is an Edwards point in projective coordinates (X, Y, Z).
type projP2 struct{ X, Y, Z Element }

// Point represents a point on the edwards25519 curve.  The zero value
// is NOT valid; construct via NewIdentityPoint, NewGeneratorPoint, or
// SetBytes.  All arguments and receivers may alias.
type Point struct {
	// Extended coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, and
	// xy = T/Z, per https://eprint.iacr.org/2008/522.
	_          incomparable
	x, y, z, t Element
}

// incomparable makes Point unusable with == or as a map key —
// equivalent points can have different Go values.
type incomparable [0]func()

func checkInitialized(points ...*Point) {
	for _, p := range points {
		if p.x == (Element{}) && p.y == (Element{}) {
			panic("janos_ed25519: use of uninitialized Point")
		}
	}
}

// projCached and affineCached are precomputed lookup-table forms of a
// Point that skip the final Z inversion.
type projCached struct{ YplusX, YminusX, Z, T2d Element }
type affineCached struct{ YplusX, YminusX, T2d Element }

// -- Constructors -------------------------------------------------

func (v *projP2) Zero() *projP2 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

// identity is the point at infinity.
var identity = mustPoint([32]byte{
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
})

// generator is the canonical curve basepoint (RFC 8032).
var generator = mustPoint([32]byte{
	0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
})

// mustPoint decodes b into a Point at package init.  Panics if b is
// not a valid encoding, which for identity/generator would indicate
// a bug in the port itself.
func mustPoint(b [32]byte) *Point {
	p := new(Point)
	if _, ok := p.SetBytes(b[:]); !ok {
		panic("janos_ed25519: internal constant is not a valid point encoding")
	}
	return p
}

// NewIdentityPoint returns a new Point set to the identity.
func NewIdentityPoint() *Point { return new(Point).Set(identity) }

// NewGeneratorPoint returns a new Point set to the canonical generator.
func NewGeneratorPoint() *Point { return new(Point).Set(generator) }

func (v *projCached) Zero() *projCached {
	v.YplusX.One()
	v.YminusX.One()
	v.Z.One()
	v.T2d.Zero()
	return v
}

func (v *affineCached) Zero() *affineCached {
	v.YplusX.One()
	v.YminusX.One()
	v.T2d.Zero()
	return v
}

// -- Assignments --------------------------------------------------

// Set sets v = u and returns v.
func (v *Point) Set(u *Point) *Point { *v = *u; return v }

// -- Encoding -----------------------------------------------------

// Bytes returns the canonical 32-byte encoding of v (RFC 8032 §5.1.2).
func (v *Point) Bytes() [32]byte {
	checkInitialized(v)
	var out [32]byte
	var zInv, x, y Element
	zInv.Invert(&v.z)
	x.Multiply(&v.x, &zInv)
	y.Multiply(&v.y, &zInv)
	out = y.Bytes()
	out[31] |= byte(x.IsNegative() << 7)
	return out
}

// SetBytes sets v = x, where x is a 32-byte encoding of v.  Returns
// (*Point, true) on success; (nil, false) if x is not a valid encoding.
//
// Accepts all non-canonical encodings of valid points, matching most
// implementations in the ecosystem rather than strict RFC 8032 rules.
// See https://hdevalence.ca/blog/2020-10-04-its-25519am (canonical A, R).
func (v *Point) SetBytes(x []byte) (*Point, bool) {
	y := new(Element)
	if _, ok := y.SetBytes(x); !ok {
		return nil, false
	}

	// Curve equation: -x² + y² = 1 + dx²y², so x² = (y² - 1) / (dy² + 1).
	y2 := new(Element).Square(y)
	u := new(Element).Subtract(y2, feOne)  // u = y² - 1
	vv := new(Element).Multiply(y2, d)      // v = dy² + 1
	vv = vv.Add(vv, feOne)

	xx, wasSquare := new(Element).SqrtRatio(u, vv)
	if wasSquare == 0 {
		return nil, false
	}

	// Pick the negative root if the sign bit is set.
	xxNeg := new(Element).Negate(xx)
	xx = xx.Select(xxNeg, xx, int(x[31]>>7))

	v.x.Set(xx)
	v.y.Set(y)
	v.z.One()
	v.t.Multiply(xx, y) // xy = T/Z
	return v, true
}

// -- Conversions --------------------------------------------------

func (v *projP2) FromP1xP1(p *projP1xP1) *projP2 {
	v.X.Multiply(&p.X, &p.T)
	v.Y.Multiply(&p.Y, &p.Z)
	v.Z.Multiply(&p.Z, &p.T)
	return v
}

func (v *projP2) FromP3(p *Point) *projP2 {
	v.X.Set(&p.x)
	v.Y.Set(&p.y)
	v.Z.Set(&p.z)
	return v
}

func (v *Point) fromP1xP1(p *projP1xP1) *Point {
	v.x.Multiply(&p.X, &p.T)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Multiply(&p.Z, &p.T)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

func (v *Point) fromP2(p *projP2) *Point {
	v.x.Multiply(&p.X, &p.Z)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Square(&p.Z)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

// d is a constant in the curve equation.
var d = mustElement([32]byte{
	0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
	0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
	0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
	0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
})
var d2 = new(Element).Add(d, d)

// mustElement decodes a 32-byte little-endian encoding at package init.
func mustElement(b [32]byte) *Element {
	e := new(Element)
	if _, ok := e.SetBytes(b[:]); !ok {
		panic("janos_ed25519: internal constant is not a valid field element")
	}
	return e
}

func (v *projCached) FromP3(p *Point) *projCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.Z.Set(&p.z)
	v.T2d.Multiply(&p.t, d2)
	return v
}

func (v *affineCached) FromP3(p *Point) *affineCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.T2d.Multiply(&p.t, d2)

	var invZ Element
	invZ.Invert(&p.z)
	v.YplusX.Multiply(&v.YplusX, &invZ)
	v.YminusX.Multiply(&v.YminusX, &invZ)
	v.T2d.Multiply(&v.T2d, &invZ)
	return v
}

// -- (Re)addition and subtraction ---------------------------------

// Add sets v = p + q and returns v.
func (v *Point) Add(p, q *Point) *Point {
	checkInitialized(p, q)
	qCached := new(projCached).FromP3(q)
	result := new(projP1xP1).Add(p, qCached)
	return v.fromP1xP1(result)
}

// Subtract sets v = p - q and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	checkInitialized(p, q)
	qCached := new(projCached).FromP3(q)
	result := new(projP1xP1).Sub(p, qCached)
	return v.fromP1xP1(result)
}

func (v *projP1xP1) Add(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 Element
	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)
	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&ZZ2, &TT2d)
	v.T.Subtract(&ZZ2, &TT2d)
	return v
}

func (v *projP1xP1) Sub(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 Element
	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped
	MM.Multiply(&YminusX, &q.YplusX) // flipped
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)
	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&ZZ2, &TT2d) // flipped
	v.T.Add(&ZZ2, &TT2d)      // flipped
	return v
}

func (v *projP1xP1) AddAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 Element
	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)
	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&Z2, &TT2d)
	v.T.Subtract(&Z2, &TT2d)
	return v
}

func (v *projP1xP1) SubAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 Element
	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped
	MM.Multiply(&YminusX, &q.YplusX) // flipped
	TT2d.Multiply(&p.t, &q.T2d)
	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&Z2, &TT2d) // flipped
	v.T.Add(&Z2, &TT2d)      // flipped
	return v
}

// -- Doubling -----------------------------------------------------

func (v *projP1xP1) Double(p *projP2) *projP1xP1 {
	var XX, YY, ZZ2, XplusYsq Element
	XX.Square(&p.X)
	YY.Square(&p.Y)
	ZZ2.Square(&p.Z)
	ZZ2.Add(&ZZ2, &ZZ2)
	XplusYsq.Add(&p.X, &p.Y)
	XplusYsq.Square(&XplusYsq)

	v.Y.Add(&YY, &XX)
	v.Z.Subtract(&YY, &XX)
	v.X.Subtract(&XplusYsq, &v.Y)
	v.T.Subtract(&ZZ2, &v.Z)
	return v
}

// -- Negation -----------------------------------------------------

// Negate sets v = -p and returns v.
func (v *Point) Negate(p *Point) *Point {
	checkInitialized(p)
	v.x.Negate(&p.x)
	v.y.Set(&p.y)
	v.z.Set(&p.z)
	v.t.Negate(&p.t)
	return v
}

// Equal returns 1 if v is equivalent to u (as projective points) and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	checkInitialized(v, u)
	var t1, t2, t3, t4 Element
	t1.Multiply(&v.x, &u.z)
	t2.Multiply(&u.x, &v.z)
	t3.Multiply(&v.y, &u.z)
	t4.Multiply(&u.y, &v.z)
	return t1.Equal(&t2) & t3.Equal(&t4)
}

// -- Constant-time operations -------------------------------------

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *projCached) Select(a, b *projCached, cond int) *projCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.Z.Select(&a.Z, &b.Z, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *affineCached) Select(a, b *affineCached, cond int) *affineCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1.
func (v *projCached) CondNeg(cond int) *projCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.Select(new(Element).Negate(&v.T2d), &v.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1.
func (v *affineCached) CondNeg(cond int) *affineCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.Select(new(Element).Negate(&v.T2d), &v.T2d, cond)
	return v
}

// Copyright (c) 2019 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from crypto/internal/fips140/edwards25519/scalarmult.go.
// Change from upstream: sync.Once is replaced with a CAS-based
// spinlock guarded by internal/runtime/atomic, because package sync
// transitively imports runtime and this package sits below runtime
// in the import graph.

package janos_ed25519

import "internal/runtime/atomic"

// -- Basepoint table (32 affine lookup tables) --------------------
//
// State machine:
//   0 -> not yet computed
//   1 -> a goroutine is computing it
//   2 -> ready
//
// First goroutine to CAS 0->1 wins the init role; others spin until 2.

var basepointTableState atomic.Uint32
var basepointTableStorage [32]affineLookupTable

func basepointTable() *[32]affineLookupTable {
	for {
		s := basepointTableState.Load()
		if s == 2 {
			return &basepointTableStorage
		}
		if s == 0 && basepointTableState.CompareAndSwap(0, 1) {
			// We won — populate the table.
			p := NewGeneratorPoint()
			for i := 0; i < 32; i++ {
				basepointTableStorage[i].FromP3(p)
				for j := 0; j < 8; j++ {
					p.Add(p, p)
				}
			}
			basepointTableState.Store(2)
			return &basepointTableStorage
		}
		// s == 1: another goroutine is initializing.  Spin.
	}
}

// -- Basepoint NAF-8 table ---------------------------------------

var basepointNafTableState atomic.Uint32
var basepointNafTableStorage nafLookupTable8

func basepointNafTable() *nafLookupTable8 {
	for {
		s := basepointNafTableState.Load()
		if s == 2 {
			return &basepointNafTableStorage
		}
		if s == 0 && basepointNafTableState.CompareAndSwap(0, 1) {
			basepointNafTableStorage.FromP3(NewGeneratorPoint())
			basepointNafTableState.Store(2)
			return &basepointNafTableStorage
		}
	}
}

// ScalarBaseMult sets v = x * B, where B is the canonical generator,
// and returns v.  Constant-time.
func (v *Point) ScalarBaseMult(x *Scalar) *Point {
	bpt := basepointTable()

	// Write x = sum(x_i * 16^i), split even and odd, use lookup
	// tables to compute x_i*16^(2i)*B and four doublings for the ×16.
	digits := x.signedRadix16()

	multiple := &affineCached{}
	tmp1 := &projP1xP1{}
	tmp2 := &projP2{}

	// Odd components first.
	v.Set(NewIdentityPoint())
	for i := 1; i < 64; i += 2 {
		bpt[i/2].SelectInto(multiple, digits[i])
		tmp1.AddAffine(v, multiple)
		v.fromP1xP1(tmp1)
	}

	// Multiply by 16.
	tmp2.FromP3(v)
	tmp1.Double(tmp2)
	tmp2.FromP1xP1(tmp1)
	tmp1.Double(tmp2)
	tmp2.FromP1xP1(tmp1)
	tmp1.Double(tmp2)
	tmp2.FromP1xP1(tmp1)
	tmp1.Double(tmp2)
	v.fromP1xP1(tmp1)

	// Even components.
	for i := 0; i < 64; i += 2 {
		bpt[i/2].SelectInto(multiple, digits[i])
		tmp1.AddAffine(v, multiple)
		v.fromP1xP1(tmp1)
	}

	return v
}

// ScalarMult sets v = x * q and returns v.  Constant-time.
func (v *Point) ScalarMult(x *Scalar, q *Point) *Point {
	checkInitialized(q)

	var table projLookupTable
	table.FromP3(q)

	digits := x.signedRadix16()

	multiple := &projCached{}
	tmp1 := &projP1xP1{}
	tmp2 := &projP2{}
	table.SelectInto(multiple, digits[63])

	v.Set(NewIdentityPoint())
	tmp1.Add(v, multiple)
	for i := 62; i >= 0; i-- {
		tmp2.FromP1xP1(tmp1)
		tmp1.Double(tmp2)
		tmp2.FromP1xP1(tmp1)
		tmp1.Double(tmp2)
		tmp2.FromP1xP1(tmp1)
		tmp1.Double(tmp2)
		tmp2.FromP1xP1(tmp1)
		tmp1.Double(tmp2)
		v.fromP1xP1(tmp1)
		table.SelectInto(multiple, digits[i])
		tmp1.Add(v, multiple)
	}
	v.fromP1xP1(tmp1)
	return v
}

// VarTimeDoubleScalarBaseMult sets v = a*A + b*B where B is the
// canonical generator, and returns v.  Not constant-time — execution
// time depends on the inputs.  This is the primitive used by Ed25519
// signature verification.
func (v *Point) VarTimeDoubleScalarBaseMult(a *Scalar, A *Point, b *Scalar) *Point {
	checkInitialized(A)

	bpt := basepointNafTable()
	var aTable nafLookupTable5
	aTable.FromP3(A)

	aNaf := a.nonAdjacentForm(5)
	bNaf := b.nonAdjacentForm(8)

	// First nonzero coefficient.
	i := 255
	for j := i; j >= 0; j-- {
		if aNaf[j] != 0 || bNaf[j] != 0 {
			break
		}
	}

	multA := &projCached{}
	multB := &affineCached{}
	tmp1 := &projP1xP1{}
	tmp2 := &projP2{}
	tmp2.Zero()

	// Sweep high to low, doubling then adding.
	for ; i >= 0; i-- {
		tmp1.Double(tmp2)

		if aNaf[i] > 0 {
			v.fromP1xP1(tmp1)
			aTable.SelectInto(multA, aNaf[i])
			tmp1.Add(v, multA)
		} else if aNaf[i] < 0 {
			v.fromP1xP1(tmp1)
			aTable.SelectInto(multA, -aNaf[i])
			tmp1.Sub(v, multA)
		}

		if bNaf[i] > 0 {
			v.fromP1xP1(tmp1)
			bpt.SelectInto(multB, bNaf[i])
			tmp1.AddAffine(v, multB)
		} else if bNaf[i] < 0 {
			v.fromP1xP1(tmp1)
			bpt.SelectInto(multB, -bNaf[i])
			tmp1.SubAffine(v, multB)
		}

		tmp2.FromP1xP1(tmp1)
	}

	v.fromP2(tmp2)
	return v
}

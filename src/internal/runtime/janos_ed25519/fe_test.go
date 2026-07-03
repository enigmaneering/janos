// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package janos_ed25519

import (
	"testing"
)

// TestFieldIdentity verifies the multiplicative and additive identities.
func TestFieldIdentity(t *testing.T) {
	var one, zero, x, r Element
	one.One()
	zero.Zero()
	// Arbitrary nonzero element; must be canonical (< 2^255-19).
	x.l0 = 0x0123456789abc
	x.l1 = 0x0fedcba987654
	x.l2 = 0x0111111111111
	x.l3 = 0x0222222222222
	x.l4 = 0x0333333333333

	r.Multiply(&x, &one)
	if r.Equal(&x) != 1 {
		t.Errorf("x * 1 != x\nx = %+v\nr = %+v", x, r)
	}
	r.Add(&x, &zero)
	if r.Equal(&x) != 1 {
		t.Errorf("x + 0 != x")
	}
}

// TestFieldInvertRoundTrip verifies x * Invert(x) == 1 for several
// nonzero elements.
func TestFieldInvertRoundTrip(t *testing.T) {
	xs := []Element{
		{1, 0, 0, 0, 0},
		{2, 0, 0, 0, 0},
		{0x123, 0x456, 0x789, 0xabc, 0xdef},
		{0x0FFFFFFFFFFFF, 0x0FFFFFFFFFFFF, 0x0FFFFFFFFFFFF, 0x0FFFFFFFFFFFF, 0x0FFFFFFFFFFFF},
	}
	var one Element
	one.One()
	for i, x := range xs {
		var inv, prod Element
		inv.Invert(&x)
		prod.Multiply(&x, &inv)
		if prod.Equal(&one) != 1 {
			t.Errorf("case %d: x * (1/x) != 1", i)
		}
	}
}

// TestFieldSquareEqMul verifies x^2 == x*x.
func TestFieldSquareEqMul(t *testing.T) {
	xs := []Element{
		{1, 0, 0, 0, 0},
		{2, 3, 5, 7, 11},
		{0x123456789abcd, 0xfedcba9876543, 0x111111111, 0x2222222, 0x3333},
	}
	for i, x := range xs {
		var sq, prod Element
		sq.Square(&x)
		prod.Multiply(&x, &x)
		if sq.Equal(&prod) != 1 {
			t.Errorf("case %d: x^2 != x*x", i)
		}
	}
}

// TestFieldBytesRoundTrip verifies SetBytes(Bytes(x)) == x for a
// range of canonical elements.
func TestFieldBytesRoundTrip(t *testing.T) {
	xs := []Element{
		{0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0},
		{0x123456789abcd, 0xfedcba9876543, 0x111111111, 0x2222222, 0x3333},
	}
	for i, x := range xs {
		buf := x.Bytes()
		var y Element
		if _, ok := y.SetBytes(buf[:]); !ok {
			t.Fatalf("case %d: SetBytes rejected valid input", i)
		}
		if y.Equal(&x) != 1 {
			t.Errorf("case %d: SetBytes(Bytes(x)) != x", i)
		}
	}
}

// TestFieldSubtractSelf verifies x - x == 0.
func TestFieldSubtractSelf(t *testing.T) {
	xs := []Element{
		{1, 0, 0, 0, 0},
		{0x123456, 0x789abc, 0xdef012, 0x345678, 0x9abcde},
	}
	var zero Element
	zero.Zero()
	for i, x := range xs {
		var r Element
		r.Subtract(&x, &x)
		if r.Equal(&zero) != 1 {
			t.Errorf("case %d: x - x != 0", i)
		}
	}
}

// TestFieldNegateTwice verifies -(-x) == x.
func TestFieldNegateTwice(t *testing.T) {
	x := Element{0x123456, 0x789abc, 0xdef012, 0x345678, 0x9abcde}
	var negX, negNegX Element
	negX.Negate(&x)
	negNegX.Negate(&negX)
	if negNegX.Equal(&x) != 1 {
		t.Errorf("-(-x) != x")
	}
}

// TestFieldSelect verifies Select's conditional branch.
func TestFieldSelect(t *testing.T) {
	a := Element{1, 2, 3, 4, 5}
	b := Element{10, 20, 30, 40, 50}
	var r Element

	r.Select(&a, &b, 1)
	if r.Equal(&a) != 1 {
		t.Errorf("Select(a,b,1) != a")
	}
	r.Select(&a, &b, 0)
	if r.Equal(&b) != 1 {
		t.Errorf("Select(a,b,0) != b")
	}
}

// TestFieldSwap verifies Swap's conditional swap.
func TestFieldSwap(t *testing.T) {
	origA := Element{1, 2, 3, 4, 5}
	origB := Element{10, 20, 30, 40, 50}

	a, b := origA, origB
	a.Swap(&b, 0)
	if a.Equal(&origA) != 1 || b.Equal(&origB) != 1 {
		t.Errorf("Swap cond=0 changed values")
	}

	a, b = origA, origB
	a.Swap(&b, 1)
	if a.Equal(&origB) != 1 || b.Equal(&origA) != 1 {
		t.Errorf("Swap cond=1 did not swap")
	}
}

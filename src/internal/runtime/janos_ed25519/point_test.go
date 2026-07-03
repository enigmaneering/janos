// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package janos_ed25519

import (
	"testing"
)

// TestPointIdentityAdd checks P + I == P for the generator.
func TestPointIdentityAdd(t *testing.T) {
	g := NewGeneratorPoint()
	id := NewIdentityPoint()
	var r Point
	r.Add(g, id)
	if r.Equal(g) != 1 {
		t.Fatal("G + Identity != G")
	}
}

// TestPointNegateAdd checks P + (-P) == Identity.
func TestPointNegateAdd(t *testing.T) {
	g := NewGeneratorPoint()
	var negG, sum Point
	negG.Negate(g)
	sum.Add(g, &negG)
	id := NewIdentityPoint()
	if sum.Equal(id) != 1 {
		t.Fatal("G + (-G) != Identity")
	}
}

// TestPointSubtractSelf checks P - P == Identity.
func TestPointSubtractSelf(t *testing.T) {
	g := NewGeneratorPoint()
	var r Point
	r.Subtract(g, g)
	id := NewIdentityPoint()
	if r.Equal(id) != 1 {
		t.Fatal("G - G != Identity")
	}
}

// TestPointBytesRoundTrip checks SetBytes(Bytes(G)) == G.
func TestPointBytesRoundTrip(t *testing.T) {
	g := NewGeneratorPoint()
	buf := g.Bytes()
	var p Point
	if _, ok := p.SetBytes(buf[:]); !ok {
		t.Fatal("SetBytes(Bytes(G)) rejected")
	}
	if p.Equal(g) != 1 {
		t.Fatal("SetBytes(Bytes(G)) != G")
	}
}

// TestPointGeneratorEncoding verifies that the RFC 8032 basepoint
// encoding matches what NewGeneratorPoint().Bytes() produces.
func TestPointGeneratorEncoding(t *testing.T) {
	g := NewGeneratorPoint()
	want := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}
	got := g.Bytes()
	if got != want {
		t.Errorf("Generator encoding mismatch\nwant %x\ngot  %x", want, got)
	}
}

// TestPointRejectInvalidBytes checks SetBytes rejects encodings
// whose y-coordinate is a valid field element but has no
// corresponding curve point.
func TestPointRejectInvalidBytes(t *testing.T) {
	// y = 2 is a valid field element but not on the curve for either sign.
	buf := [32]byte{0x02}
	var p Point
	if _, ok := p.SetBytes(buf[:]); ok {
		t.Error("SetBytes accepted y=2 encoding (not on curve)")
	}
}

// TestPointAddCommutative checks G + H == H + G for two distinct
// points (G and its double).
func TestPointAddCommutative(t *testing.T) {
	g := NewGeneratorPoint()
	// 2G via projP1xP1 doubling round-trip
	var h Point
	{
		var p2 projP2
		p2.FromP3(g)
		var p1xp1 projP1xP1
		p1xp1.Double(&p2)
		h.fromP1xP1(&p1xp1)
	}
	var gh, hg Point
	gh.Add(g, &h)
	hg.Add(&h, g)
	if gh.Equal(&hg) != 1 {
		t.Fatal("G + 2G != 2G + G")
	}
}

// Copyright (c) 2016 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from crypto/internal/fips140/edwards25519/scalar.go.
// Differences from upstream:
//   - Package name is janos_ed25519.
//   - Imports crypto/internal/fips140deps/byteorder replaced with the
//     leaf internal/byteorder.
//   - SetUniformBytes / SetCanonicalBytes / SetBytesWithClamping
//     return bool instead of error (errors package sits above
//     internal/runtime).
//   - Bytes returns [32]byte for stack friendliness.

package janos_ed25519

import (
	"internal/byteorder"
	"math/bits"
)

// A Scalar is an integer modulo
//
//	l = 2^252 + 27742317777372353535851937790883648493
//
// the prime order of the edwards25519 group.  Works similarly to
// math/big.Int; all arguments and receivers may alias.
//
// The zero value is a valid zero element.
type Scalar struct {
	// s is the scalar in the Montgomery domain, in the fiat-crypto layout.
	s fiatScalarMontgomeryDomainFieldElement
}

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar { return &Scalar{} }

// MultiplyAdd sets s = x*y + z mod l and returns s.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	zCopy := new(Scalar).Set(z)
	return s.Multiply(x, y).Add(s, zCopy)
}

// Add sets s = x + y mod l and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	fiatScalarAdd(&s.s, &x.s, &y.s)
	return s
}

// Subtract sets s = x - y mod l and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	fiatScalarSub(&s.s, &x.s, &y.s)
	return s
}

// Negate sets s = -x mod l and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	fiatScalarOpp(&s.s, &x.s)
	return s
}

// Multiply sets s = x * y mod l and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	fiatScalarMul(&s.s, &x.s, &y.s)
	return s
}

// Set sets s = x and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar { *s = *x; return s }

// SetUniformBytes sets s = x mod l, where x is a 64-byte little-endian
// integer.  Returns (s, true) on success or (nil, false) if x is the
// wrong length.  Suitable for reducing 64 uniformly-random bytes into
// a uniform scalar.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, bool) {
	if len(x) != 64 {
		return nil, false
	}
	// x has 512 bits; fiatScalarFromBytes wants a value below l
	// (~252 bits).  Split x into three shorter values a, b, c and
	// use x = a + b*2^168 + c*2^336 mod l with two multiplies and
	// two adds against precomputed constants.
	s.setShortBytes(x[:21])
	t := new(Scalar).setShortBytes(x[21:42])
	s.Add(s, t.Multiply(t, scalarTwo168))
	t.setShortBytes(x[42:])
	s.Add(s, t.Multiply(t, scalarTwo336))
	return s, true
}

// scalarTwo168 and scalarTwo336 are 2^168 and 2^336 modulo l, encoded
// in the fiat Montgomery layout (little-endian 4-limb).
var scalarTwo168 = &Scalar{s: [4]uint64{
	0x5b8ab432eac74798, 0x38afddd6de59d5d7,
	0xa2c131b399411b7c, 0x6329a7ed9ce5a30,
}}
var scalarTwo336 = &Scalar{s: [4]uint64{
	0xbd3d108e2b35ecc5, 0x5c3a3718bdf9c90b,
	0x63aa97a331b4f2ee, 0x3d217f5be65cb5c,
}}

// setShortBytes sets s = x mod l, where x is a little-endian integer
// shorter than 32 bytes.
func (s *Scalar) setShortBytes(x []byte) *Scalar {
	if len(x) >= 32 {
		panic("janos_ed25519: setShortBytes called with a long string")
	}
	var buf [32]byte
	copy(buf[:], x)
	fiatScalarFromBytes((*[4]uint64)(&s.s), &buf)
	fiatScalarToMontgomery(&s.s, (*fiatScalarNonMontgomeryDomainFieldElement)(&s.s))
	return s
}

// SetCanonicalBytes sets s = x, where x is a 32-byte little-endian
// canonical encoding of s.  Returns (s, true) on success or
// (nil, false) if x is not canonical.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, bool) {
	if len(x) != 32 {
		return nil, false
	}
	if !isReduced(x) {
		return nil, false
	}
	fiatScalarFromBytes((*[4]uint64)(&s.s), (*[32]byte)(x))
	fiatScalarToMontgomery(&s.s, (*fiatScalarNonMontgomeryDomainFieldElement)(&s.s))
	return s, true
}

// scalarMinusOneBytes is l - 1 in little endian.
var scalarMinusOneBytes = [32]byte{
	236, 211, 245, 92, 26, 99, 18, 88,
	214, 156, 247, 162, 222, 249, 222, 20,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 16,
}

// isReduced returns whether the given 32-byte little-endian encoding
// is < l.
func isReduced(s []byte) bool {
	if len(s) != 32 {
		return false
	}
	s0 := byteorder.LEUint64(s[:8])
	s1 := byteorder.LEUint64(s[8:16])
	s2 := byteorder.LEUint64(s[16:24])
	s3 := byteorder.LEUint64(s[24:])

	l0 := byteorder.LEUint64(scalarMinusOneBytes[:8])
	l1 := byteorder.LEUint64(scalarMinusOneBytes[8:16])
	l2 := byteorder.LEUint64(scalarMinusOneBytes[16:24])
	l3 := byteorder.LEUint64(scalarMinusOneBytes[24:])

	// Constant-time (l-1) - s.  If there's a borrow, s > l-1.
	_, b := bits.Sub64(l0, s0, 0)
	_, b = bits.Sub64(l1, s1, b)
	_, b = bits.Sub64(l2, s2, b)
	_, b = bits.Sub64(l3, s3, b)
	return b == 0
}

// SetBytesWithClamping applies the RFC 8032 §5.1.5 clamping and sets
// s to the result.  Input must be 32 bytes; input buffer is not
// modified.  Returns (s, true) on success or (nil, false) on
// wrong-length input.
//
// Clamping's cofactor-clearing properties are lost by the mod-l
// reduction, but the resulting value still works as expected on
// prime-order subgroups (as in Ed25519).
func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, bool) {
	if len(x) != 32 {
		return nil, false
	}
	var wide [64]byte
	copy(wide[:], x)
	wide[0] &= 248
	wide[31] &= 63
	wide[31] |= 64
	return s.SetUniformBytes(wide[:])
}

// Bytes returns the canonical 32-byte little-endian encoding of s.
func (s *Scalar) Bytes() [32]byte {
	var out [32]byte
	var ss fiatScalarNonMontgomeryDomainFieldElement
	fiatScalarFromMontgomery(&ss, &s.s)
	fiatScalarToBytes(&out, (*[4]uint64)(&ss))
	return out
}

// Equal returns 1 if s == t and 0 otherwise, in constant time.
func (s *Scalar) Equal(t *Scalar) int {
	var diff fiatScalarMontgomeryDomainFieldElement
	fiatScalarSub(&diff, &s.s, &t.s)
	var nonzero uint64
	fiatScalarNonzero(&nonzero, (*[4]uint64)(&diff))
	nonzero |= nonzero >> 32
	nonzero |= nonzero >> 16
	nonzero |= nonzero >> 8
	nonzero |= nonzero >> 4
	nonzero |= nonzero >> 2
	nonzero |= nonzero >> 1
	return int(^nonzero) & 1
}

// nonAdjacentForm computes a width-w NAF of this scalar.  w must be
// between 2 and 8.  Adapted from curve25519-dalek's scalar.rs.
func (s *Scalar) nonAdjacentForm(w uint) [256]int8 {
	b := s.Bytes()
	if b[31] > 127 {
		panic("janos_ed25519: scalar has high bit set illegally")
	}
	if w < 2 {
		panic("janos_ed25519: NAF width must be at least 2")
	} else if w > 8 {
		panic("janos_ed25519: NAF digits must fit in int8")
	}

	var naf [256]int8
	var digits [5]uint64
	for i := 0; i < 4; i++ {
		digits[i] = byteorder.LEUint64(b[i*8:])
	}

	width := uint64(1 << w)
	windowMask := width - 1

	pos := uint(0)
	carry := uint64(0)
	for pos < 256 {
		indexU64 := pos / 64
		indexBit := pos % 64
		var bitBuf uint64
		if indexBit < 64-w {
			bitBuf = digits[indexU64] >> indexBit
		} else {
			bitBuf = (digits[indexU64] >> indexBit) | (digits[1+indexU64] << (64 - indexBit))
		}
		window := carry + (bitBuf & windowMask)
		if window&1 == 0 {
			pos += 1
			continue
		}
		if window < width/2 {
			carry = 0
			naf[pos] = int8(window)
		} else {
			carry = 1
			naf[pos] = int8(window) - int8(width)
		}
		pos += w
	}
	return naf
}

// signedRadix16 returns 64 signed radix-16 digits recentered onto
// [-8, 8).  Used by the constant-time basepoint scalar mul.
func (s *Scalar) signedRadix16() [64]int8 {
	b := s.Bytes()
	if b[31] > 127 {
		panic("janos_ed25519: scalar has high bit set illegally")
	}
	var digits [64]int8
	for i := 0; i < 32; i++ {
		digits[2*i] = int8(b[i] & 15)
		digits[2*i+1] = int8((b[i] >> 4) & 15)
	}
	for i := 0; i < 63; i++ {
		carry := (digits[i] + 8) >> 4
		digits[i] -= carry << 4
		digits[i+1] += carry
	}
	return digits
}

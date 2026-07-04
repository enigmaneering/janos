// Copyright 2021 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// JanOS: P-256 field element wrapper.
//
// Provides a Go-friendly Element type over the fiat-crypto Montgomery
// primitives in janos_p256_fiat.go.  Ported from
// crypto/internal/fips140/nistec/fiat/p256.go; the runtime cannot
// import crypto/internal/fips140/subtle (sits far above runtime), so
// the constant-time comparison in Equal/IsZero is inlined.
//
// Returns [32]byte by value (not []byte) to keep the runtime's
// escape analysis happy — heap allocation from within runtime is
// forbidden.
//
// Used for schedinit ECDSA verification of the JANOSCRT slot's
// Release entry (see janos_ecdsa_p256_verify.go).

package runtime

// janosP256Element is an integer modulo p₂₅₆ = 2^256 - 2^224 + 2^192 + 2^96 - 1.
// The zero value is a valid zero element.  Values are held in the
// Montgomery domain internally and converted at Bytes / SetBytes
// boundaries.
type janosP256Element struct {
	x p256MontgomeryDomainFieldElement
}

const janosP256ElementLen = 32

type janosP256UntypedFieldElement = [4]uint64

// One sets e = 1 and returns e.
func (e *janosP256Element) One() *janosP256Element {
	p256SetOne(&e.x)
	return e
}

// Equal returns 1 if e == t and 0 otherwise, in constant time.
func (e *janosP256Element) Equal(t *janosP256Element) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	var diff byte
	for i := range eBytes {
		diff |= eBytes[i] ^ tBytes[i]
	}
	diff |= diff >> 4
	diff |= diff >> 2
	diff |= diff >> 1
	return int((diff & 1) ^ 1)
}

// IsZero returns 1 if e == 0 and 0 otherwise.
func (e *janosP256Element) IsZero() int {
	eBytes := e.Bytes()
	var v byte
	for _, b := range eBytes {
		v |= b
	}
	v |= v >> 4
	v |= v >> 2
	v |= v >> 1
	return int((v & 1) ^ 1)
}

// Set sets e = t and returns e.
func (e *janosP256Element) Set(t *janosP256Element) *janosP256Element {
	e.x = t.x
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *janosP256Element) Bytes() [janosP256ElementLen]byte {
	var out [janosP256ElementLen]byte
	var tmp p256NonMontgomeryDomainFieldElement
	p256FromMontgomery(&tmp, &e.x)
	p256ToBytes(&out, (*janosP256UntypedFieldElement)(&tmp))
	janosP256InvertEndianness(out[:])
	return out
}

// p256MinusOneBytesBE is the big-endian encoding of p₂₅₆ − 1, the
// highest canonical value that fits in the field.  SetBytes uses it
// to reject non-canonical encodings without needing a runtime
// allocation of a temporary Element.
var p256MinusOneBytesBE = [janosP256ElementLen]byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
}

// SetBytes sets e = v, where v is a 32-byte big-endian encoding.
// Returns (e, true) on success; (nil, false) if v is not 32 bytes
// or encodes a value >= p₂₅₆.
func (e *janosP256Element) SetBytes(v []byte) (*janosP256Element, bool) {
	if len(v) != janosP256ElementLen {
		return nil, false
	}
	// Reject non-canonical encodings by comparing to p₂₅₆ − 1.
	if !janosP256LessOrEqBytes32(v, p256MinusOneBytesBE) {
		return nil, false
	}

	var in [janosP256ElementLen]byte
	copy(in[:], v)
	janosP256InvertEndianness(in[:])
	var tmp p256NonMontgomeryDomainFieldElement
	p256FromBytes((*janosP256UntypedFieldElement)(&tmp), &in)
	p256ToMontgomery(&e.x, &tmp)
	return e, true
}

// Add sets e = t1 + t2 and returns e.
func (e *janosP256Element) Add(t1, t2 *janosP256Element) *janosP256Element {
	p256Add(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2 and returns e.
func (e *janosP256Element) Sub(t1, t2 *janosP256Element) *janosP256Element {
	p256Sub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2 and returns e.
func (e *janosP256Element) Mul(t1, t2 *janosP256Element) *janosP256Element {
	p256Mul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t and returns e.
func (e *janosP256Element) Square(t *janosP256Element) *janosP256Element {
	p256Square(&e.x, &t.x)
	return e
}

// Select sets v = a if cond == 1 and v = b if cond == 0.
func (v *janosP256Element) Select(a, b *janosP256Element, cond int) *janosP256Element {
	p256Selectznz((*janosP256UntypedFieldElement)(&v.x), p256Uint1(cond),
		(*janosP256UntypedFieldElement)(&b.x), (*janosP256UntypedFieldElement)(&a.x))
	return v
}

// janosP256InvertEndianness reverses the bytes of v in place.
func janosP256InvertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}

// janosP256LessOrEqBytes32 returns true iff a <= b (both interpreted
// as 32-byte big-endian unsigned integers).  Constant-time walk from
// most-significant byte down; the first differing byte position
// determines the result, which we accumulate branch-free.  b is a
// value ([32]byte) to keep allocation-free semantics for runtime.
func janosP256LessOrEqBytes32(a []byte, b [janosP256ElementLen]byte) bool {
	if len(a) != janosP256ElementLen {
		return false
	}
	var lt, gt byte
	for i := 0; i < janosP256ElementLen; i++ {
		var lessThis, greaterThis byte
		if a[i] < b[i] {
			lessThis = 1
		}
		if a[i] > b[i] {
			greaterThis = 1
		}
		decided := lt | gt
		lt |= lessThis &^ decided
		gt |= greaterThis &^ decided
	}
	return gt == 0
}

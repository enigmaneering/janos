// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// JanOS: ECDSA P-256 signature verification.
//
// Wire-format contract for the JANOSCRT slot:
//   - pubkey   : 64 bytes, uncompressed X || Y (no leading 0x04)
//   - digest   : 32 bytes, SHA-256 of the message
//   - signature: 64 bytes, r || s (each 32 bytes big-endian)
//
// This is the pure-Go verify used at schedinit time.  It only takes
// public inputs (pubkey, digest, sig), so timing side-channels are
// not a concern — variable-time double-and-add is fine.

package runtime

// janosP256VerifyASN1Bytes reports whether the signature (r||s) is a
// valid ECDSA signature of the given digest under the public key.
//
// Verify follows FIPS 186-4 §6.4.2:
//
//	1. Check r, s ∈ [1, n-1].
//	2. w  = s^-1 mod n
//	3. u1 = e * w mod n
//	4. u2 = r * w mod n
//	5. R  = u1*G + u2*Q ; reject if R = O
//	6. v  = R.x mod n
//	7. Accept iff v == r.
func janosP256VerifyRS(pubkey *[64]byte, digest *[32]byte, sig *[64]byte) bool {
	// Parse and validate r, s ∈ [1, n-1].  SetBytesBE silently reduces
	// mod n on the way in, so a value equal to n would come out as 0
	// — that gets rejected by the IsZero check.  The n case, plus
	// values >= 2*n, are also caught: the >= n subtraction inside
	// SetBytesBE would bring them into [0, n).
	var r, s janosP256Scalar
	if _, ok := r.SetBytesBE(sig[:32]); !ok {
		return false
	}
	if _, ok := s.SetBytesBE(sig[32:]); !ok {
		return false
	}
	if r.IsZero() || s.IsZero() {
		return false
	}

	// The raw r, s bytes must also be < n (SEC1: strict range check).
	// SetBytesBE already reduces, so an input == n would map to 0
	// (caught above) and inputs > n would remap to non-canonical
	// forms.  We also need to reject inputs >= n that were partially
	// reduced.  Compare raw bytes to n once more to be safe.
	if !janosP256ScalarBytesLessThanN(sig[:32]) || !janosP256ScalarBytesLessThanN(sig[32:]) {
		return false
	}

	// Parse the public key and check it lies on the curve.
	var q janosP256Point
	if _, ok := q.SetUncompressedBytes(pubkey[:]); !ok {
		return false
	}

	// Digest as a scalar mod n.  SHA-256 output is exactly 256 bits,
	// so we reduce it mod n (as FIPS 186-4 §6.4 requires: e =
	// leftmost min(N, outlen) bits of hash, reduced mod n).
	var e janosP256Scalar
	if _, ok := e.SetBytesBE(digest[:]); !ok {
		return false
	}

	// w = s^-1 mod n
	var w janosP256Scalar
	w.Invert(&s)

	// u1 = e * w, u2 = r * w (both mod n)
	var u1, u2 janosP256Scalar
	u1.Mul(&e, &w)
	u2.Mul(&r, &w)

	// R = u1*G + u2*Q via two ScalarMults and one Add.  If R is
	// infinity, reject.
	var u1G, u2Q, r0 janosP256Point
	u1Bytes := u1.Bytes()
	u2Bytes := u2.Bytes()
	if _, ok := u1G.ScalarBaseMult(u1Bytes[:]); !ok {
		return false
	}
	if _, ok := u2Q.ScalarMult(&q, u2Bytes[:]); !ok {
		return false
	}
	r0.Add(&u1G, &u2Q)
	if r0.IsInfinity() {
		return false
	}

	// v = R.x mod n.  R.x is a field element (mod p), so we take its
	// bytes and reduce mod n — SetBytesBE does that inside.
	rxBytes, ok := r0.AffineX()
	if !ok {
		return false
	}
	var v janosP256Scalar
	if _, ok := v.SetBytesBE(rxBytes[:]); !ok {
		return false
	}

	// v == r?  Compare in Montgomery domain — Bytes converts out.
	vBytes := v.Bytes()
	rBytes := r.Bytes()
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= vBytes[i] ^ rBytes[i]
	}
	return diff == 0
}

// janosP256ScalarBytesLessThanN reports whether the 32-byte big-
// endian value is strictly less than the P-256 curve order n.
// Big-endian byte-wise walk, short-circuiting on the first differing
// byte.
func janosP256ScalarBytesLessThanN(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	nBytes := [32]byte{
		0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
		0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
	}
	for i := 0; i < 32; i++ {
		if b[i] < nBytes[i] {
			return true
		}
		if b[i] > nBytes[i] {
			return false
		}
	}
	// Equal to n: not strictly less than.
	return false
}

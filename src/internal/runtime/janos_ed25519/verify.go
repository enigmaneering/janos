// Copyright (c) 2016 The Go Authors. All rights reserved.
// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ed25519 signature verification (RFC 8032, pure variant).
//
// Ported from crypto/internal/fips140/ed25519.  Only the pure
// (Ed25519, non-context) verification path is included; JanOS does
// not need Ed25519ph or Ed25519ctx at this layer.

package janos_ed25519

import "internal/runtime/janos_hash"

// PublicKeySize is the size of an Ed25519 public key in bytes.
const PublicKeySize = 32

// SignatureSize is the size of an Ed25519 signature in bytes.
const SignatureSize = 64

// Verify reports whether sig is a valid Ed25519 signature over message
// by pub, per RFC 8032 §5.1.7.  Wrong-length arguments return false.
//
// This is a variable-time implementation; do not use it in code paths
// where timing side-channels matter for the signing key.  For our
// purposes (verifying a signature over a public binary) that is fine.
func Verify(pub []byte, message, sig []byte) bool {
	if len(pub) != PublicKeySize {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	// RFC 8032 §5.1.7 step 1: reject signatures whose top three bits are set.
	if sig[63]&0b11100000 != 0 {
		return false
	}

	// Decode public key A as a curve point.
	A := new(Point)
	if _, ok := A.SetBytes(pub); !ok {
		return false
	}

	// Decode S (second half of signature) as a scalar.
	S := new(Scalar)
	if _, ok := S.SetCanonicalBytes(sig[32:]); !ok {
		return false
	}

	// Compute k = SHA-512(R || A || M) reduced mod l.
	var kh janos_hash.SHA512
	kh.Reset()
	kh.Write(sig[:32])
	kh.Write(pub)
	kh.Write(message)
	digest := kh.Sum()
	k, ok := new(Scalar).SetUniformBytes(digest[:])
	if !ok {
		return false
	}

	// Verification identity: [S]B = R + [k]A, rearranged as
	// R = [k](-A) + [S]B, then compare against sig[:32].
	minusA := new(Point).Negate(A)
	R := new(Point).VarTimeDoubleScalarBaseMult(k, minusA, S)
	rBytes := R.Bytes()

	// Constant-time byte compare of the first 32 bytes.  (This function
	// is variable-time overall anyway — see doc comment — but the byte
	// compare has no reason to fall out of constant time.)
	var diff byte
	for i := 0; i < 32; i++ {
		diff |= sig[i] ^ rBytes[i]
	}
	return diff == 0
}

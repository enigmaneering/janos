// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// Test-only Ed25519 signing.  Production JanOS signs via KMS, never
// with locally-held private keys — this file is only compiled when
// `go test -tags janos_signtest` is run, so nothing here reaches
// production binaries.  Tests that need to exercise the verifier
// against fresh signatures use SignForTest to produce them; the
// runtime cert-slot tests (janos_cert_test.go) also depend on it.

package janos_ed25519

import "internal/runtime/janos_hash"

// SignForTest signs message using a private key derived from seed,
// following RFC 8032 §5.1.5 (key derivation) + §5.1.6 (signing).
// Returns (public key, signature).  Callers verify with Verify.
func SignForTest(seed [32]byte, message []byte) (pub [32]byte, sig [64]byte) {
	// h = SHA-512(seed); low 32 bytes -> clamped signing scalar,
	// high 32 -> prefix used in R nonce derivation.
	var h janos_hash.SHA512
	h.Reset()
	h.Write(seed[:])
	digest := h.Sum()

	var seedBits [32]byte
	copy(seedBits[:], digest[:32])
	var prefix [32]byte
	copy(prefix[:], digest[32:])

	s, ok := new(Scalar).SetBytesWithClamping(seedBits[:])
	if !ok {
		panic("SignForTest: SetBytesWithClamping failed")
	}

	A := new(Point).ScalarBaseMult(s)
	pub = A.Bytes()

	// r = SHA-512(prefix || message), reduced mod l.
	var rh janos_hash.SHA512
	rh.Reset()
	rh.Write(prefix[:])
	rh.Write(message)
	rhDigest := rh.Sum()
	r, ok := new(Scalar).SetUniformBytes(rhDigest[:])
	if !ok {
		panic("SignForTest: r reduction failed")
	}

	// R = r * B
	R := new(Point).ScalarBaseMult(r)
	rBytes := R.Bytes()

	// k = SHA-512(R || A || message), reduced mod l.
	var kh janos_hash.SHA512
	kh.Reset()
	kh.Write(rBytes[:])
	kh.Write(pub[:])
	kh.Write(message)
	kDigest := kh.Sum()
	k, ok := new(Scalar).SetUniformBytes(kDigest[:])
	if !ok {
		panic("SignForTest: k reduction failed")
	}

	// S = r + k*s mod l.
	S := new(Scalar).MultiplyAdd(k, s, r)
	sBytes := S.Bytes()

	copy(sig[:32], rBytes[:])
	copy(sig[32:], sBytes[:])
	return
}

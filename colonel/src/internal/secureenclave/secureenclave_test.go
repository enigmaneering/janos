// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secureenclave_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"internal/secureenclave"
	"math/big"
	"testing"
)

// pubKey builds a stdlib ecdsa.PublicKey from a Key's 64-byte point,
// failing the test if the point is not on P-256.
func pubKey(t *testing.T, k *secureenclave.Key) *ecdsa.PublicKey {
	t.Helper()
	pt, err := k.PublicPoint()
	if err != nil {
		t.Fatalf("PublicPoint: %v", err)
	}
	x := new(big.Int).SetBytes(pt[:32])
	y := new(big.Int).SetBytes(pt[32:])
	if !elliptic.P256().IsOnCurve(x, y) {
		t.Fatalf("public point is not on P-256: %x", pt)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

// TestSignVerifiesAgainstPublicPoint is the load-bearing proof: a
// signature the Secure Enclave produced with its in-enclave private
// key verifies against the public point it reported.  If the key
// weren't a real, self-consistent P-256 keypair, this would fail.
func TestSignVerifiesAgainstPublicPoint(t *testing.T) {
	if !secureenclave.Available() {
		t.Skip("no Secure Enclave on this host")
	}
	k, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer k.Close()

	pub := pubKey(t, k)
	digest := sha256.Sum256([]byte("janos secure enclave attestation"))
	sig, err := k.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature = %d bytes, want 64 (r||s)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatalf("enclave signature did not verify against its own public point")
	}

	// A different digest must NOT verify under the same signature.
	other := sha256.Sum256([]byte("different message"))
	if ecdsa.Verify(pub, other[:], r, s) {
		t.Fatalf("signature verified for the wrong digest")
	}
}

// TestDistinctKeys confirms two generated keys are independent.
func TestDistinctKeys(t *testing.T) {
	if !secureenclave.Available() {
		t.Skip("no Secure Enclave on this host")
	}
	a, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey a: %v", err)
	}
	defer a.Close()
	b, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey b: %v", err)
	}
	defer b.Close()

	ap, _ := a.PublicPoint()
	bp, _ := b.PublicPoint()
	if ap == bp {
		t.Fatalf("two generated keys share a public point")
	}
}

// TestECDHAgreement proves the enclave's ECDH is a real, correct
// scalar multiplication: A·pub(B) and B·pub(A) yield the same shared
// secret.
func TestECDHAgreement(t *testing.T) {
	if !secureenclave.Available() {
		t.Skip("no Secure Enclave on this host")
	}
	a, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey a: %v", err)
	}
	defer a.Close()
	b, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey b: %v", err)
	}
	defer b.Close()

	ap, _ := a.PublicPoint()
	bp, _ := b.PublicPoint()

	ab, err := a.ECDH(bp)
	if err != nil {
		t.Fatalf("a.ECDH(b): %v", err)
	}
	ba, err := b.ECDH(ap)
	if err != nil {
		t.Fatalf("b.ECDH(a): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("ECDH mismatch:\n  a·B = %x\n  b·A = %x", ab, ba)
	}
	if len(ab) != 32 {
		t.Errorf("ECDH shared secret = %d bytes, want 32", len(ab))
	}
	allZero := true
	for _, c := range ab {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("ECDH shared secret is all zeros")
	}
}

// TestClosedKeyErrors confirms a closed key's operations fail cleanly
// rather than crashing.
func TestClosedKeyErrors(t *testing.T) {
	if !secureenclave.Available() {
		t.Skip("no Secure Enclave on this host")
	}
	k, err := secureenclave.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k.Close()
	k.Close() // double close must be safe

	if _, err := k.PublicPoint(); err == nil {
		t.Errorf("PublicPoint on closed key did not error")
	}
	if _, err := k.Sign(make([]byte, 32)); err == nil {
		t.Errorf("Sign on closed key did not error")
	}
}

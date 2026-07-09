// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hwkey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"internal/hwkey"
	"math/big"
	"testing"
)

// TestProviderIdentityOps drives the whole identity-relevant surface
// through the common interface — whichever hardware root this host
// has (Secure Enclave on macOS, TPM on Linux/Windows).  It proves the
// abstraction is real: the same code mints a key, reads its public
// point, signs verifiably, and does ECDH, without knowing the backend.
func TestProviderIdentityOps(t *testing.T) {
	p, err := hwkey.Open()
	if errors.Is(err, hwkey.ErrUnavailable) {
		t.Skip("no hardware root of trust on this host")
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer p.Close()

	a, err := p.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey a: %v", err)
	}
	defer a.Close()
	b, err := p.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey b: %v", err)
	}
	defer b.Close()

	// Public points: valid, distinct P-256 points — an identity's
	// PublicPoint.
	ap, err := a.PublicPoint()
	if err != nil {
		t.Fatalf("PublicPoint a: %v", err)
	}
	bp, err := b.PublicPoint()
	if err != nil {
		t.Fatalf("PublicPoint b: %v", err)
	}
	if ap == bp {
		t.Fatalf("two keys share a public point")
	}
	ax := new(big.Int).SetBytes(ap[:32])
	ay := new(big.Int).SetBytes(ap[32:])
	if !elliptic.P256().IsOnCurve(ax, ay) {
		t.Fatalf("public point not on P-256")
	}

	// Sign — the attestation primitive.  Raw r||s, verifies against
	// the public point with the stdlib.
	digest := sha256.Sum256([]byte("janos hardware identity"))
	sig, err := a.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature = %d bytes, want 64 (r||s)", len(sig))
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: ax, Y: ay}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatalf("hardware signature did not verify against its public point")
	}

	// ECDH — the Derive primitive.  a·B == b·A.
	ab, err := a.ECDH(bp)
	if err != nil {
		t.Fatalf("a.ECDH(b): %v", err)
	}
	ba, err := b.ECDH(ap)
	if err != nil {
		t.Fatalf("b.ECDH(a): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("ECDH mismatch: a·B=%x b·A=%x", ab, ba)
	}
	if len(ab) != 32 {
		t.Errorf("ECDH shared secret = %d bytes, want 32", len(ab))
	}
	t.Logf("hardware identity ops verified through the common interface")
}

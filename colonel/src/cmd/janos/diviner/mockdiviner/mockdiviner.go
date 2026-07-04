// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// Package mockdiviner registers a test-only diviner backend under
// the mockdiviner:// scheme.  Only compiled with -tags janos_signtest.
//
// Purpose: give tests (and any downstream tests that need real
// ECDSA P-256 signatures during unit testing) a signer they can
// drive deterministically.  URL format: `mockdiviner://SEEDHEX`
// where SEEDHEX is up to 64 hex characters (right-padded with zeros
// so short labels like "guild" or "release" give distinct seeds).
// The seed deterministically derives a P-256 private key; each
// invocation of that URL returns the same public key.  Individual
// signatures use crypto/rand for k, so the signature bytes differ
// per call — the runtime verifier only cares that (r, s) satisfies
// the equation, not that they are stable.
//
// This package lives outside cmd/janos/diviner because cmd/janos/
// diviner is bootstrap-copied, and bootstrap forbids imports of
// crypto/*.  Living here keeps mockdiviner's crypto dependency out
// of the bootstrap scan.
//
// Tests that want the mockdiviner scheme available do:
//
//	import _ "cmd/janos/diviner/mockdiviner"
package mockdiviner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"cmd/janos/diviner"
)

// mockDiviner holds a P-256 keypair derived deterministically from
// the URL seed.  See newFromSeed for the derivation.
type mockDiviner struct {
	priv *ecdsa.PrivateKey
	pub  [64]byte
}

func (m *mockDiviner) PublicKey() ([64]byte, error) {
	return m.pub, nil
}

func (m *mockDiviner) Sign(digest [32]byte) ([64]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, m.priv, digest[:])
	if err != nil {
		return [64]byte{}, fmt.Errorf("mockdiviner Sign: %w", err)
	}
	var out [64]byte
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// Big-endian, left-padded to 32 bytes each.
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out, nil
}

// newFromSeed derives a deterministic P-256 private key from seed.
// d = SHA-256("mockdiviner-key:" || seed) mod n; if that is zero
// (astronomically unlikely) we clamp to 1.  Then Q = d*G.  The pub
// key is stored in raw X || Y form to match the Diviner interface.
func newFromSeed(seed [32]byte) *mockDiviner {
	// Domain-separate so we can add other deriveds later without
	// collisions.
	var dSeed [len("mockdiviner-key:") + 32]byte
	copy(dSeed[:len("mockdiviner-key:")], "mockdiviner-key:")
	copy(dSeed[len("mockdiviner-key:"):], seed[:])
	dHash := sha256.Sum256(dSeed[:])

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(dHash[:])
	d.Mod(d, curve.Params().N)
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	priv := &ecdsa.PrivateKey{}
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	m := &mockDiviner{priv: priv}
	// Pack X || Y left-padded to 32 bytes each.
	xBytes := priv.PublicKey.X.Bytes()
	yBytes := priv.PublicKey.Y.Bytes()
	copy(m.pub[32-len(xBytes):32], xBytes)
	copy(m.pub[64-len(yBytes):64], yBytes)
	return m
}

func open(url string) (diviner.Diviner, error) {
	const prefix = "mockdiviner://"
	if !strings.HasPrefix(url, prefix) {
		return nil, fmt.Errorf("mockdiviner: URL %q does not start with %q", url, prefix)
	}
	seedHex := url[len(prefix):]
	if len(seedHex) == 0 {
		return nil, fmt.Errorf("mockdiviner: URL %q is missing seed hex", url)
	}
	if len(seedHex) > 64 {
		return nil, fmt.Errorf("mockdiviner: seed hex too long (%d chars, max 64)", len(seedHex))
	}
	for len(seedHex) < 64 {
		seedHex += "0"
	}
	decoded, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("mockdiviner: bad seed hex %q: %w", seedHex, err)
	}
	var seed [32]byte
	copy(seed[:], decoded)
	return newFromSeed(seed), nil
}

func init() {
	diviner.Register("mockdiviner", open)
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

package mockdiviner_test

import (
	"testing"

	"cmd/janos/diviner"
	_ "cmd/janos/diviner/mockdiviner" // registers mockdiviner:// scheme

	"internal/runtime/janos_ed25519"
)

// TestMockDivinerRoundTrip: build a mock, sign a fixed digest,
// verify against the mock's reported public key.  Exercises the
// whole interface — Open, PublicKey, Sign — and confirms the output
// actually verifies under the real Ed25519 verifier.
func TestMockDivinerRoundTrip(t *testing.T) {
	d, err := diviner.Open("mockdiviner://67756c6c") // "gull" hex
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pk, err := d.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pk == ([32]byte{}) {
		t.Fatal("PublicKey returned zero")
	}

	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i * 3)
	}
	sig, err := d.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !janos_ed25519.Verify(pk[:], digest[:], sig[:]) {
		t.Fatal("mock diviner produced a signature the verifier rejects")
	}

	digest[0] ^= 1
	if janos_ed25519.Verify(pk[:], digest[:], sig[:]) {
		t.Error("verifier accepted mismatched digest")
	}
}

// TestMockDivinerDistinctSeeds: distinct URLs must yield distinct
// public keys.  Confirms seed derivation doesn't collapse labels.
func TestMockDivinerDistinctSeeds(t *testing.T) {
	a, err := diviner.Open("mockdiviner://67756c6c") // "gull"
	if err != nil {
		t.Fatal(err)
	}
	b, err := diviner.Open("mockdiviner://72656c65617365") // "release"
	if err != nil {
		t.Fatal(err)
	}
	pkA, _ := a.PublicKey()
	pkB, _ := b.PublicKey()
	if pkA == pkB {
		t.Fatal("distinct seeds produced the same public key")
	}
}

// TestMockDivinerRejectsMalformedURL: bad hex is a hard error.
func TestMockDivinerRejectsMalformedURL(t *testing.T) {
	_, err := diviner.Open("mockdiviner://ZZZZ")
	if err == nil {
		t.Fatal("Open accepted malformed hex seed")
	}
}

// TestMockDivinerRejectsEmptySeed: empty URL after prefix -> error.
func TestMockDivinerRejectsEmptySeed(t *testing.T) {
	_, err := diviner.Open("mockdiviner://")
	if err == nil {
		t.Fatal("Open accepted empty seed")
	}
}

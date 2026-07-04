//go:build janos_signtest

package mockdiviner_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"cmd/janos/diviner"
	_ "cmd/janos/diviner/mockdiviner" // registers mockdiviner:// scheme
)

// TestMockDivinerRoundTrip: build a mock, sign a fixed digest,
// verify against the mock's reported public key.  Exercises the
// whole interface — Open, PublicKey, Sign — and confirms the output
// actually verifies under stdlib crypto/ecdsa.
func TestMockDivinerRoundTrip(t *testing.T) {
	d, err := diviner.Open("mockdiviner://67756c6c") // "gull" hex
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pk, err := d.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pk == ([64]byte{}) {
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

	if !verifyP256(pk, digest, sig) {
		t.Fatal("mock diviner produced a signature the verifier rejects")
	}

	digest[0] ^= 1
	if verifyP256(pk, digest, sig) {
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

// TestMockDivinerStableAcrossOpens: opening the same URL twice must
// return the same public key.  If the derivation ever accidentally
// pulled from crypto/rand, this would flake.
func TestMockDivinerStableAcrossOpens(t *testing.T) {
	a, err := diviner.Open("mockdiviner://67756c6c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := diviner.Open("mockdiviner://67756c6c")
	if err != nil {
		t.Fatal(err)
	}
	pkA, _ := a.PublicKey()
	pkB, _ := b.PublicKey()
	if pkA != pkB {
		t.Fatalf("same seed produced different public keys:\n a: %x\n b: %x", pkA, pkB)
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

// verifyP256 unpacks the mock's raw X||Y pubkey into an
// *ecdsa.PublicKey and its r||s signature into big.Ints, then
// hands them to stdlib ecdsa.Verify.  A test-side helper — the
// mock's Sign only makes claims we can trust if we verify them
// against the real deal.
func verifyP256(pkRaw [64]byte, digest [32]byte, sig [64]byte) bool {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pkRaw[:32]),
		Y:     new(big.Int).SetBytes(pkRaw[32:]),
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

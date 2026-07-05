package runtime_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"runtime"
	"testing"

	"cmd/janos/certslot"
)

// TestJanosVerifyChainSlotHappyPath synthesizes a JANOSCRT slot using
// stdlib crypto/ecdsa (which is what a real divined build's diviner
// backend produces byte-for-byte), then feeds the slot to the
// runtime's own janosVerifyChainSlot.  Exercises the full chain
// verify without needing to rebuild the toolchain or boot a divined
// binary.
//
// A green run means: the runtime's cert-chain verifier will accept
// any correctly-constructed slot produced by any compliant diviner
// backend (GCP KMS, AWS KMS, mockdiviner — all the same math).
func TestJanosVerifyChainSlotHappyPath(t *testing.T) {
	guild := mustNewKeypair(t)
	release := mustNewKeypair(t)

	var binaryHash [32]byte
	for i := range binaryHash {
		binaryHash[i] = byte(i*3 + 7)
	}

	// Guild signs SHA-256(release.pubkey).
	releasePKDigest := sha256.Sum256(release.pubKey[:])
	parentCert := signRS(t, guild.priv, releasePKDigest[:])

	// Release signs the binary hash.
	releaseSig := signRS(t, release.priv, binaryHash[:])

	slot := certslot.EncodeSlot([]certslot.Certificate{
		{
			Level:        certslot.LevelGuild,
			RevokeEpoch:  1,
			SignerPubKey: guild.pubKey,
			// Guild has no parent_cert; empty.
			// Guild has no Signature over binaryHash — Guild does
			// not endorse the binary directly.
		},
		{
			Level:        certslot.LevelRelease,
			RevokeEpoch:  1,
			SignerPubKey: release.pubKey,
			ParentCert:   parentCert,
			Signature:    releaseSig,
		},
	})

	if !runtime.VerifyChainSlotForTest(slot[:], binaryHash, &guild.pubKey, &release.pubKey) {
		t.Fatal("verify chain rejected a well-formed synthetic slot")
	}
}

func TestJanosVerifyChainSlotRejectsWrongGuild(t *testing.T) {
	guild := mustNewKeypair(t)
	release := mustNewKeypair(t)
	imposterGuild := mustNewKeypair(t)

	var binaryHash [32]byte
	for i := range binaryHash {
		binaryHash[i] = byte(i)
	}

	releasePKDigest := sha256.Sum256(release.pubKey[:])
	parentCert := signRS(t, guild.priv, releasePKDigest[:])
	releaseSig := signRS(t, release.priv, binaryHash[:])

	slot := certslot.EncodeSlot([]certslot.Certificate{
		{Level: certslot.LevelGuild, RevokeEpoch: 1, SignerPubKey: guild.pubKey},
		{Level: certslot.LevelRelease, RevokeEpoch: 1,
			SignerPubKey: release.pubKey, ParentCert: parentCert, Signature: releaseSig},
	})

	// Pass an unrelated Guild pubkey as the "expected" key — verify
	// must reject.
	if runtime.VerifyChainSlotForTest(slot[:], binaryHash, &imposterGuild.pubKey, &release.pubKey) {
		t.Fatal("verify chain accepted a slot with a mismatched expected Guild pubkey")
	}
}

func TestJanosVerifyChainSlotRejectsTamperedBinaryHash(t *testing.T) {
	guild := mustNewKeypair(t)
	release := mustNewKeypair(t)

	var binaryHash [32]byte
	for i := range binaryHash {
		binaryHash[i] = byte(i)
	}

	releasePKDigest := sha256.Sum256(release.pubKey[:])
	parentCert := signRS(t, guild.priv, releasePKDigest[:])
	releaseSig := signRS(t, release.priv, binaryHash[:])

	slot := certslot.EncodeSlot([]certslot.Certificate{
		{Level: certslot.LevelGuild, RevokeEpoch: 1, SignerPubKey: guild.pubKey},
		{Level: certslot.LevelRelease, RevokeEpoch: 1,
			SignerPubKey: release.pubKey, ParentCert: parentCert, Signature: releaseSig},
	})

	// Present a tampered binary hash — release's signature no longer
	// verifies against it.
	tampered := binaryHash
	tampered[0] ^= 0xFF
	if runtime.VerifyChainSlotForTest(slot[:], tampered, &guild.pubKey, &release.pubKey) {
		t.Fatal("verify chain accepted a slot with a tampered binary hash")
	}
}

func TestJanosVerifyChainSlotRejectsSwappedParentCert(t *testing.T) {
	guild := mustNewKeypair(t)
	release := mustNewKeypair(t)
	imposterRelease := mustNewKeypair(t)

	var binaryHash [32]byte
	for i := range binaryHash {
		binaryHash[i] = byte(i + 5)
	}

	// Guild signs the WRONG release pubkey's digest — meant to
	// simulate someone swapping the parent_cert to a different
	// release's certificate.  Then legitimate release signs the
	// binary.  The verifier should catch that parent_cert doesn't
	// match release.SignerPubKey.
	wrongParentDigest := sha256.Sum256(imposterRelease.pubKey[:])
	wrongParentCert := signRS(t, guild.priv, wrongParentDigest[:])
	releaseSig := signRS(t, release.priv, binaryHash[:])

	slot := certslot.EncodeSlot([]certslot.Certificate{
		{Level: certslot.LevelGuild, RevokeEpoch: 1, SignerPubKey: guild.pubKey},
		{Level: certslot.LevelRelease, RevokeEpoch: 1,
			SignerPubKey: release.pubKey,
			ParentCert:   wrongParentCert,
			Signature:    releaseSig},
	})

	if runtime.VerifyChainSlotForTest(slot[:], binaryHash, &guild.pubKey, &release.pubKey) {
		t.Fatal("verify chain accepted a slot with a parent_cert bound to the wrong release pubkey")
	}
}

func TestJanosVerifyChainSlotRejectsMissingMagic(t *testing.T) {
	// Empty (all-zero) slot — no JANOSCRT magic — must be rejected.
	var slot [certslot.SlotSize]byte
	var binaryHash [32]byte
	var pk [64]byte
	if runtime.VerifyChainSlotForTest(slot[:], binaryHash, &pk, &pk) {
		t.Fatal("verify chain accepted an all-zero slot (missing JANOSCRT magic)")
	}
}

// -----------------------------------------------------------------
// Helpers — real stdlib ECDSA P-256, matching the byte layout the
// runtime verifier expects.
// -----------------------------------------------------------------

type keypair struct {
	priv   *ecdsa.PrivateKey
	pubKey [64]byte // X‖Y, 32 bytes each big-endian
}

func mustNewKeypair(t *testing.T) *keypair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var pub [64]byte
	xBytes := priv.PublicKey.X.Bytes()
	yBytes := priv.PublicKey.Y.Bytes()
	copy(pub[32-len(xBytes):32], xBytes)
	copy(pub[64-len(yBytes):64], yBytes)
	return &keypair{priv: priv, pubKey: pub}
}

// signRS signs digest with priv and returns the r‖s (each 32 bytes
// big-endian) form the runtime verifier expects.
func signRS(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) [64]byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var out [64]byte
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out
}


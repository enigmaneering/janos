// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

package janos_cert

import (
	"internal/runtime/janos_ed25519"
	"testing"
)

var (
	guildSeed = [32]byte{0x67, 0x75, 0x69, 0x6c, 0x64} // "guild"
	binHash   = [32]byte{
		0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
		0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
		0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
		0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,
	}
)

// certEntry produces a Certificate for a signer at the given level,
// signing binHash with signerSeed, and (if hasParent) attaching a
// parent-cert produced by parentSeed over signerPub.
func certEntry(t *testing.T, level uint8, signerSeed, parentSeed [32]byte, hasParent bool) Certificate {
	t.Helper()
	signerPub, sigOverBin := janos_ed25519.SignForTest(signerSeed, binHash[:])
	var parentCert [64]byte
	if hasParent {
		_, parentSig := janos_ed25519.SignForTest(parentSeed, signerPub[:])
		parentCert = parentSig
	}
	return Certificate{
		Level:        level,
		SignerPubKey: signerPub,
		ParentCert:   parentCert,
		Signature:    sigOverBin,
	}
}

// guildPub returns the public key that would derive from guildSeed.
func guildPub() [32]byte {
	pub, _ := janos_ed25519.SignForTest(guildSeed, nil)
	return pub
}

// TestCertSlotHappyPathGuildOnly: guild-only slot fails because
// the current runtime policy requires a release entry too.
func TestCertSlotHappyPathGuildOnly(t *testing.T) {
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	slot := EncodeSlot([]Certificate{guild})
	_, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, [32]byte{})
	if ok {
		t.Error("guild-only slot verified — should have required release entry")
	}
}

// TestCertSlotHappyPathGuildRelease: guild + release verifies.
func TestCertSlotHappyPathGuildRelease(t *testing.T) {
	releaseSeed := [32]byte{0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})

	result, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey)
	if !ok {
		t.Fatal("valid guild+release slot rejected")
	}
	if !result.HasGuild || !result.HasRelease {
		t.Errorf("expected HasGuild && HasRelease, got %+v", result)
	}
	if result.HasUser {
		t.Errorf("expected HasUser=false, got true")
	}
}

// TestCertSlotFullChain: guild + release + user.
func TestCertSlotFullChain(t *testing.T) {
	releaseSeed := [32]byte{0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65}
	userSeed := [32]byte{0x75, 0x73, 0x65, 0x72}

	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	user := certEntry(t, LevelUser, userSeed, releaseSeed, true)
	slot := EncodeSlot([]Certificate{guild, release, user})

	result, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey)
	if !ok {
		t.Fatal("valid full chain rejected")
	}
	if !result.HasGuild || !result.HasRelease || !result.HasUser {
		t.Errorf("expected all three, got %+v", result)
	}
	if result.User.SignerPubKey != user.SignerPubKey {
		t.Errorf("User.SignerPubKey mismatch")
	}
}

// TestCertSlotWrongGuildKey: slot's Guild PK != runtime expectation.
func TestCertSlotWrongGuildKey(t *testing.T) {
	otherSeed := [32]byte{0x66, 0x61, 0x6b, 0x65}
	releaseSeed := [32]byte{0x72}

	guild := certEntry(t, LevelGuild, otherSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, otherSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})

	_, ok := VerifyChain(slot[:], binHash, guildPub(), release.SignerPubKey)
	if ok {
		t.Error("slot with wrong Guild PK verified")
	}
}

// TestCertSlotWrongReleaseKey: slot's Release PK != runtime expectation.
func TestCertSlotWrongReleaseKey(t *testing.T) {
	releaseSeed := [32]byte{0x72}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})

	_, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, [32]byte{0xff})
	if ok {
		t.Error("slot with wrong Release PK verified")
	}
}

// TestCertSlotTamperedSig: flipping a bit in Guild sig rejects.
func TestCertSlotTamperedSig(t *testing.T) {
	releaseSeed := [32]byte{0x72}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})
	// Guild sig starts at header (16) + 104 within its entry.
	slot[16+104] ^= 1
	_, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey)
	if ok {
		t.Error("slot with tampered Guild signature verified")
	}
}

// TestCertSlotUnauthorizedUser: user's parent_cert wasn't signed by
// release -> reject.
func TestCertSlotUnauthorizedUser(t *testing.T) {
	releaseSeed := [32]byte{0x72}
	userSeed := [32]byte{0x75}
	rogueSeed := [32]byte{0xde, 0xad}

	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	user := certEntry(t, LevelUser, userSeed, rogueSeed, true)
	slot := EncodeSlot([]Certificate{guild, release, user})

	_, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey)
	if ok {
		t.Error("slot with rogue-parented User cert verified")
	}
}

// TestCertSlotBadMagic: wrong magic -> reject.
func TestCertSlotBadMagic(t *testing.T) {
	releaseSeed := [32]byte{0x72}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})
	slot[0] = 'X'
	_, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey)
	if ok {
		t.Error("slot with bad magic verified")
	}
}

// TestCertSlotWrongBinaryHash: sigs valid over different hash than
// what we pass in -> reject.
func TestCertSlotWrongBinaryHash(t *testing.T) {
	releaseSeed := [32]byte{0x72}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})

	var other [32]byte
	for i := range other {
		other[i] = 0x77
	}
	_, ok := VerifyChain(slot[:], other, guild.SignerPubKey, release.SignerPubKey)
	if ok {
		t.Error("slot verified against wrong binary hash")
	}
}

// TestCertSlotRevokedRelease: a Release key on the revocation list
// causes VerifyChain to reject, even when all signatures are valid.
func TestCertSlotRevokedRelease(t *testing.T) {
	releaseSeed := [32]byte{0x72, 0xff}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	slot := EncodeSlot([]Certificate{guild, release})

	// Sanity: passes before revocation.
	if _, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey); !ok {
		t.Fatal("pre-revocation chain rejected")
	}

	// Add the Release signer to the revoke list.
	prev := SetRevokedReleasesForTest([]RevocationEntry{
		RevocationEntryForTest(release.SignerPubKey, WildcardEpochForTest),
	})
	defer SetRevokedReleasesForTest(prev)

	if _, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey); ok {
		t.Error("chain with revoked Release verified")
	}
}

// TestCertSlotRevokedReleaseSpecificEpoch: revocation targeting a
// specific epoch only affects entries with that epoch.
func TestCertSlotRevokedReleaseSpecificEpoch(t *testing.T) {
	releaseSeed := [32]byte{0x72, 0x02}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	release.RevokeEpoch = 5
	slot := EncodeSlot([]Certificate{guild, release})

	// Revoke a DIFFERENT epoch (7) — should still pass.
	prev := SetRevokedReleasesForTest([]RevocationEntry{
		RevocationEntryForTest(release.SignerPubKey, 7),
	})
	if _, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey); !ok {
		t.Error("chain with non-matching epoch revocation rejected")
	}

	// Revoke THIS epoch (5) — should fail.
	SetRevokedReleasesForTest([]RevocationEntry{
		RevocationEntryForTest(release.SignerPubKey, 5),
	})
	if _, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey); ok {
		t.Error("chain with matching epoch revocation verified")
	}
	SetRevokedReleasesForTest(prev)
}

// TestCertSlotRevokedUser: user cert revocation is enforced.
func TestCertSlotRevokedUser(t *testing.T) {
	releaseSeed := [32]byte{0x72, 0x03}
	userSeed := [32]byte{0x75, 0x03}
	guild := certEntry(t, LevelGuild, guildSeed, [32]byte{}, false)
	release := certEntry(t, LevelRelease, releaseSeed, guildSeed, true)
	user := certEntry(t, LevelUser, userSeed, releaseSeed, true)
	slot := EncodeSlot([]Certificate{guild, release, user})

	prev := SetRevokedUsersForTest([]RevocationEntry{
		RevocationEntryForTest(user.SignerPubKey, WildcardEpochForTest),
	})
	defer SetRevokedUsersForTest(prev)

	if _, ok := VerifyChain(slot[:], binHash, guild.SignerPubKey, release.SignerPubKey); ok {
		t.Error("chain with revoked User verified")
	}
}

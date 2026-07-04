// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: certificate slot format and chain-of-trust verification.
//
// Every JanOS binary carries a fixed-size "JANOSCRT" slot embedded
// by the linker's diviner pass.  The slot contains up to eight
// signature entries arranged as a chain of trust:
//
//    entry[0] Guild        — non-revocable, identifies the family
//                            line.  Runtime hardcodes the expected
//                            Guild public key.  Failure to match
//                            aborts the process at schedinit.
//    entry[1] Release      — per-release, signed by a Release
//                            key whose public key was in turn signed
//                            by the Guild (parent_cert).  The Release
//                            key expected by this runtime is
//                            hardcoded at build time.  Failure aborts.
//    entry[2] User         — Glitter's "signet".  Runtime does not
//                            enforce it, but surfaces it via
//                            provenance so Glitter programs can
//                            consume it for identification and
//                            disclosure-based execution decisions.
//    entry[3..7]           — reserved for future extension.
//
// The on-disk layout (constants, Certificate struct, slot encoder)
// lives in cmd/janos/certslot so it can be shared bootstrap-safely
// between the runtime and cmd/link's diviner pass.  This file holds
// the crypto-aware verification, revocation, and the runtime-facing
// re-exports.

package janos_cert

import (
	"cmd/janos/certslot"
	"internal/runtime/janos_ed25519"
	"internal/runtime/janos_hash"
)

// -- Re-exports from cmd/janos/certslot --------------------------

// Slot layout constants.
const (
	SlotSize    = certslot.SlotSize
	Magic       = certslot.Magic
	MagicSize   = certslot.MagicSize
	Version     = certslot.Version
	HeaderSize  = certslot.HeaderSize
	EntrySize   = certslot.EntrySize
	MaxEntries  = certslot.MaxEntries
	EntriesSize = certslot.EntriesSize
)

// Entry level codes.
const (
	LevelGuild   = certslot.LevelGuild
	LevelRelease = certslot.LevelRelease
	LevelUser    = certslot.LevelUser
	LevelEmpty   = certslot.LevelEmpty
)

// Certificate is a JANOSCRT slot entry.  Type alias so callers can
// pass values between janos_cert and cmd/janos/certslot without
// conversions.
type Certificate = certslot.Certificate

// EncodeSlot returns a slot with the given entries in order.
func EncodeSlot(entries []Certificate) [SlotSize]byte {
	return certslot.EncodeSlot(entries)
}

// -- Byte-level accessors ----------------------------------------

// entry describes one slot entry's byte offsets internally.
//
//	offset  size  field
//	   0     1    level
//	   1     3    revoke_epoch (little-endian)
//	   4     4    reserved
//	   8    32    signer_pk
//	  40    64    parent_cert
//	 104    64    sig_over_binary
type entry struct {
	level       uint8
	revokeEpoch uint32
	signerPK    [32]byte
	parentCert  [64]byte
	signature   [64]byte
}

// decodeEntry unpacks entry bytes from the slot at the given index.
func decodeEntry(slot []byte, idx int) (entry, bool) {
	if idx < 0 || idx >= MaxEntries {
		return entry{}, false
	}
	base := HeaderSize + idx*EntrySize
	if base+EntrySize > len(slot) {
		return entry{}, false
	}
	var e entry
	e.level = slot[base]
	e.revokeEpoch = uint32(slot[base+1]) | uint32(slot[base+2])<<8 | uint32(slot[base+3])<<16
	copy(e.signerPK[:], slot[base+8:base+40])
	copy(e.parentCert[:], slot[base+40:base+104])
	copy(e.signature[:], slot[base+104:base+168])
	return e, true
}

// checkSlotHeader verifies the magic + version at the start of the slot.
func checkSlotHeader(slot []byte) bool {
	if len(slot) < HeaderSize {
		return false
	}
	for i := 0; i < MagicSize; i++ {
		if slot[i] != Magic[i] {
			return false
		}
	}
	return slot[8] == Version
}

// -- Verification -------------------------------------------------

// VerifyResult reports which entries were successfully verified.
type VerifyResult struct {
	Guild   Certificate
	Release Certificate
	User    Certificate

	HasGuild, HasRelease, HasUser bool
}

// VerifyChain walks the entries in slot and validates the chain of
// trust.  Guild entry mandatory: SignerPubKey must equal
// expectGuildPK; the Guild does not sign individual binaries so its
// Signature field is not checked.  Release entry mandatory:
// SignerPubKey must equal expectReleasePK, ParentCert must verify as
// Guild's signature over Release's SignerPubKey, and Signature must
// verify as Release's signature over binaryHash.  Revocation is
// consulted for Release and User (if present).  User entry
// optional; when present, its ParentCert must be Release's signature
// over the User's SignerPubKey.
func VerifyChain(slot []byte, binaryHash [32]byte, expectGuildPK, expectReleasePK [32]byte) (VerifyResult, bool) {
	var res VerifyResult

	if !checkSlotHeader(slot) {
		return VerifyResult{}, false
	}

	// Entry 0: Guild.  Identity-only — Guild does not sign binaries.
	g, ok := decodeEntry(slot, 0)
	if !ok || g.level != LevelGuild {
		return VerifyResult{}, false
	}
	if g.signerPK != expectGuildPK {
		return VerifyResult{}, false
	}
	res.Guild = Certificate{
		Level:        g.level,
		RevokeEpoch:  g.revokeEpoch,
		SignerPubKey: g.signerPK,
		ParentCert:   g.parentCert,
		Signature:    g.signature,
	}
	res.HasGuild = true

	// Entry 1: Release.  Mandatory.  Guild-signed pubkey +
	// binary-signing sig.
	r, ok := decodeEntry(slot, 1)
	if !ok || r.level != LevelRelease {
		return VerifyResult{}, false
	}
	if r.signerPK != expectReleasePK {
		return VerifyResult{}, false
	}
	if !janos_ed25519.Verify(expectGuildPK[:], r.signerPK[:], r.parentCert[:]) {
		return VerifyResult{}, false
	}
	if !janos_ed25519.Verify(r.signerPK[:], binaryHash[:], r.signature[:]) {
		return VerifyResult{}, false
	}
	if isRevoked(revokedReleases, certIDFromPubKey(r.signerPK), r.revokeEpoch) {
		return VerifyResult{}, false
	}
	res.Release = Certificate{
		Level:        r.level,
		RevokeEpoch:  r.revokeEpoch,
		SignerPubKey: r.signerPK,
		ParentCert:   r.parentCert,
		Signature:    r.signature,
	}
	res.HasRelease = true

	// Entry 2: User.  Optional.  When present, must chain to Release.
	u, ok := decodeEntry(slot, 2)
	if ok && u.level == LevelUser {
		if !janos_ed25519.Verify(r.signerPK[:], u.signerPK[:], u.parentCert[:]) {
			return VerifyResult{}, false
		}
		if !janos_ed25519.Verify(u.signerPK[:], binaryHash[:], u.signature[:]) {
			return VerifyResult{}, false
		}
		if isRevoked(revokedUsers, certIDFromPubKey(u.signerPK), u.revokeEpoch) {
			return VerifyResult{}, false
		}
		res.User = Certificate{
			Level:        u.level,
			RevokeEpoch:  u.revokeEpoch,
			SignerPubKey: u.signerPK,
			ParentCert:   u.parentCert,
			Signature:    u.signature,
		}
		res.HasUser = true
	}

	return res, true
}

// certIDFromPubKey returns SHA-256 of a signer's public key, used as
// a compact stable identifier we can carry in Provenance.
func certIDFromPubKey(pk [32]byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(pk[:])
	return d.Sum()
}

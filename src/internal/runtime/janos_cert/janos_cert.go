// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: certificate slot format and chain-of-trust verification.
//
// Every JanOS binary carries a fixed-size "JANOSCRT" slot embedded
// by the linker.  The slot contains up to eight signature entries
// arranged as a chain of trust:
//
//    entry[0] Guild        — non-revocable, signed by the Enigmaneering
//                            Guild root key.  Runtime hardcodes the
//                            expected Guild public key.  Failure to
//                            match aborts the process at schedinit.
//    entry[1] Release      — per-release, signed by a Release key whose
//                            public key was in turn signed by the Guild
//                            (parent_cert).  The Release key expected by
//                            this runtime is hardcoded at build time.
//                            Failure aborts the process.
//    entry[2] User         — Glitter's "signet".  Runtime does not
//                            enforce it, but surfaces it via provenance
//                            so Glitter programs can consume it for
//                            identification and disclosure-based
//                            execution decisions.
//    entry[3..7]           — reserved for future extension.
//
// This file defines the on-disk layout and a pure verify function.
// The schedinit hookup (task #57) and the linker-emitted slot (task
// #49) come in follow-up work.

package janos_cert

import (
	"internal/runtime/janos_ed25519"
	"internal/runtime/janos_hash"
)

// -- Slot layout constants ---------------------------------------

const (
	SlotSize    = 2048       // total slot bytes (zeroed for hash)
	Magic       = "JANOSCRT" // first 8 bytes
	MagicSize   = 8
	Version     = 1
	HeaderSize  = 16 // magic (8) + ver (1) + entry_count (1) + reserved (6)
	EntrySize   = 168
	MaxEntries  = 8
	EntriesSize = EntrySize * MaxEntries // 1344
)

// Entry level codes.
const (
	LevelGuild   = 0
	LevelRelease = 1
	LevelUser    = 2
	LevelEmpty   = 0xFF
)

// -- Public certificate type -------------------------------------

// Certificate is the runtime-visible form of one JANOSCRT slot entry.
// GuildCert/ReleaseCert/UserCert accessors return values of this type.
type Certificate struct {
	// Level is one of TrustJanosGuild / TrustJanosRelease / TrustJanosUser
	// (mirrors the on-disk level byte).
	Level uint8
	// RevokeEpoch is the signer's per-key revocation serial.  Compared
	// against the runtime's baked-in revocation list.
	RevokeEpoch uint32
	// SignerPubKey is the Ed25519 public key that produced Signature.
	SignerPubKey [32]byte
	// ParentCert is the parent level's Ed25519 signature over
	// SignerPubKey.  Zero for Guild (no parent).
	ParentCert [64]byte
	// Signature is the Ed25519 signature over the binary's SHA-256
	// digest (computed with the cert slot region zeroed).
	Signature [64]byte
}

// -- Byte-level accessors ----------------------------------------

// entry describes one slot entry's byte offsets.
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
// Returns (entry, true) on success or (zero, false) if idx is out of
// range or the header magic/version is wrong.
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
// Missing entries return the zero value.
type VerifyResult struct {
	Guild   Certificate // valid if HasGuild
	Release Certificate // valid if HasRelease
	User    Certificate // valid if HasUser

	HasGuild, HasRelease, HasUser bool
}

// VerifyChain walks the entries in slot and validates the
// chain of trust: entry 0 must be Guild-signed with a public key that
// exactly equals expectGuildPK, entry 1 (if present) must be Release-
// signed and its public key must equal expectReleasePK AND its
// parent_cert must be a valid Guild signature over that public key,
// entry 2 (if present) is User-signed and its parent_cert must be a
// valid Release signature over the user's public key.
//
// binaryHash is SHA-256 of the binary with the slot region zeroed.
//
// Returns (result, true) if the chain of trust is intact.  Any
// failure — bad magic/version, wrong Guild PK, invalid sig, missing
// Guild entry — returns (zero, false).
func VerifyChain(slot []byte, binaryHash [32]byte, expectGuildPK, expectReleasePK [32]byte) (VerifyResult, bool) {
	var res VerifyResult

	if !checkSlotHeader(slot) {
		return VerifyResult{}, false
	}

	// Entry 0: Guild.  MANDATORY.
	g, ok := decodeEntry(slot, 0)
	if !ok || g.level != LevelGuild {
		return VerifyResult{}, false
	}
	if g.signerPK != expectGuildPK {
		return VerifyResult{}, false
	}
	if !janos_ed25519.Verify(g.signerPK[:], binaryHash[:], g.signature[:]) {
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

	// Entry 1: Release.  MANDATORY for now; empty slot means "not a
	// Guild-blessed release build" and verification fails.  (When
	// dev builds without a release cert are wanted, we relax this.)
	r, ok := decodeEntry(slot, 1)
	if !ok || r.level != LevelRelease {
		return VerifyResult{}, false
	}
	if r.signerPK != expectReleasePK {
		return VerifyResult{}, false
	}
	// Guild signed the Release public key.
	if !janos_ed25519.Verify(expectGuildPK[:], r.signerPK[:], r.parentCert[:]) {
		return VerifyResult{}, false
	}
	if !janos_ed25519.Verify(r.signerPK[:], binaryHash[:], r.signature[:]) {
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

	// Entry 2: User.  OPTIONAL.  If present, must chain to Release.
	u, ok := decodeEntry(slot, 2)
	if ok && u.level == LevelUser {
		// Release signed the user's public key.
		if !janos_ed25519.Verify(r.signerPK[:], u.signerPK[:], u.parentCert[:]) {
			// A malformed user cert is a hard failure — someone tried
			// to attach an unauthorized user sig.
			return VerifyResult{}, false
		}
		if !janos_ed25519.Verify(u.signerPK[:], binaryHash[:], u.signature[:]) {
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
	// Empty user entry is fine; that binary just isn't Glitter-signed.

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

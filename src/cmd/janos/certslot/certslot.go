// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package certslot defines the on-disk layout of the JANOSCRT slot
// and provides a bootstrap-safe encoder used by both the runtime and
// cmd/link's diviner pass.
//
// This package sits in cmd/janos/ rather than internal/runtime/
// because cmd/link is a bootstrap tool with restricted imports —
// internal/runtime/* is not on the bootstrap-copy allow list.  All
// the format-level knowledge (constants, Certificate struct, slot
// encoding) lives here so both sides of the wire compile against the
// same source of truth.  Verification (VerifyChain) stays over in
// internal/runtime/janos_cert because it depends on Ed25519, which
// belongs closer to the runtime.
package certslot

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

// Certificate is one JANOSCRT slot entry.  Layout must match the
// on-disk offsets — see EncodeSlot for the byte-level layout.
type Certificate struct {
	// Level is one of LevelGuild, LevelRelease, LevelUser (or
	// LevelEmpty for an entry the encoder should skip).
	Level uint8
	// RevokeEpoch is the signer's per-key revocation serial.
	RevokeEpoch uint32
	// SignerPubKey is the Ed25519 public key that produced Signature.
	SignerPubKey [32]byte
	// ParentCert is the parent level's Ed25519 signature over
	// SignerPubKey.  Zero for Guild (no parent).
	ParentCert [64]byte
	// Signature is the Ed25519 signature over the binary's SHA-256
	// digest (computed with the slot region zeroed).  Zero for
	// Guild — Guild's private key is offline and it endorses this
	// release only through the Release entry's ParentCert.
	Signature [64]byte
}

// EncodeSlot builds a well-formed [SlotSize]byte with the given
// entries in order.  Missing entry slots (indices past len(entries))
// get their level byte set to LevelEmpty (0xFF).
//
// The first eight bytes always spell Magic and the version byte at
// offset 8 is set to Version — that's what signals to a decoder that
// the slot has been divined.
func EncodeSlot(entries []Certificate) [SlotSize]byte {
	var slot [SlotSize]byte
	copy(slot[0:MagicSize], Magic)
	slot[8] = Version
	slot[9] = byte(len(entries))

	for i := 0; i < MaxEntries; i++ {
		base := HeaderSize + i*EntrySize
		slot[base] = LevelEmpty
	}
	for i, e := range entries {
		if i >= MaxEntries {
			break
		}
		base := HeaderSize + i*EntrySize
		slot[base] = e.Level
		slot[base+1] = byte(e.RevokeEpoch)
		slot[base+2] = byte(e.RevokeEpoch >> 8)
		slot[base+3] = byte(e.RevokeEpoch >> 16)
		copy(slot[base+8:base+40], e.SignerPubKey[:])
		copy(slot[base+40:base+104], e.ParentCert[:])
		copy(slot[base+104:base+168], e.Signature[:])
	}
	return slot
}

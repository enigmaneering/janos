// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build janos_signtest

// Test-only slot encoder.  Only compiled when tests run with
// -tags janos_signtest.  Production signing is a linker/tooling
// concern; this exists so verification tests can build a slot
// from a list of Certificates without a linker.

package janos_cert

// EncodeSlot builds a well-formed [SlotSize]byte with the given
// entries in-order.  Empty entries at any index (0xFF level byte)
// leave that slot's remaining bytes zero.
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

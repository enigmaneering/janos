// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: JANOSCRT slot storage.
//
// This file declares the fixed-size byte array that cmd/link's
// diviner pass patches with the Guild + Release + optional User
// certificate chain during the final build step.  At source time the
// slot is all-zero; after the diviner pass runs the first 8 bytes
// spell "JANOSCRT" and the remainder contains the encoded chain.
//
// The runtime discovers the slot at schedinit by reading
// janosCertSlotBytes directly (same package, no linkname needed).
// The diviner in cmd/link reaches it via its symbol name
// runtime.janosCertSlotBytes.

package runtime

// janosCertSlotStorageSize is the size of the JANOSCRT slot in bytes.
// Matches internal/runtime/janos_cert.SlotSize.  Duplicated here as a
// constant because the runtime cannot import janos_cert (that would
// create the same cycle that put janos_cert outside the runtime tree
// in the first place); if these ever diverge, tests will scream.
const janosCertSlotStorageSize = 2048

// janosCertSlotBytes is the 2 KiB block reserved for the JANOSCRT
// certificate chain.  Patched by cmd/link's diviner pass; on an
// undivined build the block is all-zero after the magic bytes and
// the version byte reads 0.
//
// Given an initializer so the array lands in .data (which is written
// to the file), not .bss (which is not).  The diviner pass patches
// bytes IN THE FILE, so a BSS location wouldn't work.  The initial
// magic "JANOSCRT" makes the presence of the slot visible in a hex
// dump even before the diviner runs; the version byte (offset 8) is
// 0 on undivined builds and gets bumped to janos_cert.Version by the
// diviner pass once the chain is populated.
//
// The variable's SYMBOL NAME (runtime.janosCertSlotBytes) is
// significant — the diviner pass looks it up by name.  Do not rename
// without updating cmd/link.
var janosCertSlotBytes = [janosCertSlotStorageSize]byte{
	'J', 'A', 'N', 'O', 'S', 'C', 'R', 'T', // magic (offsets 0..7)
	0x00, // version (offset 8) — 0 = undivined; diviner pass sets it
	// entry_count (offset 9), reserved (10..15), and 8 entry slots
	// (16..1359) all zero until the diviner runs.  Remaining reserved
	// tail (1360..2047) is left permanently zero for future extension.
}

// janosCertSlot returns the runtime's own JANOSCRT slot bytes.
// Empty (all-zero) on an undivined build; carries the chain of
// trust on a properly divined one.
//
//go:nosplit
func janosCertSlot() *[janosCertSlotStorageSize]byte {
	return &janosCertSlotBytes
}

// janosVerifyCertSlot runs at schedinit after the self-hash pass.
// On an undivined build the slot is all-zero and this function is a
// no-op.  On a divined build (once the diviner pass lands in cmd/link)
// it will verify the Guild+Release chain via internal/runtime/janos_cert
// and throw on failure.  Referencing janosCertSlotBytes here also
// keeps the symbol alive against dead-code elimination — the diviner
// pass in cmd/link needs the slot present in the binary to patch it.
//
// The runtime.KeepAlive-style read through a package-level function
// pointer prevents the compiler from const-folding the all-zero
// initial contents into a compile-time constant; the diviner pass in
// cmd/link may patch the bytes after the compiler has finished, and
// we need those reads to hit real memory.
//
//go:noinline
//go:nosplit
func janosVerifyCertSlot() {
	// The slot has "JANOSCRT" magic pre-baked (see initializer above),
	// so the version byte is what tells us whether the diviner has
	// populated the chain.  Indirected through janosSlotVersionByte
	// so the compiler cannot prove at compile time what value the
	// diviner will patch in.
	v := janosSlotVersionByte()
	if v == 0 {
		// Undivined binary — no chain to verify.  Boot continues.
		return
	}
	// TODO(task #57): compute SHA-256 of the running binary with the
	// slot region zeroed, then linkname over to
	// internal/runtime/janos_cert.VerifyChain, then throw on any
	// failure.
	_ = v
}

// janosSlotVersionByte returns the version byte of the JANOSCRT slot
// (offset 8, right after the "JANOSCRT" magic).  Indirected through
// this small no-inline function so the compiler cannot prove the
// value at compile time — the diviner pass patches the bytes AFTER
// the compiler is done, so runtime reads must go to real memory.
//
//go:noinline
//go:nosplit
func janosSlotVersionByte() byte {
	return janosCertSlotBytes[8]
}

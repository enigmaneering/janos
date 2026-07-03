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
// certificate chain.  Patched by cmd/link's diviner pass; all-zero
// on undivined builds (dev binaries produced before the diviner
// pass is invoked, or by a stock Go toolchain with no diviner
// configuration).
//
// The variable's SYMBOL NAME (runtime.janosCertSlotBytes) is
// significant — the diviner pass looks it up by name.  Do not rename
// without updating cmd/link.
var janosCertSlotBytes [janosCertSlotStorageSize]byte

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
	// Route the read through the atomic-load-style indirection below
	// so the compiler cannot prove the value is zero.
	m := janosSlotMagicByte()
	if m == 0 {
		// Undivined binary — nothing to check.
		return
	}
	// TODO(diviner-C, task #57): compute SHA-256 of the running
	// binary with the slot region zeroed, then linkname over to
	// internal/runtime/janos_cert.VerifyChain, then throw on any
	// failure.
	_ = m
}

// janosSlotMagicByte returns the first byte of the JANOSCRT slot.
// Indirected through this small function to defeat the compiler's
// "the array is provably all-zero" const-fold — the diviner pass
// patches the bytes AFTER the compiler is done, so runtime reads
// must go to real memory.
//
//go:noinline
//go:nosplit
func janosSlotMagicByte() byte {
	return janosCertSlotBytes[0]
}

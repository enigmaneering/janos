// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: JANOSCRT slot storage + schedinit verification hook.
//
// This file declares the fixed-size byte array cmd/link's diviner
// pass patches with the Guild + Release + optional User certificate
// chain during the final build step, plus the runtime-side gate that
// verifies the chain at schedinit and throws on any failure.

package runtime

// janosCertSlotStorageSize is the size of the JANOSCRT slot in bytes.
// Matches cmd/janos/certslot.SlotSize.
const janosCertSlotStorageSize = 2048

// janosCertSlotBytes is the 2 KiB block reserved for the JANOSCRT
// certificate chain.  Patched by cmd/link's diviner pass; on an
// undivined build the block contains "JANOSCRT" magic followed by
// version 0 (see initializer below) and the version-byte gate in
// janosVerifyCertSlot skips verification.
//
// Given an initializer so the array lands in .data (which is written
// to the file), not .bss (which is not).  The diviner pass patches
// bytes IN THE FILE, so a BSS location wouldn't work.  The initial
// magic "JANOSCRT" makes the presence of the slot visible in a hex
// dump even before the diviner runs.
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

// janosExpectedGuildPubKey holds the Ed25519 public key of the Guild
// this runtime was built to recognise.  Patched by cmd/link's diviner
// pass from the signet's guild_pubkey field.  All-zero on an
// undivined build; a divined binary with a zero key here is a
// build-system bug and janosVerifyCertSlot throws.
//
// Symbol name (runtime.janosExpectedGuildPubKey) is significant — the
// diviner pass looks it up.
var janosExpectedGuildPubKey = [32]byte{}

// janosExpectedReleasePubKey holds the Ed25519 public key of the
// Release this runtime was built to recognise.  Patched by cmd/link's
// diviner pass from the signet's release_pubkey field.
var janosExpectedReleasePubKey = [32]byte{}

// janosCertSlot returns the runtime's own JANOSCRT slot bytes.
//
//go:nosplit
func janosCertSlot() *[janosCertSlotStorageSize]byte {
	return &janosCertSlotBytes
}

// JanosParentKeys returns the Ed25519 public keys of the Guild and
// Release the currently running JanOS runtime was built to
// recognise.  Both zero on an undivined (bootstrap) runtime.
//
// Used by cmd/link's post-link auto-inherit step to bake the current
// janos binary's family-line keys into every colonel it produces —
// so a colonel of a divined janos automatically enforces the same
// family line even if the operator didn't pass -janos-diviner.
// User code has no legitimate reason to call this; it is exposed
// only for the toolchain.
func JanosParentKeys() (guild, release [32]byte) {
	return janosExpectedGuildPubKey, janosExpectedReleasePubKey
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

// janosVerifyChainHook is called by janosVerifyCertSlot at schedinit
// to verify the JANOSCRT slot's chain of trust.  When nil (default),
// verification is skipped entirely — undivined builds and the
// current bootstrapping state.
//
// When a divined-binary bring-up path wires up cert verification
// end-to-end, an init in an imported package will populate this via
// runtime.SetJanosVerifyChainHook (declared in janos_cert_slot_hook.go)
// with a closure that calls janos_cert.VerifyChain and returns whether
// the slot was accepted.  The runtime side stays crypto-free; the
// crypto lives at the janos_cert layer where it belongs.
var janosVerifyChainHook func(slot []byte, guildPK, releasePK [32]byte) bool

// SetJanosVerifyChainHook installs the schedinit-time cert-chain
// verifier.  Called from janos_cert's init() (once wired) to bridge
// runtime and the crypto-heavy verifier without a hard import
// dependency.  Idempotent within a process — the first call wins;
// subsequent calls are ignored.  Not intended for user code.
//
//go:nosplit
func SetJanosVerifyChainHook(fn func(slot []byte, guildPK, releasePK [32]byte) bool) {
	if janosVerifyChainHook == nil {
		janosVerifyChainHook = fn
	}
}

// janosVerifyCertSlot runs at schedinit after the self-hash pass.
// Uses a hybrid policy keyed on whether this runtime has expected
// Guild/Release keys baked in:
//
//   - Bootstrap mode (expected keys all zero): permissive.  Runtime
//     boots regardless of slot state.  This is the state of a
//     stock-Go-built janos-v0 or a colonel of an undivined janos —
//     no family line has been declared, so the runtime enforces
//     nothing.  TrustLevel stays at whatever the self-hash pass
//     set (TrustSelfAttested on platforms with a reader, TrustNone
//     on stubs).
//
//   - Strict mode (expected keys non-zero): runtime has been
//     assigned a family line.  Every colonel produced through it
//     inherits those keys automatically at link time.  So:
//       * Slot version byte 0 (undivined): throw.  This colonel
//         claims to belong to this family line but has no chain
//         to prove it — either the operator forgot to invoke
//         -janos-diviner or someone stripped the slot.
//       * Slot version byte > 0 with no verifier hook installed:
//         throw.  A runtime declaring family membership must
//         carry the verifier; this one didn't get the bridge
//         wired.
//       * Slot version > 0 with a valid chain: bump TrustLevel to
//         TrustJanosReleased.  Descendants inherit via the
//         gProvenance copy at newproc1.
//       * Slot version > 0 with an invalid chain: throw.
//
//go:noinline
//go:nosplit
func janosVerifyCertSlot() {
	zero := [32]byte{}
	if janosExpectedGuildPubKey == zero && janosExpectedReleasePubKey == zero {
		// Bootstrap mode: no family line declared, nothing to enforce.
		return
	}

	// Strict mode below.  Both expected keys must be non-zero (a
	// partial declaration is a build-system bug).
	if janosExpectedGuildPubKey == zero || janosExpectedReleasePubKey == zero {
		throw("janos: only one of Guild/Release expected keys is baked in — build-system bug")
	}

	if janosSlotVersionByte() == 0 {
		throw("janos: this runtime is divined but the JANOSCRT slot is not — colonels of a divined janos must be divined too")
	}

	if janosVerifyChainHook == nil {
		throw("janos: JANOSCRT slot is divined but no verifier hook is registered — this runtime was not built with cert-verify wiring")
	}

	if !janosVerifyChainHook(janosCertSlotBytes[:],
		janosExpectedGuildPubKey, janosExpectedReleasePubKey) {
		throw("janos: JANOSCRT chain verification failed")
	}

	// Bump this g's trust level; child goroutines inherit via
	// gProvenance copy at newproc1.
	gp := getg()
	gp.provenance.trustLevel = TrustJanosReleased
}

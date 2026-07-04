// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: JANOSCRT slot storage + schedinit verification.
//
// This file declares the fixed-size byte array cmd/link's diviner
// pass patches with the Guild + Release + optional User certificate
// chain during the final build step, plus the runtime-side gate that
// verifies the chain at schedinit and throws on any failure.
//
// Layout constants and the wire format live in cmd/janos/certslot
// (shared with cmd/link, which is bootstrap-copied and cannot import
// from internal/runtime).  Verification (janos_cert_verify.go) is
// runtime-local and calls the runtime's own ECDSA P-256 verifier.

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
	// (16..1615) all zero until the diviner runs.  Remaining reserved
	// tail (1616..2047) is left permanently zero for future extension.
}

// janosExpectedGuildPubKey holds the ECDSA P-256 public key of the
// Guild this runtime was built to recognise (X || Y, 64 bytes).
// Patched by cmd/link's diviner pass from the signet's guild_pubkey
// field.  All-zero on an undivined build; a divined binary with a
// zero key here is a build-system bug and janosVerifyCertSlot throws.
//
// Symbol name (runtime.janosExpectedGuildPubKey) is significant — the
// diviner pass looks it up.
var janosExpectedGuildPubKey = [64]byte{}

// janosExpectedReleasePubKey holds the ECDSA P-256 public key of the
// Release this runtime was built to recognise (X || Y, 64 bytes).
// Patched by cmd/link's diviner pass from the signet's release_pubkey
// field.
var janosExpectedReleasePubKey = [64]byte{}

// janosCertSlot returns the runtime's own JANOSCRT slot bytes.
func janosCertSlot() *[janosCertSlotStorageSize]byte {
	return &janosCertSlotBytes
}

// JanosParentKeys returns the ECDSA P-256 public keys of the Guild
// and Release the currently running JanOS runtime was built to
// recognise.  Both zero on an undivined (bootstrap) runtime.
//
// Used by cmd/link's post-link auto-inherit step to bake the current
// janos binary's family-line keys into every colonel it produces —
// so a colonel of a divined janos automatically enforces the same
// family line even if the operator didn't pass -janos-diviner.
// User code has no legitimate reason to call this; it is exposed
// only for the toolchain.
func JanosParentKeys() (guild, release [64]byte) {
	return janosExpectedGuildPubKey, janosExpectedReleasePubKey
}

// janosSlotVersionByte returns the version byte of the JANOSCRT slot
// (offset 8, right after the "JANOSCRT" magic).  Indirected through
// this small no-inline function so the compiler cannot prove the
// value at compile time — the diviner pass patches the bytes AFTER
// the compiler is done, so runtime reads must go to real memory.
//
//go:noinline
func janosSlotVersionByte() byte {
	return janosCertSlotBytes[8]
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
//       * Slot version > 0 with a valid chain: bump TrustLevel to
//         TrustJanosReleased.  Descendants inherit via the
//         gProvenance copy at newproc1.
//       * Slot version > 0 with an invalid chain: throw.
//
// Not nosplit: the verify path calls into pure-Go ECDSA P-256, which
// uses nested stack frames well beyond the tiny nosplit budget.
// Called from schedinit after the runtime is initialized enough for
// stack growth.
func janosVerifyCertSlot() {
	zero := [64]byte{}
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

	// Read the binary hash the self-hash pass computed (with the
	// slot region zeroed) — that's the message under the Release
	// signature we're about to verify.
	gp := getg()
	binaryHash := gp.provenance.binaryHash

	guild, release, user, hasUser, ok := janosVerifyChainSlot(
		janosCertSlotBytes[:], binaryHash,
		&janosExpectedGuildPubKey, &janosExpectedReleasePubKey)
	if !ok {
		throw("janos: JANOSCRT chain verification failed")
	}

	// Publish the verified certificates process-wide.
	janosGuildCert = guild
	janosReleaseCert = release
	if hasUser {
		janosUserCert = user
		janosHasUserCert = true
	}

	// Compute compact cert IDs (SHA-256 of the signer pubkey) for
	// per-goroutine provenance.
	gp.provenance.guildCertID = janosCertIDFromPubKey(&guild.SignerPubKey)
	gp.provenance.releaseCertID = janosCertIDFromPubKey(&release.SignerPubKey)
	gp.provenance.trustLevel = TrustJanosReleased
}

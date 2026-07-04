// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: cmd/link diviner pass.
//
// A "diviner" is the KMS-backed signing pass invoked at the very end
// of link — after asmb2 has assembled the full binary image and
// before ctxt.Out.Close munmaps it.  The pass:
//
//   1. Loads the signet file named by -janos-signet.
//   2. Locates the runtime.janosCertSlotBytes symbol emitted by the
//      Go runtime source.
//   3. Zeros the slot region in a copy of the assembled image and
//      computes SHA-256 of that copy.  (The verifier does the same
//      thing at boot: reads its own file, zeros the slot region in
//      an in-memory buffer, hashes, then verifies signatures against
//      the resulting digest.)
//   4. Invokes the configured diviner via URL-scheme dispatch
//      (gcpkms://, awskms://, azurekv://, or mockdiviner:// in tests)
//      to sign the digest.  Ed25519 signatures come back as raw
//      64-byte values from every KMS backend.
//   5. Writes the Guild + Release chain into the slot region of the
//      assembled image, in place — the mmap'd output buffer is our
//      canvas.  The signet's release_parent_cert is embedded as the
//      Release entry's parent_cert.  Guild's own signature over the
//      binary is deliberately zero: Guild's private key is offline,
//      and it endorses this release only through the parent_cert on
//      the Release entry (which was produced once during a release
//      ceremony, not on every build).  User (Glitter signet) is not
//      populated here; it's appended later by janos-sign if at all.

package ld

import (
	"cmd/janos/certslot"
	"cmd/janos/diviner"
	// Import gcpkms so its init() registers the "gcpkms" scheme
	// with diviner.Register.  Adding a scheme means adding a
	// blank import here.
	_ "cmd/janos/diviner/gcpkms"
	"cmd/janos/signet"

	"crypto/sha256"
	"fmt"
)

// janosDivinerPass runs after asmb2 has finished writing the binary
// into ctxt.Out and before ctxt.Out.Close munmaps it.  Any error is
// reported through Errorf so the link fails; a JanOS binary must not
// ship without a completed diviner pass.
func janosDivinerPass(ctxt *Link, divinerURL string) {
	if *flagJanosSignet == "" {
		Errorf("-janos-diviner is set but -janos-signet is not; a signet file is mandatory with the diviner pass")
		return
	}

	cfg, err := signet.Load(*flagJanosSignet)
	if err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}
	if err := cfg.ValidateForBuild(); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}

	// Locate the JANOSCRT slot symbol in the assembled image.
	ldr := ctxt.loader
	slotSym := ldr.Lookup("runtime.janosCertSlotBytes", 0)
	if slotSym == 0 {
		Errorf("janos-diviner: symbol runtime.janosCertSlotBytes not found — is this a JanOS runtime?")
		return
	}
	sect := ldr.SymSect(slotSym)
	if sect == nil || sect.Seg == nil {
		Errorf("janos-diviner: runtime.janosCertSlotBytes has no section — did the slot get placed in .bss? It must be initialized so it lands in .data")
		return
	}
	slotVA := uint64(ldr.SymValue(slotSym))
	if slotVA < sect.Vaddr || slotVA-sect.Vaddr >= sect.Length {
		Errorf("janos-diviner: janosCertSlotBytes VA %#x is outside its section [%#x, %#x)", slotVA, sect.Vaddr, sect.Vaddr+sect.Length)
		return
	}
	slotFileOff := sect.Seg.Fileoff + (slotVA - sect.Seg.Vaddr)
	slotSize := int64(certslot.SlotSize)

	// Compute SHA-256 of the whole binary with the slot region zeroed.
	// We hash a copy so the slot bytes on disk still show the pre-populated
	// magic; the verifier does the same in-memory-zeroing on boot.
	data := ctxt.Out.Data()
	if int64(len(data)) < int64(slotFileOff)+slotSize {
		Errorf("janos-diviner: output buffer is %d bytes but slot ends at %d", len(data), int64(slotFileOff)+slotSize)
		return
	}
	hashInput := make([]byte, len(data))
	copy(hashInput, data)
	for i := int64(0); i < slotSize; i++ {
		hashInput[int64(slotFileOff)+i] = 0
	}
	digest := sha256.Sum256(hashInput)

	// Open the release diviner and sign the digest.
	d, err := diviner.Open(divinerURL)
	if err != nil {
		Errorf("janos-diviner: Open(%q): %v", divinerURL, err)
		return
	}
	sig, err := d.Sign(digest)
	if err != nil {
		Errorf("janos-diviner: Sign: %v", err)
		return
	}
	// Cross-check the diviner's public key against the signet's
	// declared release_pubkey — if they disagree, the operator's KMS
	// URL and their signet are out of sync and the build should fail
	// rather than silently emit a binary that won't verify anywhere.
	pubKey, err := d.PublicKey()
	if err != nil {
		Errorf("janos-diviner: PublicKey: %v", err)
		return
	}
	if pubKey != cfg.ReleasePubKey {
		Errorf("janos-diviner: diviner public key does not match signet release_pubkey (KMS says %x, signet says %x)", pubKey, cfg.ReleasePubKey)
		return
	}

	// Build the Guild + Release entries.  Guild.Signature is
	// deliberately zero — Guild's key is offline, and its endorsement
	// of this release lives in Release.ParentCert (signet's
	// release_parent_cert), not in a per-binary signature.
	guildEntry := certslot.Certificate{
		Level:        certslot.LevelGuild,
		SignerPubKey: cfg.GuildPubKey,
	}
	releaseEntry := certslot.Certificate{
		Level:        certslot.LevelRelease,
		RevokeEpoch:  cfg.ReleaseEpoch,
		SignerPubKey: cfg.ReleasePubKey,
		ParentCert:   cfg.ReleaseParentCert,
		Signature:    sig,
	}
	slot := certslot.EncodeSlot([]certslot.Certificate{guildEntry, releaseEntry})

	// Patch the slot into the assembled image, in place.  The
	// verifier at boot re-computes the SHA-256 with the slot zeroed,
	// so the actual bytes we write here do not affect what was
	// signed.
	copy(data[slotFileOff:slotFileOff+uint64(slotSize)], slot[:])

	// Also patch the runtime's expected Guild + Release public key
	// vars so schedinit's verifier knows what to check the slot
	// against.  These symbols are declared with [32]byte initializers
	// so they land in .data (file-backed) alongside the slot.
	if err := patchRuntimeKey(ctxt, "runtime.janosExpectedGuildPubKey", cfg.GuildPubKey[:]); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}
	if err := patchRuntimeKey(ctxt, "runtime.janosExpectedReleasePubKey", cfg.ReleasePubKey[:]); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("janos: diviner pass sealed %d-byte slot at file offset %#x (VA %#x, section %q); expected Guild/Release keys patched\n",
			slotSize, slotFileOff, slotVA, sect.Name)
	}
}

// patchRuntimeKey overwrites the bytes at the named runtime symbol
// with value.  The symbol must be an initialized array of the same
// length as value (32 bytes for a pubkey).
func patchRuntimeKey(ctxt *Link, symName string, value []byte) error {
	ldr := ctxt.loader
	s := ldr.Lookup(symName, 0)
	if s == 0 {
		return fmt.Errorf("symbol %s not found in runtime", symName)
	}
	sect := ldr.SymSect(s)
	if sect == nil || sect.Seg == nil {
		return fmt.Errorf("symbol %s has no section (must be initialized)", symName)
	}
	symVA := uint64(ldr.SymValue(s))
	fileOff := sect.Seg.Fileoff + (symVA - sect.Seg.Vaddr)
	data := ctxt.Out.Data()
	if int(fileOff)+len(value) > len(data) {
		return fmt.Errorf("symbol %s offset %#x+%d is past end of output (%d)", symName, fileOff, len(value), len(data))
	}
	copy(data[fileOff:fileOff+uint64(len(value))], value)
	return nil
}

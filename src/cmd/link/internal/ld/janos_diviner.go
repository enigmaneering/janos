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
//   2. Locates the JANOSCRT slot in the assembled image by scanning
//      for its pre-divined magic header.
//   3. Zeros the slot region + the janosExpected*PubKey symbols in a
//      copy of the assembled image, then computes SHA-256 excluding
//      the Go build ID marker occurrences and the Mach-O code
//      signature (via cmd/internal/buildid.FindAndHash).  Excluding
//      those regions matters because cmd/go rewrites the build ID
//      and recomputes the code signature after cmd/link finishes —
//      any bytes the diviner signs there would drift out of sync
//      with the final on-disk file.
//   4. Invokes the configured diviner via URL-scheme dispatch
//      (gcpkms://, awskms://, azurekv://, or mockdiviner:// in tests)
//      to sign the digest.  ECDSA P-256 signatures come back as raw
//      64-byte r||s values from every KMS backend.
//   5. Writes the Guild + Release chain into the slot region of the
//      assembled image, in place.  Also patches the runtime's
//      janosExpectedGuildPubKey / janosExpectedReleasePubKey vars to
//      the signet's authoritative pubkeys.

package ld

import (
	"cmd/janos/certslot"
	"cmd/janos/diviner"
	// Import gcpkms so its init() registers the "gcpkms" scheme
	// with diviner.Register.  Adding a scheme means adding a
	// blank import here.
	_ "cmd/janos/diviner/gcpkms"
	"cmd/janos/signet"
	"cmd/internal/buildid"

	"bytes"
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

	// Find the JANOSCRT slot by scanning the assembled image for its
	// pre-divined magic header ("JANOSCRT" + version 0 + entry_count 0
	// + 6 reserved zero bytes).  Doing this by content search is more
	// robust than trusting the loader's segment.Fileoff + (VA - Vaddr)
	// math, which on darwin/arm64 was observed off by 32 bytes.
	data := ctxt.Out.Data()
	slotOff, ok := janosLocateSlot(data)
	if !ok {
		Errorf("janos-diviner: JANOSCRT slot magic not found in assembled image — is runtime.janosCertSlotBytes properly initialized?")
		return
	}
	slotSize := int64(certslot.SlotSize)
	if int64(len(data)) < slotOff+slotSize {
		Errorf("janos-diviner: output buffer is %d bytes but slot ends at %d", len(data), slotOff+slotSize)
		return
	}

	// Prepare hashInput = copy of ctxt.Out.Data() with:
	//   - the JANOSCRT slot region zeroed, and
	//   - the janosExpected*PubKey regions zeroed.
	// FindAndHash then further zeros the Go build ID occurrences and
	// excludes the Mach-O code signature from the hash.  The runtime
	// at boot applies matching zeroing to its on-disk read so both
	// sides converge on the same digest.
	hashInput := make([]byte, len(data))
	copy(hashInput, data)
	for i := int64(0); i < slotSize; i++ {
		hashInput[slotOff+i] = 0
	}
	if err := janosZeroSymbol(ctxt, hashInput, "runtime.janosExpectedGuildPubKey", 64); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}
	if err := janosZeroSymbol(ctxt, hashInput, "runtime.janosExpectedReleasePubKey", 64); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}

	// FindAndHash zeros every occurrence of the Go build ID string
	// while hashing, and excludes the Mach-O code signature blob.
	// The linker knows the build ID via *flagBuildid; on ELF it's
	// present in .note.go.buildid and *flagBuildid is authoritative.
	// If -buildid was empty (very rare), fall back to plain SHA-256.
	var digest [32]byte
	if *flagBuildid == "" {
		digest = sha256Of(hashInput)
	} else {
		_, digest, err = buildid.FindAndHash(bytes.NewReader(hashInput), *flagBuildid, 0)
		if err != nil {
			Errorf("janos-diviner: FindAndHash: %v", err)
			return
		}
	}

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
	// declared release_pubkey.
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

	// Patch the slot into the assembled image, in place.
	copy(data[slotOff:slotOff+slotSize], slot[:])

	// Patch the runtime's expected Guild + Release public key vars.
	if err := patchRuntimeKey(ctxt, "runtime.janosExpectedGuildPubKey", cfg.GuildPubKey[:]); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}
	if err := patchRuntimeKey(ctxt, "runtime.janosExpectedReleasePubKey", cfg.ReleasePubKey[:]); err != nil {
		Errorf("janos-diviner: %v", err)
		return
	}

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("janos: diviner pass sealed %d-byte slot at file offset %#x; expected Guild/Release keys patched\n",
			slotSize, slotOff)
	}
}

// janosLocateSlot scans buf for the JANOSCRT slot's pre-divined
// header ("JANOSCRT" + version 0 + entry_count 0 + 6 reserved zero
// bytes) and returns the byte offset of the 'J' plus true on
// success.  The 16-byte pattern is unique to an initialised (but
// not yet sealed) JANOSCRT slot.
func janosLocateSlot(buf []byte) (int64, bool) {
	for i := 0; i+16 <= len(buf); i++ {
		if buf[i] != 'J' || buf[i+1] != 'A' || buf[i+2] != 'N' || buf[i+3] != 'O' ||
			buf[i+4] != 'S' || buf[i+5] != 'C' || buf[i+6] != 'R' || buf[i+7] != 'T' {
			continue
		}
		if buf[i+8] != 0 || buf[i+9] != 0 {
			continue
		}
		if buf[i+10] != 0 || buf[i+11] != 0 || buf[i+12] != 0 ||
			buf[i+13] != 0 || buf[i+14] != 0 || buf[i+15] != 0 {
			continue
		}
		return int64(i), true
	}
	return 0, false
}

// janosZeroSymbol looks up symName in the loader and zeros exactly
// n bytes at its computed file offset in buf.  Returns an error if
// the symbol is missing, unsectioned, or out of range.  Called on
// the hashInput copy so the runtime's expected pubkeys stay at
// their sentinel values in the buffer the diviner signs.
func janosZeroSymbol(ctxt *Link, buf []byte, symName string, n int) error {
	ldr := ctxt.loader
	s := ldr.Lookup(symName, 0)
	if s == 0 {
		return fmt.Errorf("symbol %s not found", symName)
	}
	sect := ldr.SymSect(s)
	if sect == nil || sect.Seg == nil {
		return fmt.Errorf("symbol %s has no section", symName)
	}
	symVA := uint64(ldr.SymValue(s))
	fileOff := sect.Seg.Fileoff + (symVA - sect.Seg.Vaddr)
	if int(fileOff)+n > len(buf) {
		return fmt.Errorf("symbol %s offset %#x+%d is past end of buffer", symName, fileOff, n)
	}
	for i := 0; i < n; i++ {
		buf[int(fileOff)+i] = 0
	}
	return nil
}

// sha256Of returns SHA-256 of buf.  Wraps crypto/sha256 for the
// no-build-ID fallback path.
func sha256Of(buf []byte) [32]byte {
	return sha256.Sum256(buf)
}

// janosInheritParentKeysIntoOutput is declared in a per-build-tag
// file so bootstrap-copied cmd/link (compiled against stock Go's
// runtime, which lacks runtime.JanosParentKeys) can compile with a
// no-op stub, while non-bootstrap cmd/link uses the full
// implementation that reads its own parent's keys.  See
// janos_inherit_ok.go and janos_inherit_bootstrap.go.

// patchRuntimeKeyIfPresent is patchRuntimeKey but returns nil when
// the symbol is not found (rather than erroring).  Used by the
// inherit step, which shouldn't fail on non-JanOS-runtime outputs.
func patchRuntimeKeyIfPresent(ctxt *Link, symName string, value []byte) error {
	ldr := ctxt.loader
	s := ldr.Lookup(symName, 0)
	if s == 0 {
		return nil // absent = "not a JanOS-runtime binary"; skip silently
	}
	return patchRuntimeKey(ctxt, symName, value)
}

// patchRuntimeKey overwrites the bytes at the named runtime symbol
// with value.  The symbol must be an initialized array of the same
// length as value (64 bytes for a P-256 pubkey).
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

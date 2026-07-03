// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: cmd/link diviner pass.
//
// A "diviner" is the KMS-backed signing pass invoked at the very end
// of link — after asmb2 has assembled the full binary image and
// before ctxt.Out.Close munmaps it.  The pass:
//
//   1. Locates the runtime.janosCertSlotBytes symbol emitted by the
//      Go runtime source.
//   2. Zeroes the slot region in the assembled image (it's already
//      zero at this stage since the runtime source declares the var
//      as a zero-initialised [2048]byte).
//   3. Computes SHA-256 of the whole binary image.
//   4. Reads the repo-root signet file to discover which KMS URL
//      names the diviner authorized to seal this build.
//   5. Invokes the diviner via URL-scheme dispatch (gcpkms://,
//      awskms://, azurekv://) to sign the digest.
//   6. Writes the Guild + Release chain (with the fresh Release
//      signature and the signet's baked-in Guild chain) into the
//      slot region of the assembled image.
//
// This file currently contains a no-op stub — the pipeline scaffolding
// is in place, but real hashing/signing/patching lands in sub-tasks B
// (Diviner interface + gcpkms:// backend) and C (ELF integration).

package ld

// janosDivinerPass is called from ld.Main after asmb2 completes if
// --janos-diviner is set.  The current implementation only logs its
// invocation for now; it will grow the real hash/sign/patch pipeline
// in follow-up commits.
func janosDivinerPass(ctxt *Link, divinerURL string) {
	// Silence the "declared and not used" complaint on ctxt for now.
	// The real implementation reads the loader for the JANOSCRT slot
	// symbol and writes into ctxt.Out's mmap'd buffer.
	_ = ctxt

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("janos: diviner pass triggered (url=%s) — no-op stub\n", divinerURL)
	}
	// TODO(diviner-B, diviner-C):
	//   - lookup ldr.LookupSym("runtime.janosCertSlotBytes")
	//   - compute SHA-256 of ctxt.Out.Data()
	//   - open diviner via cmd/janos/diviner.Open(divinerURL)
	//   - patch the slot with Guild + Release chain
}

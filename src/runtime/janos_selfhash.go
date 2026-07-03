// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: binary self-attestation.
//
// The runtime computes the SHA-256 of its own executable image at
// schedinit and stores it in the current g's provenance.  This is
// what makes provenance implicit — every JanOS binary knows what it
// is without user code lifting a finger.
//
// Per-target files define janosInitBinaryHash end-to-end:
//   janos_selfhash_linux.go   — opens /proc/self/exe with runtime open/read/closefd
//   janos_selfhash_darwin.go  — opens runtime.executablePath with runtime open/read/closefd
//   janos_selfhash_windows.go — CreateFileW/ReadFile/CloseHandle via kernel32 stdcall
//   janos_selfhash_stub.go    — no-op for platforms without a reader yet
//     (BSDs, Solaris, Plan 9, wasm, tamago)
//
// On stub-covered platforms provenance stays at
// {BinaryHash: 0, TrustLevel: TrustNone}; higher layers can layer
// hardware/colonel attestation on top when available.

package runtime

// janosStoreBinaryHash finishes a per-platform self-hash run: given the
// completed SHA-256 digest, it writes both the hash and TrustSelfAttested
// onto the current g's provenance.  Each per-target file calls this
// once after it has streamed the binary through its own janosSHA256.
//
//go:nosplit
func janosStoreBinaryHash(digest [32]byte) {
	gp := getg()
	gp.provenance.binaryHash = digest
	gp.provenance.trustLevel = TrustSelfAttested
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test-only helpers that live in the runtime package so external tests
// can reach package-internal state.  Production code has no setter
// for provenance — it is entirely runtime-driven — so this file
// exists purely to let the test harness synthesize inheritance
// scenarios that the natural schedinit flow would not exercise.

package runtime

// SetCurrentProvenanceForTest overwrites the current goroutine's
// provenance.  Snapshot the value before calling and restore it in a
// deferred call to avoid polluting other tests.
func SetCurrentProvenanceForTest(p Provenance) {
	janosSetGProvenance(getg(), p)
}

// JanosSHA256ForTest exposes the runtime-internal SHA-256 to external
// tests so they can compare its output against a known-good vector
// without needing to import crypto/sha256 (which sits above runtime).
func JanosSHA256ForTest(p []byte) [32]byte {
	var d janosSHA256
	d.Reset()
	d.Write(p)
	return d.Sum()
}

// JanosSHA512ForTest exposes the runtime-internal SHA-512 to external
// tests.  Ed25519 verification depends on SHA-512 internally, so we
// vet it here against NIST test vectors before wiring it up.
func JanosSHA512ForTest(p []byte) [64]byte {
	var d janosSHA512
	d.Reset()
	d.Write(p)
	return d.Sum()
}

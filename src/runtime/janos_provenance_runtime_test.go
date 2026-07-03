// Copyright 2026 The Enigmaneering Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Test-only helpers that live in the runtime package so external tests
// can reach package-internal state (janosSetGProvenance and
// rootAttestSet). Production callers use SetRootBinaryAttestation
// and CurrentProvenance.

package runtime

// SetCurrentProvenanceForTest overwrites the current goroutine's
// provenance without touching the SetRootBinaryAttestation once-guard.
// Tests use this to snapshot-restore around inheritance assertions.
func SetCurrentProvenanceForTest(p Provenance) {
	janosSetGProvenance(getg(), p)
}

// ResetRootAttestForTest clears the once-guard on SetRootBinaryAttestation
// so tests can drive the attest → assert → reset cycle repeatedly.
// It does not touch any g's provenance — pair with SetCurrentProvenanceForTest
// to fully reset test state.
func ResetRootAttestForTest() {
	rootAttestSet.Store(0)
}

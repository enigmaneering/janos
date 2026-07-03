// Copyright 2026 The Enigmaneering Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// This file lives in the runtime package so external tests can reach
// the package-internal janosSetGProvenance helper.

package runtime

// SetCurrentProvenance overwrites the current goroutine's provenance.
// Exported here for the sole benefit of janos_provenance_test.go —
// production code sets provenance via the boot self-attestation path
// and can call janosSetGProvenance directly.
func SetCurrentProvenance(p Provenance) {
	janosSetGProvenance(getg(), p)
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test-only helpers that live in the runtime package so external tests
// can reach package-internal state.  Production code has no setter
// for provenance — it is entirely runtime-driven — so this file
// exists purely to let the test harness synthesize inheritance
// scenarios that the natural schedinit flow would not exercise.

package runtime

import "internal/runtime/janos_hash"

// CurrentInstanceIDHexForTest returns the running goroutine's
// InstanceID as a 32-char hex string.  Test-only helper so
// TestInstanceIDDistinctAcrossRuns can print and compare without
// importing encoding/hex into runtime tests.
func CurrentInstanceIDHexForTest() string {
	id := CurrentProvenance().InstanceID
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(id)*2)
	for i, b := range id {
		out[i*2] = hexChars[b>>4]
		out[i*2+1] = hexChars[b&0xf]
	}
	return string(out)
}

// SetCurrentProvenanceForTest overwrites the current goroutine's
// provenance.  Snapshot the value before calling and restore it in a
// deferred call to avoid polluting other tests.
func SetCurrentProvenanceForTest(p Provenance) {
	janosSetGProvenance(getg(), p)
}

// JanosSHA256ForTest exposes the runtime-adjacent SHA-256 to external
// tests so they can compare its output against a known-good vector
// without needing to import crypto/sha256 (which sits above runtime).
func JanosSHA256ForTest(p []byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(p)
	return d.Sum()
}

// JanosSHA512ForTest exposes the runtime-adjacent SHA-512 to external
// tests.  Ed25519 verification depends on SHA-512 internally, so we
// vet it here against NIST test vectors before wiring it up.
func JanosSHA512ForTest(p []byte) [64]byte {
	var d janos_hash.SHA512
	d.Reset()
	d.Write(p)
	return d.Sum()
}

// SetJanosVerifyChainHookForTest installs / clears the schedinit
// cert-verify hook that the runtime calls from janosVerifyCertSlot.
// Tests use this to exercise the divined-boot code path without
// wiring up the real janos_cert crypto (which lives outside
// runtime).
func SetJanosVerifyChainHookForTest(fn func(slot []byte, guildPK, releasePK [32]byte) bool) {
	janosVerifyChainHook = fn
}

// SetJanosCertificatesForTest populates the process-wide Guild/
// Release/User cert storage without going through the real schedinit
// verification path.  Also updates the calling goroutine's cert IDs
// and bumps TrustLevel to TrustJanosReleased so tests can observe
// the "runtime has verified this binary" state.  Pass nil for user
// to clear the user cert.  Restore via SetJanosCertificatesForTest
// with zero-value certs.
func SetJanosCertificatesForTest(guild, release Certificate, user *Certificate) {
	janosGuildCert = guild
	janosReleaseCert = release
	if user != nil {
		janosUserCert = *user
		janosHasUserCert = true
	} else {
		janosUserCert = Certificate{}
		janosHasUserCert = false
	}

	gp := getg()
	gp.provenance.guildCertID = certIDForTest(guild.SignerPubKey)
	gp.provenance.releaseCertID = certIDForTest(release.SignerPubKey)
	// Only bump the trust level when at least Guild + Release are set.
	// A zero-value guild/release clears back to whatever level was
	// there before, which for stubs is TrustNone and for platforms
	// with a self-hash reader is TrustSelfAttested.
	if guild != (Certificate{}) && release != (Certificate{}) {
		gp.provenance.trustLevel = TrustJanosReleased
	}
}

// certIDForTest is the same hash function janos_cert would use to
// compute a compact identifier for a signer.  We inline it here so
// the test setter doesn't have to import janos_cert (which would drag
// in the whole ed25519/hash stack for every runtime test binary).
func certIDForTest(pk [32]byte) [32]byte {
	var d janos_hash.SHA256
	d.Reset()
	d.Write(pk[:])
	return d.Sum()
}

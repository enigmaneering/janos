// Copyright 2026 The Enigmaneering Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// JanOS: goroutine provenance.
//
// Every g carries a gProvenance value identifying the code the
// goroutine is running: who signed the binary, the hash of the running
// binary, and how strongly that identity has been verified. Child
// goroutines inherit the field verbatim from their creator at newproc1
// time (see src/runtime/proc.go), which makes the identity chain a
// natural walk backward through parentGoid + ancestor state.
//
// The exported Provenance type and CurrentProvenance() accessor let
// user code (e.g. mental.State()) read the identity of the currently
// executing goroutine with no allocation, no lock, and no syscall.

package runtime

// gProvenance is the identity of the binary a goroutine is executing.
// It is copied — never referenced — into child goroutines, so it is
// safe to embed by value in g.
type gProvenance struct {
	// signerID identifies the entity that vouched for this binary.
	// Zero value means "no signer" (equivalent to trustLevel == TrustNone).
	signerID [32]byte
	// binaryHash is the SHA-256 of the code currently being run.
	// For the root g it is set from JanOS's self-attestation ceremony;
	// for descendants it is inherited from the creating g.
	binaryHash [32]byte
	// trustLevel records how the current identity was established.
	trustLevel TrustLevel
	// _ padding — keeps the struct 8-byte aligned regardless of GOARCH.
	_ [7]byte
}

// janosSetGProvenance overwrites the provenance of the given g.
// Package-internal — reserved for the runtime's own boot self-attestation
// path and future signed-boundary crossings in JanOS colonels. There is
// deliberately no exported equivalent: user code can only read
// provenance, never set it.
//
//go:nosplit
func janosSetGProvenance(gp *g, p Provenance) {
	gp.provenance.signerID = p.SignerID
	gp.provenance.binaryHash = p.BinaryHash
	gp.provenance.trustLevel = p.TrustLevel
}

// Provenance is the identity of the code a goroutine is executing.
//
// SignerID identifies the entity that vouched for the binary.
// BinaryHash is the SHA-256 of the running code.
// TrustLevel records how strongly the identity has been established.
//
// The zero value describes an unattested goroutine (no signer, no hash,
// TrustLevel == TrustNone), which is the state a JanOS binary boots in
// until self-attestation completes.
type Provenance struct {
	SignerID   [32]byte
	BinaryHash [32]byte
	TrustLevel TrustLevel
}

// TrustLevel records how strongly the current provenance has been verified.
type TrustLevel uint8

// Trust levels, in ascending order of strength.
const (
	// TrustNone: identity has not been established (zero value).
	TrustNone TrustLevel = iota
	// TrustSelfAttested: the binary hashed itself at boot and asserted
	// its own signerID. Vulnerable to a tampered runtime.
	TrustSelfAttested
	// TrustHardwareAttested: an HSM/TPM/SE has attested the running
	// binary matches an expected measurement.
	TrustHardwareAttested
	// TrustColonelAttested: a JanOS colonel has verified this binary
	// at load time against a chain rooted in silicon.
	TrustColonelAttested
)

// String returns a human-readable name for the trust level.
func (t TrustLevel) String() string {
	switch t {
	case TrustNone:
		return "none"
	case TrustSelfAttested:
		return "self-attested"
	case TrustHardwareAttested:
		return "hardware-attested"
	case TrustColonelAttested:
		return "colonel-attested"
	default:
		return "unknown"
	}
}

// CurrentProvenance returns the provenance of the currently executing
// goroutine.
//
// It reads directly off the g descriptor — no allocation, no syscall,
// no lock. Safe to call at any point in user code, including in hot
// paths. The returned value is a snapshot; provenance is fixed for the
// lifetime of a goroutine, so callers do not need to worry about the
// value changing under them.
//
//go:nosplit
func CurrentProvenance() Provenance {
	gp := getg()
	return Provenance{
		SignerID:   gp.provenance.signerID,
		BinaryHash: gp.provenance.binaryHash,
		TrustLevel: gp.provenance.trustLevel,
	}
}

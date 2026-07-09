// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package secureenclave is JanOS's macOS hardware root-of-trust
// provider.
//
// It creates P-256 keys whose private scalar is generated and held
// inside the Apple Secure Enclave and never leaves it.  Only the
// public point and the results of operations — an ECDSA signature, an
// ECDH shared secret — cross the boundary; the scalar itself is not
// representable in process memory.  This is the macOS analog of the
// TPM-wrapped keys package internal/tpm2 provides on Linux and the
// CNG Platform Crypto Provider will provide on Windows: same role
// (bind an identity's private key to on-chip hardware), platform-
// native mechanism.
//
// The Secure Enclave supports exactly one key type — 256-bit EC on
// the NIST P-256 curve — which is precisely the curve JanOS identities
// already use, so an SE key drops directly into the identity model:
// its public point is Identity.PublicPoint, its ECDH backs Derive,
// its signature backs attestation.
//
// CGO is required (Security.framework); the darwin build carries the
// implementation and every other build carries a stub that reports
// ErrUnavailable, so the package compiles everywhere.
package secureenclave

import (
	"errors"
	"unsafe"
)

// ErrUnavailable is returned when the Secure Enclave is not present or
// usable on this platform (non-darwin, cgo disabled, or a Mac without
// a Secure Enclave).
var ErrUnavailable = errors.New("secureenclave: not available on this platform")

// Key is a handle to a Secure Enclave-backed P-256 key.  The private
// scalar lives in the enclave; ref holds the platform key reference
// (a SecKeyRef on darwin, nil on the stub).  A Key must be Closed to
// release the reference.
type Key struct {
	ref unsafe.Pointer
}

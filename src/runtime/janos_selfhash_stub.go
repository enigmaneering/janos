// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin && !windows

// JanOS: binary self-attestation, no-op stub.
//
// Compiled on every target that does not yet have a native reader:
// WASM (js and wasip1), tamago, the BSDs, Solaris, Plan 9, and AIX.
// On these platforms provenance boots as
// {BinaryHash: 0, TrustLevel: TrustNone}; per-target readers will
// replace this file as each board comes up.

package runtime

func janosInitBinaryHash() {}

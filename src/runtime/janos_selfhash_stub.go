// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin

// JanOS: binary self-attestation, no-op stub.
//
// Compiled on every target that does not yet have a native reader:
// Windows, WASM (js and wasip1), tamago, the BSDs, Solaris, AIX, and
// Plan 9.  On these platforms provenance boots as
// {BinaryHash: 0, TrustLevel: TrustNone}; per-target readers will
// replace this file as each board comes up.

package runtime

func janosOpenSelfBinary() int32 { return -1 }

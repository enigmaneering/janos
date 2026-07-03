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
// The reader is target-specific: janos_selfhash_linux.go opens
// /proc/self/exe, janos_selfhash_darwin.go opens the exe path recorded
// during sysargs, and janos_selfhash_stub.go is a no-op used on
// platforms we have not implemented yet (Windows, WASM, tamago, BSDs).
// On the stub-covered platforms provenance stays at
// {BinaryHash: 0, TrustLevel: TrustNone}; higher layers can layer
// hardware/colonel attestation on top when available.

package runtime

import "unsafe"

// janosInitBinaryHash reads the executable image from disk, computes
// SHA-256, and records the result in the current g's provenance.  It
// is called from schedinit right after janosInitInstanceID.  On
// platforms without a working janosOpenSelfBinary, it silently leaves
// provenance in the zero state.
func janosInitBinaryHash() {
	fd := janosOpenSelfBinary()
	if fd < 0 {
		return
	}
	var d janosSHA256
	d.Reset()
	var buf [4096]byte
	for {
		n := read(fd, unsafe.Pointer(&buf[0]), int32(len(buf)))
		if n < 0 {
			closefd(fd)
			return
		}
		if n == 0 {
			break
		}
		d.Write(buf[:n])
	}
	closefd(fd)

	gp := getg()
	gp.provenance.binaryHash = d.Sum()
	gp.provenance.trustLevel = TrustSelfAttested
}

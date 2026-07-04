// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

// JanOS: binary self-attestation, Linux reader.
//
// Linux exposes the currently running executable via the
// /proc/self/exe symlink; opening it yields a file descriptor over
// the on-disk image.  We hand a null-terminated path buffer to the
// two-pass streaming hasher in janos_selfhash.go.

package runtime

var janosSelfExePathLinux = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'e', 'x', 'e', 0}

const janosLinuxORDONLY = 0

func janosInitBinaryHash() {
	digest, ok := janosHashExecutable(janosLinuxOpenExe)
	if !ok {
		return
	}
	janosStoreBinaryHash(digest)
}

func janosLinuxOpenExe() int32 {
	return open(&janosSelfExePathLinux[0], janosLinuxORDONLY, 0)
}

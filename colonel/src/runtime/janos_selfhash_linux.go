// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

// JanOS: binary self-attestation, Linux reader.
//
// Linux exposes the running executable via /proc/self/exe.  We open
// it and hand the fd to janos_selfhash.go's mmap-based hasher.

package runtime

var janosSelfExePathLinux = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'e', 'x', 'e', 0}

const janosLinuxORDONLY = 0

func janosInitBinaryHash() {
	fd := open(&janosSelfExePathLinux[0], janosLinuxORDONLY, 0)
	if fd < 0 {
		return
	}
	defer closefd(fd)

	digest, ok := janosHashFD(fd)
	if !ok {
		return
	}
	janosStoreBinaryHash(digest)
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

// JanOS: binary self-attestation, Darwin reader.
//
// On Darwin, the executable path is provided by the kernel in the
// argv area of the launch parameters and captured by the runtime in
// os_darwin.go's sysargs into the package-level executablePath.  By
// the time schedinit runs, the string is available; we copy it into a
// null-terminated stack buffer and hand it to the runtime's own
// open() syscall wrapper.

package runtime

// janosDarwinORDONLY mirrors the C O_RDONLY constant.
const janosDarwinORDONLY = 0

// Maximum path length we can inline.  Darwin's PATH_MAX is 1024; we
// allow one extra byte for the null terminator.
const janosDarwinPathMax = 1024

func janosOpenSelfBinary() int32 {
	p := executablePath
	if len(p) == 0 || len(p) >= janosDarwinPathMax {
		return -1
	}
	var buf [janosDarwinPathMax + 1]byte
	for i := 0; i < len(p); i++ {
		buf[i] = p[i]
	}
	buf[len(p)] = 0
	return open(&buf[0], janosDarwinORDONLY, 0)
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

// JanOS: binary self-attestation, Darwin reader.
//
// On Darwin the executable path is provided by the kernel in the argv
// area of the launch parameters and captured by the runtime in
// os_darwin.go's sysargs into the package-level executablePath.  By
// the time schedinit runs the string is available; we copy it into a
// null-terminated stack buffer and hand it to the runtime's own
// open() syscall wrapper.

package runtime

import "unsafe"

const janosDarwinORDONLY = 0    // O_RDONLY
const janosDarwinPathMax = 1024 // Darwin PATH_MAX

func janosInitBinaryHash() {
	p := executablePath
	if len(p) == 0 || len(p) >= janosDarwinPathMax {
		return
	}
	var pathBuf [janosDarwinPathMax + 1]byte
	for i := 0; i < len(p); i++ {
		pathBuf[i] = p[i]
	}
	pathBuf[len(p)] = 0

	fd := open(&pathBuf[0], janosDarwinORDONLY, 0)
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
	janosStoreBinaryHash(d.Sum())
}

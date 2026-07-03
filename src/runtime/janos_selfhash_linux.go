// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

// JanOS: binary self-attestation, Linux reader.
//
// Linux exposes the currently running executable via the
// /proc/self/exe symlink; opening it yields a file descriptor over
// the on-disk image, which is exactly what SHA-256'ing the "binary"
// means in this context.  Works regardless of whether the process
// still has read permission on its original argv[0] path.

package runtime

import "unsafe"

var janosSelfExePathLinux = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'e', 'x', 'e', 0}

const janosLinuxORDONLY = 0 // O_RDONLY on all Linux archs

func janosInitBinaryHash() {
	fd := open(&janosSelfExePathLinux[0], janosLinuxORDONLY, 0)
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

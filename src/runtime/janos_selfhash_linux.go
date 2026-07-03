// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

// JanOS: binary self-attestation, Linux reader.
//
// Linux exposes the currently running executable via the
// /proc/self/exe symlink; opening it yields a file descriptor over the
// on-disk image, which is exactly what SHA-256'ing the "binary" means
// in this context.  This works regardless of whether the process still
// has read permission on its original argv[0] path.

package runtime

// Null-terminated for direct handoff to the runtime's open() syscall.
var janosSelfExePathLinux = [...]byte{'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'e', 'x', 'e', 0}

// janosLinuxORDONLY mirrors the C O_RDONLY constant.  Linux uses
// value 0 across all supported architectures.
const janosLinuxORDONLY = 0

func janosOpenSelfBinary() int32 {
	return open(&janosSelfExePathLinux[0], janosLinuxORDONLY, 0)
}

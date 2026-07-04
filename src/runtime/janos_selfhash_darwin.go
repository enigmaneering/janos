// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

// JanOS: binary self-attestation, Darwin reader.
//
// On Darwin the executable path is provided by the kernel in the argv
// area of the launch parameters and captured by the runtime in
// os_darwin.go's sysargs into the package-level executablePath.  We
// hand the path to the two-pass streaming self-hasher in
// janos_selfhash.go; that hasher does all the exclusion / mask work.

package runtime

const janosDarwinORDONLY = 0
const janosDarwinPathMax = 1024

// janosDarwinExePath holds a null-terminated copy of executablePath
// so the opener can reopen the file across passes without touching
// the (possibly growing) Go string.  Populated on the first opener
// call.
var janosDarwinExePath [janosDarwinPathMax + 1]byte

func janosInitBinaryHash() {
	p := executablePath
	if len(p) == 0 || len(p) >= janosDarwinPathMax {
		return
	}
	for i := 0; i < len(p); i++ {
		janosDarwinExePath[i] = p[i]
	}
	janosDarwinExePath[len(p)] = 0

	digest, ok := janosHashExecutable(janosDarwinOpenExe)
	if !ok {
		return
	}
	janosStoreBinaryHash(digest)
}

func janosDarwinOpenExe() int32 {
	return open(&janosDarwinExePath[0], janosDarwinORDONLY, 0)
}

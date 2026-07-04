//go:build darwin

// JanOS: binary self-attestation, Darwin reader.
//
// On Darwin the executable path is provided by the kernel in the argv
// area and captured by the runtime in os_darwin.go's sysargs into the
// package-level executablePath.  We hand the path to the mmap-based
// single-pass hasher in janos_selfhash.go.

package runtime

const janosDarwinORDONLY = 0
const janosDarwinPathMax = 1024

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
	defer closefd(fd)

	digest, ok := janosHashFD(fd)
	if !ok {
		return
	}
	janosStoreBinaryHash(digest)
}

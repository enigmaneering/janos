// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux

// JanOS: binary self-attestation, POSIX mmap + read path.
//
// Shared by the darwin and linux readers.  Reserves a large VA window
// via runtime.mmap (bypassing the Go allocator so TestMemPprof does
// not see a multi-MB alloc), reads the fd into it, then runs the
// portable canonical hasher.  Windows has its own equivalent in
// janos_selfhash_windows.go using VirtualAlloc + ReadFile.

package runtime

import "unsafe"

// janosHashFD reads the whole file behind fd into a fresh mmap
// mapping, canonicalises the bytes the same way cmd/internal/buildid
// .FindAndHash does (with the JanOS-specific extra zeros for slot
// and expected pubkeys), and returns SHA-256 of the result.
//
// Returns (digest, true) on success, ([32]byte{}, false) on any I/O
// or mmap error — the caller leaves the provenance untouched in that
// case.
func janosHashFD(fd int32) ([32]byte, bool) {
	buf, mapped := janosMmapAnon(janosMaxBinarySize)
	if buf == nil {
		return [32]byte{}, false
	}
	defer janosMunmap(buf, mapped)

	total := 0
	for total < mapped {
		n := read(fd, unsafe.Pointer(&buf[total]), int32(mapped-total))
		if n < 0 {
			return [32]byte{}, false
		}
		if n == 0 {
			break
		}
		total += int(n)
	}
	if total == 0 || total >= mapped {
		return [32]byte{}, false
	}
	return janosHashCanonical(buf[:total]), true
}

// janosMmapAnon allocates an anonymous mmap region of size bytes via
// runtime.mmap.  Returns (nil, 0) on failure.  The region is a
// []byte view over the underlying pages.
func janosMmapAnon(size int) ([]byte, int) {
	if size <= 0 {
		return nil, 0
	}
	p, err := mmap(nil, uintptr(size),
		_PROT_READ|_PROT_WRITE,
		_MAP_ANON|_MAP_PRIVATE,
		-1, 0)
	if err != 0 {
		return nil, 0
	}
	return unsafe.Slice((*byte)(p), size), size
}

// janosMunmap releases a mapping obtained via janosMmapAnon.
func janosMunmap(buf []byte, size int) {
	if len(buf) == 0 || size <= 0 {
		return
	}
	munmap(unsafe.Pointer(&buf[0]), uintptr(size))
}

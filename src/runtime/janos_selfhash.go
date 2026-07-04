// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: binary self-attestation.
//
// The runtime computes the SHA-256 of its own executable image at
// schedinit and stores it in the current g's provenance.  Both the
// runtime here and cmd/link's diviner pass canonicalise the byte
// stream the same way before hashing, so their digests converge:
//
//   - The JANOSCRT slot region is zeroed.  (Signing something
//     containing its own signature is impossible.)
//   - The janosExpected*PubKey byte regions are zeroed.  The diviner
//     hashes ctxt.Out.Data() BEFORE calling patchRuntimeKey, so
//     those regions still hold the undivined-sentinel string at
//     signing time; the runtime sees the patched pubkeys at boot.
//     Zeroing at every occurrence of the current divined pubkey on
//     the runtime side matches the diviner zeroing the symbol.
//   - Every occurrence of the Go build ID string is zeroed.  cmd/go
//     rewrites the build ID between cmd/link and the on-disk file.
//   - The Mach-O code signature blob and LC_UUID load command data
//     are excluded.  cmd/go recomputes both when it rewrites the
//     build ID.  On ELF/PE the corresponding regions (GNU note
//     .note.gnu.build-id, PE authenticode) get the same treatment.
//
// This is the same canonicalisation as cmd/internal/buildid.FindAnd-
// Hash, which the diviner uses.  Runtime cross-check: a userspace
// tool calling FindAndHash with the runtime binary's post-rewrite
// build ID reproduces the diviner's signed digest byte-for-byte.
//
// The runtime opens its executable, mmaps the file via runtime.mmap
// (bypassing the Go heap so mem profiles don't get dominated by a
// multi-MB alloc), then does a single-pass scan-plus-hash over the
// mmapped region.  runtime.mmap does NOT show up in TestMemPprof.
//
// Per-target file (janos_selfhash_darwin.go, ...) provides the
// executable path, opens the file, and hands the fd to janosHashFD.

package runtime

import (
	"internal/runtime/janos_hash"
	"unsafe"
)

// janosStoreBinaryHash finishes a per-platform self-hash run: given
// the completed SHA-256 digest, it writes both the hash and Trust-
// SelfAttested onto the current g's provenance.
//
//go:nosplit
func janosStoreBinaryHash(digest [32]byte) {
	gp := getg()
	gp.provenance.binaryHash = digest
	gp.provenance.trustLevel = TrustSelfAttested
}

// janosGoBuildIDMarker is the byte sequence cmd/link writes right
// before the Go build ID string: "\xff Go build ID: ".  Followed by
// the quoted ID and the suffix `"\n \xff`.
var janosGoBuildIDMarker = [16]byte{
	0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', ' ', 'I', 'D', ':', ' ', '"',
}

// janosMaxBinarySize caps how large a binary the runtime is willing
// to hash.  Reasonable Go binaries land in the low tens of MB;
// picking a generous 256 MB cap keeps the mmap sizing simple without
// risking absurd VA reservations.  A binary past this cap will fail
// to hash and stay at TrustNone / TrustSelfAttested → false — the
// runtime just doesn't declare itself divined.
const janosMaxBinarySize = 256 << 20

// janosHashFD reads the whole file behind fd into a fresh mmap
// mapping, canonicalises the bytes the same way cmd/internal/buildid
// .FindAndHash does (with the JanOS-specific extra zeros for slot
// and expected pubkeys), and returns SHA-256 of the result.
//
// Returns (digest, true) on success, ([32]byte{}, false) on any I/O
// or mmap error — the caller leaves the provenance untouched in that
// case.
func janosHashFD(fd int32) ([32]byte, bool) {
	// Reserve a large VA window via anonymous mmap.  runtime.mmap
	// bypasses the Go allocator, so TestMemPprof does not see the
	// mapping in its alloc profile.
	buf, mapped := janosMmapAnon(janosMaxBinarySize)
	if buf == nil {
		return [32]byte{}, false
	}
	defer janosMunmap(buf, mapped)

	// Read the entire file into the mmap region.  Stops at EOF or
	// when the buffer is full.  A file bigger than janosMaxBinary-
	// Size is unusual for a Go binary; we refuse to hash it.
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
	fileBytes := buf[:total]

	// Compute the exclusion set inline and hash in one pass.
	return janosHashCanonical(fileBytes), true
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

// janosHashCanonical computes the digest of buf with the JanOS
// canonicalisation applied, using the current runtime's expected
// Guild/Release pubkey patterns.  Wrapper around janosCanonicalHash
// for the production call site; tests use janosCanonicalHash
// directly so they can inject arbitrary patterns.
func janosHashCanonical(buf []byte) [32]byte {
	return janosCanonicalHash(buf,
		janosExpectedGuildPubKey[:],
		janosExpectedReleasePubKey[:])
}

// janosCanonicalHash computes the digest of buf after zeroing the
// regions that both the diviner (via cmd/internal/buildid.FindAnd-
// Hash + explicit slot/expected-key zeros) and the runtime need to
// agree on.  buf is mutated in place — the caller's mmap region is
// discarded shortly after this returns, so the mutations don't
// matter.  Steps:
//
//	1. Locate the JANOSCRT slot (divined magic + version 1) and
//	   zero its 2 KiB.
//	2. Zero every occurrence of guildKey and releaseKey byte
//	   patterns.
//	3. Parse the Mach-O header, if present, and zero the LC_CODE_
//	   SIGNATURE data range and the LC_UUID 16-byte UUID region.
//	4. Find the Go build ID marker `\xff Go build ID: "..."\n \xff`,
//	   extract the ID, and zero every occurrence of it.
//	5. SHA-256 the result.
func janosCanonicalHash(buf, guildKey, releaseKey []byte) [32]byte {
	// Step 1: JANOSCRT divined slot.
	if off, ok := janosLocateDivinedSlot(buf); ok {
		end := off + janosCertSlotStorageSize
		if end > len(buf) {
			end = len(buf)
		}
		for i := off; i < end; i++ {
			buf[i] = 0
		}
	}

	// Step 2: expected pubkey positions.
	janosZeroAll(buf, guildKey)
	janosZeroAll(buf, releaseKey)

	// Step 3: Mach-O codesig + LC_UUID.
	janosZeroMachoExcludes(buf)

	// Step 4: Go build ID.
	if idStart, idEnd, ok := janosFindBuildIDInBuf(buf); ok {
		id := append([]byte(nil), buf[idStart:idEnd]...)
		if len(id) > 0 {
			janosZeroAll(buf, id)
		}
	}

	// Step 5: hash.
	var d janos_hash.SHA256
	d.Reset()
	d.Write(buf)
	return d.Sum()
}

// janosLocateDivinedSlot scans buf for the divined JANOSCRT slot
// header ("JANOSCRT" + version 0x01 + entry_count 1..8 + 6 reserved
// zero bytes) and returns its byte offset.  Returns (0, false) on
// undivined binaries.
func janosLocateDivinedSlot(buf []byte) (int, bool) {
	for i := 0; i+16 <= len(buf); i++ {
		if buf[i] != 'J' || buf[i+1] != 'A' || buf[i+2] != 'N' || buf[i+3] != 'O' ||
			buf[i+4] != 'S' || buf[i+5] != 'C' || buf[i+6] != 'R' || buf[i+7] != 'T' {
			continue
		}
		if buf[i+8] != 1 {
			continue
		}
		count := buf[i+9]
		if count == 0 || count > 8 {
			continue
		}
		if buf[i+10] != 0 || buf[i+11] != 0 || buf[i+12] != 0 ||
			buf[i+13] != 0 || buf[i+14] != 0 || buf[i+15] != 0 {
			continue
		}
		return i, true
	}
	return 0, false
}

// janosZeroAll zeros every non-overlapping occurrence of pattern in
// buf.  pattern must be at least 1 byte.
func janosZeroAll(buf, pattern []byte) {
	n := len(pattern)
	if n == 0 || n > len(buf) {
		return
	}
	first := pattern[0]
	limit := len(buf) - n
	for i := 0; i <= limit; i++ {
		if buf[i] != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			if buf[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		for j := 0; j < n; j++ {
			buf[i+j] = 0
		}
		i += n - 1
	}
}

// janosFindBuildIDInBuf locates the Go build ID marker in buf and
// returns the byte range of the ID string inside the quotes.  The
// marker format is `\xff Go build ID: "ID"\n \xff`; we require the
// full suffix to filter out unrelated bytes that happen to start
// with the marker prefix.
func janosFindBuildIDInBuf(buf []byte) (int, int, bool) {
	for i := 0; i+20 <= len(buf); i++ {
		match := true
		for j := 0; j < 16; j++ {
			if buf[i+j] != janosGoBuildIDMarker[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		end := i + 16
		for end < len(buf) && buf[end] != '"' {
			end++
		}
		if end+3 >= len(buf) {
			continue
		}
		if buf[end] != '"' || buf[end+1] != '\n' || buf[end+2] != ' ' || buf[end+3] != 0xff {
			continue
		}
		return i + 16, end, true
	}
	return 0, 0, false
}

// janosZeroMachoExcludes parses buf's Mach-O header (if present) and
// zeros the LC_CODE_SIGNATURE data range plus the LC_UUID 16-byte
// UUID payload.  Both regions are the ones cmd/internal/buildid
// excludes on darwin/macos.  Non-Mach-O input is a no-op.
func janosZeroMachoExcludes(buf []byte) {
	if len(buf) < 32 {
		return
	}
	// 64-bit Mach-O magic (LE): CF FA ED FE.
	if buf[0] != 0xCF || buf[1] != 0xFA || buf[2] != 0xED || buf[3] != 0xFE {
		return
	}
	ncmds := uint32(buf[16]) | uint32(buf[17])<<8 | uint32(buf[18])<<16 | uint32(buf[19])<<24
	sizeofcmds := uint32(buf[20]) | uint32(buf[21])<<8 | uint32(buf[22])<<16 | uint32(buf[23])<<24
	off := uint32(32)
	end := off + sizeofcmds
	if end > uint32(len(buf)) {
		end = uint32(len(buf))
	}
	for i := uint32(0); i < ncmds && off+8 <= end; i++ {
		cmd := uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16 | uint32(buf[off+3])<<24
		cmdsize := uint32(buf[off+4]) | uint32(buf[off+5])<<8 | uint32(buf[off+6])<<16 | uint32(buf[off+7])<<24
		if cmdsize < 8 || off+cmdsize > end {
			return
		}
		// LC_CODE_SIGNATURE = 0x1D (linkedit_data_command).
		if cmd == 0x1D && cmdsize >= 16 {
			dataoff := uint32(buf[off+8]) | uint32(buf[off+9])<<8 | uint32(buf[off+10])<<16 | uint32(buf[off+11])<<24
			datasize := uint32(buf[off+12]) | uint32(buf[off+13])<<8 | uint32(buf[off+14])<<16 | uint32(buf[off+15])<<24
			s := int(dataoff)
			e := s + int(datasize)
			if e > len(buf) {
				e = len(buf)
			}
			for k := s; k < e; k++ {
				buf[k] = 0
			}
		}
		// LC_UUID = 0x1B.  16 bytes of UUID follow the 8-byte cmd
		// header.  cmd/internal/buildid excludes this because -B
		// gobuildid derives the UUID from the Go build ID; leaving
		// it in the hash creates a convergence problem.
		if cmd == 0x1B && cmdsize >= 24 {
			s := int(off) + 8
			e := s + 16
			if e > len(buf) {
				e = len(buf)
			}
			for k := s; k < e; k++ {
				buf[k] = 0
			}
		}
		off += cmdsize
	}
}

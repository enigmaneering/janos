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

import "internal/runtime/janos_hash"

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

	// Step 3: platform host build-ID / code signature excludes.
	// Mach-O: LC_CODE_SIGNATURE data + LC_UUID payload.
	// ELF:    .note.gnu.build-id note payload (post-header).
	// Both bail cleanly on non-matching magics.
	janosZeroMachoExcludes(buf)
	janosZeroElfExcludes(buf)

	// Step 4: Go build ID.  Mach-O carries it inside the
	// `\xff Go build ID: "..."\n \xff` marker in .text; ELF carries
	// it as the descriptor payload of the .note.go.buildid section.
	// Try both patterns and zero every occurrence of the extracted
	// ID.
	if idStart, idEnd, ok := janosFindBuildIDInBuf(buf); ok {
		id := append([]byte(nil), buf[idStart:idEnd]...)
		if len(id) > 0 {
			janosZeroAll(buf, id)
		}
	} else if id, ok := janosFindElfGoBuildID(buf); ok && len(id) > 0 {
		// Copy id out before zeroing (zeroAll mutates the source
		// bytes if the pattern overlaps its own location).
		idCopy := append([]byte(nil), id...)
		janosZeroAll(buf, idCopy)
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

// janosZeroElfExcludes parses buf's ELF header (if present) and
// zeros the payload of the .note.gnu.build-id section, skipping the
// 16-byte note "GNU\x00" header — the same range cmd/internal/build
// id.FindAndHash excludes.  Under -B gobuildid (default on Linux),
// the GNU note is derived from the Go build ID, so including it in
// the identity hash creates the same convergence problem the Mach-O
// LC_UUID exclusion solves.
//
// Only ELF64 little-endian inputs are handled — Go binaries on
// supported architectures (amd64, arm64, riscv64, ppc64le) all
// match.  Non-ELF, ELF32, or big-endian inputs are silently ignored.
func janosZeroElfExcludes(buf []byte) {
	secOff, secSize, ok := janosFindElfSection(buf, ".note.gnu.build-id")
	if !ok || secSize < 16 {
		return
	}
	s := secOff + 16
	e := secOff + secSize
	if e > uint64(len(buf)) {
		e = uint64(len(buf))
	}
	for k := s; k < e; k++ {
		buf[k] = 0
	}
}

// janosFindElfGoBuildID looks for the .note.go.buildid section and
// returns a slice pointing to the ID bytes inside its descriptor.
// Unlike Mach-O binaries, Linux/ELF Go binaries do not embed the
// `\xff Go build ID: "..."` marker in .text — the ID lives only in
// the ELF note section, formatted as:
//
//	  0: n_namesz (u32 LE) = 4    (len of "Go\x00\x00")
//	  4: n_descsz (u32 LE) = len(buildID)
//	  8: n_type   (u32 LE)         (Go's private tag value)
//	 12: name     ("Go\x00\x00")   (4 bytes, aligned)
//	 16: descriptor                (n_descsz bytes = the ID)
//
// Returns (idBytes, true) on success; (nil, false) if the section
// isn't present or the note format doesn't parse.
func janosFindElfGoBuildID(buf []byte) ([]byte, bool) {
	secOff, secSize, ok := janosFindElfSection(buf, ".note.go.buildid")
	if !ok || secSize < 16 {
		return nil, false
	}
	if secOff+secSize > uint64(len(buf)) {
		return nil, false
	}
	namesz := janosU32LE(buf[secOff:])
	descsz := janosU32LE(buf[secOff+4:])
	if namesz != 4 || descsz == 0 {
		return nil, false
	}
	// Name lives at secOff+12 for 4 bytes; descriptor at secOff+16.
	if secOff+16+uint64(descsz) > secOff+secSize {
		return nil, false
	}
	return buf[secOff+16 : secOff+16+uint64(descsz)], true
}

// janosFindElfSection walks the ELF64 LE section header table and
// returns the (file offset, size) of the section whose name matches
// target.  Returns (_, _, false) on any parse failure or when the
// section is absent.  Callers must not treat the returned range as
// valid without a size check.
func janosFindElfSection(buf []byte, target string) (uint64, uint64, bool) {
	if len(buf) < 64 {
		return 0, 0, false
	}
	// e_ident magic: 0x7F 'E' 'L' 'F'.
	if buf[0] != 0x7F || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F' {
		return 0, 0, false
	}
	// EI_CLASS: 2 = ELFCLASS64; EI_DATA: 1 = ELFDATA2LSB.
	if buf[4] != 2 || buf[5] != 1 {
		return 0, 0, false
	}
	shoff := janosU64LE(buf[40:])
	shentsize := uint64(janosU16LE(buf[58:]))
	shnum := uint64(janosU16LE(buf[60:]))
	shstrndx := uint64(janosU16LE(buf[62:]))
	if shentsize < 64 || shnum == 0 || shstrndx >= shnum {
		return 0, 0, false
	}
	if shoff+shnum*shentsize > uint64(len(buf)) {
		return 0, 0, false
	}
	strTabHdrOff := shoff + shstrndx*shentsize
	strTabOff := janosU64LE(buf[strTabHdrOff+24:])
	strTabSize := janosU64LE(buf[strTabHdrOff+32:])
	if strTabOff+strTabSize > uint64(len(buf)) {
		return 0, 0, false
	}

	for i := uint64(0); i < shnum; i++ {
		hdrOff := shoff + i*shentsize
		nameIdx := uint64(janosU32LE(buf[hdrOff:]))
		if nameIdx >= strTabSize {
			continue
		}
		nameStart := strTabOff + nameIdx
		if nameStart+uint64(len(target))+1 > uint64(len(buf)) {
			continue
		}
		match := true
		for k := 0; k < len(target); k++ {
			if buf[nameStart+uint64(k)] != target[k] {
				match = false
				break
			}
		}
		if !match || buf[nameStart+uint64(len(target))] != 0 {
			continue
		}
		return janosU64LE(buf[hdrOff+24:]), janosU64LE(buf[hdrOff+32:]), true
	}
	return 0, 0, false
}

// janosU16LE, janosU32LE, janosU64LE read little-endian unsigned
// integers from the front of b.  Callers ensure b has enough bytes.
func janosU16LE(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}
func janosU32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func janosU64LE(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

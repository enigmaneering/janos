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
//	- The JANOSCRT slot region is zeroed.  (Signing something
//	  containing its own signature is impossible.)
//	- The janosExpected*PubKey byte regions are zeroed.  The diviner
//	  hashes ctxt.Out.Data() BEFORE calling patchRuntimeKey, so
//	  those regions still hold the undivined-sentinel string at
//	  signing time; the runtime sees the patched pubkeys at boot
//	  time.  Zeroing on both sides removes the disagreement.
//	- Every occurrence of the Go build ID string is zeroed.
//	  cmd/go rewrites the build ID between cmd/link and the on-disk
//	  file, so its bytes differ between the diviner's view and the
//	  runtime's.
//	- The Mach-O code signature blob is excluded.  cmd/go recomputes
//	  it whenever it rewrites the build ID.  On ELF/PE the analog
//	  regions (.note.gnu.build-id, PE authenticode) are excluded by
//	  the corresponding per-platform reader.
//
// The exclusion logic mirrors cmd/internal/buildid.FindAndHash so
// the diviner (which calls FindAndHash directly) and the runtime
// (which reimplements the same shape here) produce identical
// digests.  Any drift between the two is a divined-boot bug.
//
// Per-target readers live in janos_selfhash_{darwin,linux,windows,
// stub}.go and call janosHashExecutable with a fresh open of the
// running binary's on-disk file.

package runtime

import (
	"internal/runtime/janos_hash"
	"unsafe"
)

// janosStoreBinaryHash finishes a per-platform self-hash run: given the
// completed SHA-256 digest, it writes both the hash and TrustSelfAttested
// onto the current g's provenance.
//
//go:nosplit
func janosStoreBinaryHash(digest [32]byte) {
	gp := getg()
	gp.provenance.binaryHash = digest
	gp.provenance.trustLevel = TrustSelfAttested
}

// janosSelfHashBufSize is the chunk size the streaming reader uses.
// Kept small enough that a package-level buffer (janosSelfHashScratch
// below) lands in .noptrbss without dominating memory profiles.
const janosSelfHashBufSize = 32 * 1024

// janosSelfHashScratch is the streaming buffer for self-hashing.
// Lives in BSS — no schedinit heap allocation.  Only one janos
// self-hash pass runs per process (from schedinit), so a single
// package-level array is safe.
var janosSelfHashScratch [janosSelfHashBufSize]byte

// janosSelfHashPass2Scratch is a second BSS chunk of the same
// size, used for pass-2 masking (so we don't have to overwrite
// pass-1 state).
var janosSelfHashPass2Scratch [janosSelfHashBufSize]byte

// janosGoBuildIDMarker is the byte sequence cmd/link writes right
// before the Go build ID string (in the "go buildid" data symbol):
//
//	"\xff Go build ID: "
//
// The ID string is quoted, so it starts with the opening `"` right
// after this marker.
var janosGoBuildIDMarker = [16]byte{
	0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', ' ', 'I', 'D', ':', ' ', '"',
}

// janosSelfHashOpener is the per-platform hook that opens the
// running binary's on-disk file and returns a file descriptor.
// Returns -1 if the binary can't be opened.  The two-pass hasher
// calls the opener once per pass.
type janosSelfHashOpener func() int32

// janosSelfHashExcludeRange records one [start, end) byte range to
// exclude from the running self-hash.
type janosSelfHashExcludeRange struct {
	start int64
	end   int64
}

// janosSelfHashState holds per-pass state during self-hashing.
type janosSelfHashState struct {
	// buildIDBuf holds up to 128 bytes of the extracted Go build ID
	// string (empty if not found).  Used in pass 2 to zero every
	// occurrence of the ID during hashing.
	buildIDBuf [128]byte
	buildIDLen int

	// exclude holds the discovered exclusion ranges from pass 1.
	// Cap keeps the slice on the stack (Go's escape analysis).
	exclude    [16]janosSelfHashExcludeRange
	excludeLen int
}

// janosHashExecutable runs the two-pass streaming self-hash using
// the given opener.  Pass 1 scans for exclusion ranges (slot,
// expected pubkey positions, Mach-O code signature, Go build ID
// marker).  Pass 2 re-streams the file, zeros the exclusion ranges
// and every occurrence of the extracted build ID, and feeds the
// result to SHA-256.  Returns the digest on success; janos-
// StoreBinaryHash is left uncalled on any I/O failure so the g's
// TrustLevel stays at TrustNone.
func janosHashExecutable(opener janosSelfHashOpener) ([32]byte, bool) {
	var st janosSelfHashState

	// Pass 1: discover exclusion ranges.
	if !janosSelfHashPass1(opener, &st) {
		return [32]byte{}, false
	}

	// Pass 2: mask + hash.
	digest, ok := janosSelfHashPass2(opener, &st)
	if !ok {
		return [32]byte{}, false
	}
	return digest, true
}

// janosSelfHashPass1 opens the file, streams through it, and
// records exclusion ranges in st.
func janosSelfHashPass1(opener janosSelfHashOpener, st *janosSelfHashState) bool {
	fd := opener()
	if fd < 0 {
		return false
	}
	defer closefd(fd)

	buf := janosSelfHashScratch[:]
	const lookback = 128
	// Filled portion of buf that we haven't yet scanned past.  We
	// keep a 128-byte tail as look-back for the next chunk so
	// patterns spanning read boundaries are found.
	head := 0     // start of unscanned region within buf
	filled := 0   // total bytes in buf (head..filled)
	fileOff := int64(0)
	var machoHead [4096]byte
	machoHeadLen := 0

	for {
		n := read(fd, unsafe.Pointer(&buf[filled]), int32(len(buf)-filled))
		if n < 0 {
			return false
		}
		if n == 0 {
			// EOF — scan the last window.
			janosScanChunk(buf[:filled], fileOff-int64(filled-head), st)
			break
		}
		filled += int(n)

		// Save first 4 KiB (starting from file offset 0) into
		// machoHead for later Mach-O header parsing.  fileOff at
		// this point in the loop still refers to the *next* byte
		// that will leave buf via the scanEnd feed below, so the
		// buffer position of the byte we want is head + (needed
		// - (fileOff - int64(head))).  Simpler: for the FIRST
		// iteration only, buf[head:filled] IS from file offset 0
		// onward, so copy directly.
		if machoHeadLen < len(machoHead) && fileOff == 0 {
			available := filled - head
			need := len(machoHead) - machoHeadLen
			take := available
			if take > need {
				take = need
			}
			for k := 0; k < take; k++ {
				machoHead[machoHeadLen+k] = buf[head+k]
			}
			machoHeadLen += take
		}

		// Scan buf[head:filled-lookback], leaving lookback bytes
		// unread for next iteration.
		scanEnd := filled - lookback
		if scanEnd < head {
			scanEnd = head
		}
		if n == int32(len(buf)-filled+int(n)) {
			// buf was empty going in; adjust nothing
		}
		janosScanChunk(buf[head:scanEnd], fileOff-int64(head), st)
		fileOff += int64(scanEnd - head)

		// Slide the trailing lookback bytes to the front.
		tail := filled - scanEnd
		if tail > 0 {
			copy(buf[:tail], buf[scanEnd:filled])
		}
		head = 0
		filled = tail
	}

	// Parse the captured Mach-O header for LC_CODE_SIGNATURE.
	janosParseMachoHeaderForCodesig(machoHead[:machoHeadLen], fileOff, st)

	return true
}

// janosScanChunk searches buf (which represents file bytes at
// [chunkFileOff .. chunkFileOff+len(buf))) for interesting patterns
// and appends exclusion ranges to st.
func janosScanChunk(buf []byte, chunkFileOff int64, st *janosSelfHashState) {
	// JANOSCRT divined slot magic: "JANOSCRT" + \x01 + count(1..8) + 6 zeros.
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
		janosSelfHashAddExclude(st, chunkFileOff+int64(i), chunkFileOff+int64(i)+2048)
	}

	// Go build ID marker: `\xff Go build ID: "..." \n \xff`.  We
	// only accept the marker if the closing `"\n \xff` suffix
	// follows the ID, so we don't get fooled by unrelated bytes
	// starting with the marker prefix but bearing binary garbage
	// inside the quotes.
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
		if end+4 > len(buf) {
			continue
		}
		// Suffix must be `"`, `\n`, ` `, `\xff`.
		if buf[end] != '"' || buf[end+1] != '\n' || buf[end+2] != ' ' || buf[end+3] != 0xff {
			continue
		}
		idLen := end - (i + 16)
		if idLen > 0 && idLen <= len(st.buildIDBuf) && st.buildIDLen == 0 {
			for k := 0; k < idLen; k++ {
				st.buildIDBuf[k] = buf[i+16+k]
			}
			st.buildIDLen = idLen
		}
	}

	// Guild + Release expected-key positions.  On the diviner side,
	// hashInput has sentinel bytes at those positions (patchRuntimeKey
	// runs after the hash is computed) and is zeroed via janosZero-
	// Symbol.  On the runtime side, the on-disk file has the divined
	// pubkey bytes there; we zero at every occurrence of the current
	// janosExpectedGuild/ReleasePubKey bytes to match.  The sentinel
	// *constant* symbols (janosExpectedGuild/ReleaseUndivinedSentinel)
	// are deliberately NOT zeroed — the diviner leaves those
	// unchanged too, so both sides carry identical sentinel bytes
	// through to the hash.
	janosScanPattern(buf, chunkFileOff, janosExpectedGuildPubKey[:], st)
	janosScanPattern(buf, chunkFileOff, janosExpectedReleasePubKey[:], st)
}

// janosScanPattern finds every occurrence of pattern in buf and
// records the corresponding [file-offset, file-offset+len(pattern))
// range as an exclusion.
func janosScanPattern(buf []byte, chunkFileOff int64, pattern []byte, st *janosSelfHashState) {
	if len(pattern) == 0 || len(pattern) > len(buf) {
		return
	}
	for i := 0; i+len(pattern) <= len(buf); i++ {
		if buf[i] != pattern[0] {
			continue
		}
		match := true
		for j := 1; j < len(pattern); j++ {
			if buf[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		janosSelfHashAddExclude(st, chunkFileOff+int64(i), chunkFileOff+int64(i+len(pattern)))
	}
}

// janosSelfHashAddExclude appends a range to st.exclude, dropping it
// if the fixed array is already full.
func janosSelfHashAddExclude(st *janosSelfHashState, start, end int64) {
	if st.excludeLen >= len(st.exclude) {
		return
	}
	st.exclude[st.excludeLen] = janosSelfHashExcludeRange{start: start, end: end}
	st.excludeLen++
}

// janosParseMachoHeaderForCodesig parses the first ~4 KiB of buf as
// a Mach-O header and appends the LC_CODE_SIGNATURE dataoff/datasize
// range to st.exclude if found.  Returns silently on non-Mach-O
// input (linux/windows), where the ELF/PE reader has already handled
// its host-buildid analog earlier.
func janosParseMachoHeaderForCodesig(buf []byte, fileSize int64, st *janosSelfHashState) {
	if len(buf) < 32 {
		return
	}
	// Mach-O 64-bit magic: 0xFEEDFACF (LE bytes: CF FA ED FE).
	if !(buf[0] == 0xCF && buf[1] == 0xFA && buf[2] == 0xED && buf[3] == 0xFE) {
		return
	}
	ncmds := uint32(buf[16]) | uint32(buf[17])<<8 | uint32(buf[18])<<16 | uint32(buf[19])<<24
	sizeofcmds := uint32(buf[20]) | uint32(buf[21])<<8 | uint32(buf[22])<<16 | uint32(buf[23])<<24
	// Load commands start at offset 32 (mach_header_64).
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
			s := int64(dataoff)
			e := s + int64(datasize)
			if s >= 0 && e <= fileSize {
				janosSelfHashAddExclude(st, s, e)
			}
		}
		// LC_UUID = 0x1B.  Mach-O host build ID (16 bytes of UUID
		// data after the 8-byte load command header).  buildid.Find-
		// AndHash excludes this on macOS because with -B gobuildid
		// the UUID is derived from the Go build ID; leaving it in the
		// hash creates a convergence problem.
		if cmd == 0x1B && cmdsize >= 24 {
			cmdOffInFile := int64(off) + 8
			s := cmdOffInFile
			e := s + 16
			janosSelfHashAddExclude(st, s, e)
		}
		off += cmdsize
	}
}

// janosSelfHashPass2 opens the file again, streams through it,
// masks exclusion ranges + every occurrence of the extracted build
// ID, and feeds the result to SHA-256.
func janosSelfHashPass2(opener janosSelfHashOpener, st *janosSelfHashState) ([32]byte, bool) {
	fd := opener()
	if fd < 0 {
		return [32]byte{}, false
	}
	defer closefd(fd)

	var d janos_hash.SHA256
	d.Reset()

	buf := janosSelfHashScratch[:]
	// masked reuses janosSelfHashPass2Scratch for the buffer we
	// actually feed to SHA-256; keeping it separate keeps the mask
	// logic simple even though it doubles our BSS footprint.
	masked := janosSelfHashPass2Scratch[:]
	const lookback = 128
	head := 0
	filled := 0
	fileOff := int64(0)

	for {
		n := read(fd, unsafe.Pointer(&buf[filled]), int32(len(buf)-filled))
		if n < 0 {
			return [32]byte{}, false
		}
		if n == 0 {
			// Final tail: mask whatever's left.
			maskLen := filled - head
			if maskLen > 0 {
				chunkStart := fileOff - int64(head)
				copy(masked[:maskLen], buf[head:filled])
				janosMaskChunk(masked[:maskLen], chunkStart, st)
				d.Write(masked[:maskLen])
			}
			break
		}
		filled += int(n)

		// Feed all but the trailing lookback bytes.
		scanEnd := filled - lookback
		if scanEnd < head {
			scanEnd = head
		}
		if scanEnd > head {
			chunkStart := fileOff - int64(head)
			maskLen := scanEnd - head
			copy(masked[:maskLen], buf[head:scanEnd])
			janosMaskChunk(masked[:maskLen], chunkStart, st)
			d.Write(masked[:maskLen])
			fileOff += int64(maskLen)
		}

		// Slide lookback to front.
		tail := filled - scanEnd
		if tail > 0 {
			copy(buf[:tail], buf[scanEnd:filled])
		}
		head = 0
		filled = tail
	}
	return d.Sum(), true
}

// janosMaskChunk zeroes bytes in chunk that fall inside any
// exclusion range in st, or that match the extracted Go build ID
// string.  chunkFileOff is the file offset at which chunk begins.
func janosMaskChunk(chunk []byte, chunkFileOff int64, st *janosSelfHashState) {
	chunkEnd := chunkFileOff + int64(len(chunk))
	// Exclusion ranges (slot, expected pubkeys, codesig).
	for i := 0; i < st.excludeLen; i++ {
		r := &st.exclude[i]
		if r.end <= chunkFileOff || r.start >= chunkEnd {
			continue
		}
		from := int64(0)
		if chunkFileOff < r.start {
			from = r.start - chunkFileOff
		}
		to := int64(len(chunk))
		if chunkEnd > r.end {
			to = r.end - chunkFileOff
		}
		for j := from; j < to; j++ {
			chunk[j] = 0
		}
	}
	// Zero every occurrence of the build ID string.  Because build
	// ID lengths are ~50 bytes and can span chunk boundaries in
	// theory, but pass 2 uses the same lookback as pass 1 (128
	// bytes ≫ ID length), any complete match in the file lies
	// entirely within some chunk.
	if st.buildIDLen == 0 {
		return
	}
	id := st.buildIDBuf[:st.buildIDLen]
	for i := 0; i+len(id) <= len(chunk); i++ {
		if chunk[i] != id[0] {
			continue
		}
		match := true
		for j := 1; j < len(id); j++ {
			if chunk[i+j] != id[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		for j := 0; j < len(id); j++ {
			chunk[i+j] = 0
		}
		i += len(id) - 1
	}
}

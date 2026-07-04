package runtime_test

import (
	"runtime"
	"testing"
)

// The tests below exercise runtime.janosCanonicalHash (exposed as
// runtime.JanosCanonicalHashForTest) against synthetic Mach-O byte
// buffers.  Each fixture embeds a known layout — JANOSCRT slot at
// slotOff, Guild/Release pubkey patterns at pubkey offsets, a Go
// build-ID marker at buildIDOff, and LC_CODE_SIGNATURE + LC_UUID
// load commands with known data ranges.  The tests compute the
// expected digest by manually zeroing the same regions and running
// SHA-256; a match confirms the runtime's canonicaliser touches
// exactly those bytes and no others.
//
// The tests do NOT drive the executable-hashing path (open + mmap
// + read the actual running binary).  That's the darwin/linux
// reader glue and is exercised implicitly by every janos-runtime
// test binary at schedinit time; a mismatch would surface as
// TrustSelfAttested / TrustJanosReleased ambiguity that other
// tests already catch.

// selfHashFixture describes a synthetic Mach-O buffer built for
// self-hash canonicalisation testing.
type selfHashFixture struct {
	buf []byte

	// slotOff is the byte offset of the JANOSCRT slot's 'J', or -1
	// if the buffer has no slot.  divined controls whether the
	// slot's version byte is 1 (divined) or 0 (undivined).
	slotOff int
	divined bool

	// guildOffs and releaseOffs are the byte offsets where the
	// guild and release pubkey patterns were embedded (once per
	// entry — a two-entry list tests multi-occurrence zeroing).
	// Empty means the pattern wasn't embedded at all.  The pubkey
	// patterns themselves live in guildPat / releasePat.
	guildPat, releasePat [64]byte
	guildOffs            []int
	releaseOffs          []int

	// buildIDOff is the byte offset of the marker's '\xff' byte, or
	// -1 if the buffer has no marker.  buildIDID is the ID string
	// that appears inside the quotes; every occurrence of it in the
	// buffer is expected to be zeroed.
	buildIDOff int
	buildIDID  []byte

	// codesigOff / codesigSize describe the LC_CODE_SIGNATURE data
	// range in the buffer.  -1 / 0 means the load command isn't
	// present.  uuidOff is the offset of the 16-byte UUID payload
	// (i.e., the load command's cmd header + 8), or -1.
	codesigOff  int
	codesigSize int
	uuidOff     int

	// elfNoteOff / elfNoteSize describe the range the ELF exclusion
	// path zeros: everything AFTER the 16-byte GNU note header in
	// the .note.gnu.build-id section.  -1 / 0 means no ELF header
	// was embedded.
	elfNoteOff  int
	elfNoteSize int

	// elfGoBuildIDValue holds the buildID string embedded in the
	// .note.go.buildid section (and also duplicated elsewhere in
	// the buffer to exercise multi-occurrence zeroing).  nil if the
	// fixture didn't request the ELF Go buildID branch.
	elfGoBuildIDValue []byte
}

// buildFixture constructs a Mach-O-shaped byte buffer with the
// features controlled by the opts.  It returns a description of
// what was embedded so the test can compute the expected digest.
type fixtureOpts struct {
	machO            bool  // if true, prepend a Mach-O 64-bit header
	elf              bool  // if true, prepend an ELF64 LE header (mutually exclusive with machO)
	includeSlot      bool  // if true, embed a JANOSCRT slot
	divinedSlot      bool  // if includeSlot: version 1 (divined) vs version 0 (undivined)
	pubkeyReps       int   // number of times to embed each pubkey (0, 1, or 2)
	includeBuildID   bool  // if true, embed a valid Go build ID marker
	garbageBuildID   bool  // if true, embed a marker with bad suffix (should be ignored)
	includeCodesig      bool  // Mach-O only: if true, LC_CODE_SIGNATURE present, blob at end
	includeUUID         bool  // Mach-O only: if true, LC_UUID present
	includeElfNote      bool  // ELF only: if true, .note.gnu.build-id section present
	includeElfGoBuildID bool  // ELF only: if true, .note.go.buildid section present + ID string embedded elsewhere in buf
	bufSize             int   // total buffer size
}

// selfHashFixture also tracks the ELF host-buildID note range when
// the fixture is ELF-shaped.  These fields are separate from the
// Mach-O codesigOff / uuidOff so an ELF fixture doesn't accidentally
// share expectation slots with a Mach-O one.
//
// (elfBuildIDOff, elfBuildIDLen) is the byte range zeroed by the
// runtime's ELF exclusion path (skipping the 16-byte GNU note
// header).

func buildFixture(opts fixtureOpts) selfHashFixture {
	if opts.bufSize == 0 {
		opts.bufSize = 32 * 1024
	}
	f := selfHashFixture{
		buf:        make([]byte, opts.bufSize),
		slotOff:    -1,
		buildIDOff: -1,
		codesigOff: -1,
		uuidOff:    -1,
		elfNoteOff: -1,
	}
	// Fill with a distinctive pattern so a stray un-zeroed byte
	// isn't a zero coincidence.
	for i := range f.buf {
		f.buf[i] = byte(i * 7)
	}
	// Two distinctive pubkey patterns; picked from within an ASCII
	// range that isn't printable so they don't collide with the
	// build-ID string.
	for i := 0; i < 64; i++ {
		f.guildPat[i] = 0xA0 + byte(i)
		f.releasePat[i] = 0xE0 + byte(i)
	}

	// Mach-O 64-bit header at offset 0 (32 bytes).
	//
	//	  0: magic       = 0xFEEDFACF (LE bytes: CF FA ED FE)
	//	  4: cputype     = 0x0100000C (arm64, arbitrary)
	//	  8: cpusubtype  = 0
	//	 12: filetype    = 2 (MH_EXECUTE)
	//	 16: ncmds       = X (count of load commands)
	//	 20: sizeofcmds  = Y (total size of load commands)
	//	 24: flags       = 0
	//	 28: reserved    = 0
	//
	// Load commands start at offset 32.  We use LC_UUID (0x1B,
	// cmdsize=24) and LC_CODE_SIGNATURE (0x1D, cmdsize=16) if
	// requested.  Each is written just after the previous one.
	loadOff := 32
	ncmds := uint32(0)
	sizeofcmds := uint32(0)

	if opts.machO {
		// Magic (little-endian 0xFEEDFACF).
		f.buf[0] = 0xCF
		f.buf[1] = 0xFA
		f.buf[2] = 0xED
		f.buf[3] = 0xFE
		// cputype, subtype, filetype
		writeUint32LE(f.buf[4:], 0x0100000C)
		writeUint32LE(f.buf[8:], 0)
		writeUint32LE(f.buf[12:], 2)
		// ncmds + sizeofcmds are filled in after we know them; skip.
	} else if opts.elf {
		// Minimal ELF64 little-endian header + a small section table.
		// Sections we care about:
		//   [0] SHT_NULL
		//   [1] .shstrtab
		//   [2] .note.gnu.build-id  (if includeElfNote)
		//   [3] .note.go.buildid    (if includeElfGoBuildID)
		//
		// Layout in the buffer:
		//	   0..64     ELF header
		//	  64..320    section header table (4 × 64-byte entries)
		//	 320..416    .shstrtab data (up to 48 bytes; pad reserved)
		//	 416..464    .note.gnu.build-id (16+32 = 48 bytes)
		//	 464..512    .note.go.buildid (16-byte hdr + name "Go\0\0"
		//	            + 16-byte ID = 32 bytes)
		f.buf[0] = 0x7F
		f.buf[1] = 'E'
		f.buf[2] = 'L'
		f.buf[3] = 'F'
		f.buf[4] = 2 // ELFCLASS64
		f.buf[5] = 1 // ELFDATA2LSB
		f.buf[6] = 1 // EV_CURRENT
		writeUint16LE(f.buf[16:], 2)    // e_type = ET_EXEC
		writeUint16LE(f.buf[18:], 0xB7) // e_machine = EM_AARCH64
		writeUint32LE(f.buf[20:], 1)    // e_version

		var shnum uint16 = 2 // NULL + shstrtab
		if opts.includeElfNote {
			shnum++
		}
		if opts.includeElfGoBuildID {
			shnum++
		}
		const shentsize = 64
		shoff := uint64(64)
		writeUint64LE(f.buf[40:], shoff)
		writeUint16LE(f.buf[58:], shentsize)
		writeUint16LE(f.buf[60:], shnum)
		writeUint16LE(f.buf[62:], 1) // e_shstrndx = 1 (.shstrtab)

		// .shstrtab data at offset 320.  Layout:
		//    0: \0
		//    1: ".shstrtab\0"                       -> starts at 1
		//   11: ".note.gnu.build-id\0"              -> starts at 11
		//   30: ".note.go.buildid\0"                -> starts at 30
		shstrtabOff := uint64(320)
		f.buf[shstrtabOff+0] = 0
		copy(f.buf[shstrtabOff+1:], ".shstrtab")
		f.buf[shstrtabOff+1+9] = 0
		copy(f.buf[shstrtabOff+11:], ".note.gnu.build-id")
		f.buf[shstrtabOff+11+18] = 0
		copy(f.buf[shstrtabOff+30:], ".note.go.buildid")
		f.buf[shstrtabOff+30+16] = 0
		shstrtabSize := uint64(47)

		// Section header [1]: .shstrtab
		hdr1 := shoff + 1*shentsize
		writeUint32LE(f.buf[hdr1:], 1)                // sh_name = 1
		writeUint32LE(f.buf[hdr1+4:], 3)              // SHT_STRTAB
		writeUint64LE(f.buf[hdr1+24:], shstrtabOff)   // sh_offset
		writeUint64LE(f.buf[hdr1+32:], shstrtabSize)  // sh_size

		nextHdrIdx := uint64(2)
		if opts.includeElfNote {
			hdr := shoff + nextHdrIdx*shentsize
			noteOff := uint64(416)
			writeUint32LE(f.buf[noteOff:], 4)    // n_namesz
			writeUint32LE(f.buf[noteOff+4:], 32) // n_descsz
			writeUint32LE(f.buf[noteOff+8:], 3)  // NT_GNU_BUILD_ID
			f.buf[noteOff+12] = 'G'
			f.buf[noteOff+13] = 'N'
			f.buf[noteOff+14] = 'U'
			f.buf[noteOff+15] = 0
			for i := uint64(0); i < 32; i++ {
				f.buf[noteOff+16+i] = 0x77
			}
			writeUint32LE(f.buf[hdr:], 11)          // sh_name = 11 (".note.gnu.build-id")
			writeUint32LE(f.buf[hdr+4:], 7)         // SHT_NOTE
			writeUint64LE(f.buf[hdr+24:], noteOff)
			writeUint64LE(f.buf[hdr+32:], 48)       // 16-byte hdr + 32 descriptor
			f.elfNoteOff = int(noteOff + 16)
			f.elfNoteSize = 32
			nextHdrIdx++
		}

		if opts.includeElfGoBuildID {
			hdr := shoff + nextHdrIdx*shentsize
			goNoteOff := uint64(464)
			// n_namesz = 4 ("Go\0\0"), n_descsz = 16 (small ID for
			// the fixture), n_type = arbitrary (Go uses 4).
			writeUint32LE(f.buf[goNoteOff:], 4)
			writeUint32LE(f.buf[goNoteOff+4:], 16)
			writeUint32LE(f.buf[goNoteOff+8:], 4)
			f.buf[goNoteOff+12] = 'G'
			f.buf[goNoteOff+13] = 'o'
			f.buf[goNoteOff+14] = 0
			f.buf[goNoteOff+15] = 0
			// A distinctive 16-byte Go build ID value.
			f.elfGoBuildIDValue = []byte("goBUILDidTEST_1x")
			copy(f.buf[goNoteOff+16:], f.elfGoBuildIDValue)
			writeUint32LE(f.buf[hdr:], 30)           // sh_name = 30 (".note.go.buildid")
			writeUint32LE(f.buf[hdr+4:], 7)          // SHT_NOTE
			writeUint64LE(f.buf[hdr+24:], goNoteOff)
			writeUint64LE(f.buf[hdr+32:], 32)        // 16 hdr + 16 descriptor
			nextHdrIdx++
		}
		loadOff = 512
	} else {
		// Non-Mach-O, non-ELF input: put arbitrary bytes at the
		// start.  Both parsers must decline to touch anything.
		f.buf[0] = 0x7F
		f.buf[1] = 'X' // deliberately not 'E'
		f.buf[2] = 'Y'
		f.buf[3] = 'Z'
	}

	if opts.machO && opts.includeUUID {
		// LC_UUID = 0x1B, cmdsize = 24, 16 bytes of UUID payload.
		writeUint32LE(f.buf[loadOff:], 0x1B)
		writeUint32LE(f.buf[loadOff+4:], 24)
		// UUID payload at loadOff+8 .. loadOff+24 (16 bytes).
		for i := 0; i < 16; i++ {
			f.buf[loadOff+8+i] = byte(0x11 + i)
		}
		f.uuidOff = loadOff + 8
		loadOff += 24
		ncmds++
		sizeofcmds += 24
	}

	if opts.machO && opts.includeCodesig {
		// LC_CODE_SIGNATURE = 0x1D, cmdsize = 16.
		// dataoff at loadOff+8, datasize at loadOff+12.  The blob
		// itself lives at the end of the buffer, sized to 512 bytes.
		codesigSize := 512
		codesigOff := opts.bufSize - codesigSize
		writeUint32LE(f.buf[loadOff:], 0x1D)
		writeUint32LE(f.buf[loadOff+4:], 16)
		writeUint32LE(f.buf[loadOff+8:], uint32(codesigOff))
		writeUint32LE(f.buf[loadOff+12:], uint32(codesigSize))
		// Put some distinctive bytes in the blob so we can tell it
		// was zeroed.
		for i := 0; i < codesigSize; i++ {
			f.buf[codesigOff+i] = 0x55
		}
		f.codesigOff = codesigOff
		f.codesigSize = codesigSize
		loadOff += 16
		ncmds++
		sizeofcmds += 16
	}

	if opts.machO {
		writeUint32LE(f.buf[16:], ncmds)
		writeUint32LE(f.buf[20:], sizeofcmds)
	}

	// After the load commands, embed the "interesting" content.
	// Layout inside the tail of the buffer:
	//   contentStart: expected pubkey embed(s)
	//   +64/128:      build-ID marker (if requested)
	//   +...:         JANOSCRT slot (if requested)
	//
	// Placements are chosen so nothing collides with the Mach-O
	// header or the trailing codesig blob.
	contentStart := loadOff + 128
	if opts.pubkeyReps > 0 {
		off := contentStart
		for rep := 0; rep < opts.pubkeyReps; rep++ {
			copy(f.buf[off:off+64], f.guildPat[:])
			f.guildOffs = append(f.guildOffs, off)
			off += 128
			copy(f.buf[off:off+64], f.releasePat[:])
			f.releaseOffs = append(f.releaseOffs, off)
			off += 128
		}
		contentStart = off + 64
	}

	// If the ELF fixture has a Go build ID, embed one extra copy of
	// its value at a content position so the runtime's find-and-zero
	// path is exercised at more than just the note descriptor.  The
	// note-descriptor copy is zeroed too (the ID pattern is unique
	// and its bytes appear everywhere they were placed).
	if len(f.elfGoBuildIDValue) > 0 {
		copy(f.buf[contentStart:], f.elfGoBuildIDValue)
		contentStart += len(f.elfGoBuildIDValue) + 32
	}

	if opts.includeBuildID || opts.garbageBuildID {
		f.buildIDOff = contentStart
		// `\xff Go build ID: "TESTBUILDID..."\n \xff`
		marker := []byte{0xff, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', ' ', 'I', 'D', ':', ' ', '"'}
		copy(f.buf[f.buildIDOff:], marker)
		f.buildIDID = []byte("TESTBUILDID_A1B2C3D4")
		copy(f.buf[f.buildIDOff+len(marker):], f.buildIDID)
		end := f.buildIDOff + len(marker) + len(f.buildIDID)
		if opts.garbageBuildID {
			// Suffix that fails the `"\n \xff` check — use `"xx `.
			f.buf[end] = '"'
			f.buf[end+1] = 'x'
			f.buf[end+2] = 'x'
			f.buf[end+3] = ' '
			f.buildIDOff = -1 // won't be zeroed
		} else {
			f.buf[end] = '"'
			f.buf[end+1] = '\n'
			f.buf[end+2] = ' '
			f.buf[end+3] = 0xff
		}
		contentStart = end + 32
	}

	if opts.includeSlot {
		// Align to 8-byte boundary for readability, then embed the
		// 2 KiB slot with "JANOSCRT" + version + count + reserved,
		// followed by 2032 filler bytes.
		slotOff := (contentStart + 7) &^ 7
		if slotOff+2048 > opts.bufSize-f.codesigSize {
			panic("fixture too small to hold slot")
		}
		copy(f.buf[slotOff:], []byte("JANOSCRT"))
		if opts.divinedSlot {
			f.buf[slotOff+8] = 1 // version 1 = divined
			f.buf[slotOff+9] = 2 // entry_count = 2 (guild + release)
		} else {
			f.buf[slotOff+8] = 0
			f.buf[slotOff+9] = 0
		}
		for i := 10; i < 16; i++ {
			f.buf[slotOff+i] = 0
		}
		// Fill remaining slot bytes with a marker so we can tell
		// they got zeroed by the algorithm.
		for i := 16; i < 2048; i++ {
			f.buf[slotOff+i] = byte(0x33 + (i % 7))
		}
		f.slotOff = slotOff
		f.divined = opts.divinedSlot
	}

	return f
}

// expectedDigest re-runs the same zeroing operations the runtime's
// canonical hasher does — from the test's perspective, using the
// fixture's known layout — then computes SHA-256 of the result.
// The order of zeroing matches janosCanonicalHash exactly.
func expectedDigest(f selfHashFixture) [32]byte {
	buf := make([]byte, len(f.buf))
	copy(buf, f.buf)

	// Step 1: JANOSCRT slot (only if divined).
	if f.slotOff >= 0 && f.divined {
		end := f.slotOff + 2048
		if end > len(buf) {
			end = len(buf)
		}
		for i := f.slotOff; i < end; i++ {
			buf[i] = 0
		}
	}

	// Step 2: pubkey patterns.
	for _, off := range f.guildOffs {
		for j := 0; j < 64; j++ {
			buf[off+j] = 0
		}
	}
	for _, off := range f.releaseOffs {
		for j := 0; j < 64; j++ {
			buf[off+j] = 0
		}
	}

	// Step 3: Mach-O codesig + LC_UUID.
	if f.codesigOff >= 0 {
		for i := f.codesigOff; i < f.codesigOff+f.codesigSize; i++ {
			buf[i] = 0
		}
	}
	if f.uuidOff >= 0 {
		for i := f.uuidOff; i < f.uuidOff+16; i++ {
			buf[i] = 0
		}
	}
	if f.elfNoteOff >= 0 {
		for i := f.elfNoteOff; i < f.elfNoteOff+f.elfNoteSize; i++ {
			buf[i] = 0
		}
	}

	// Step 4: Go build ID (every occurrence of the ID string).
	// On Mach-O fixtures the runtime finds the ID via the
	// `\xff Go build ID: "..."\n \xff` marker; on ELF fixtures via
	// the .note.go.buildid descriptor.  Either way, the algorithm
	// zeros EVERY occurrence of the ID bytes in the buffer.  Our
	// fixtures embed the Mach-O ID once (inside the marker) and the
	// ELF ID at two positions (the note descriptor and one extra
	// stamp elsewhere in content).
	if f.buildIDOff >= 0 {
		zeroAllInBuf(buf, f.buildIDID)
	}
	if len(f.elfGoBuildIDValue) > 0 {
		zeroAllInBuf(buf, f.elfGoBuildIDValue)
	}

	return runtime.JanosSHA256ForTest(buf)
}

// zeroAllInBuf is a test-side copy of the runtime's zeroAll: zeros
// every non-overlapping occurrence of pattern in buf.
func zeroAllInBuf(buf, pattern []byte) {
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

func writeUint16LE(dst []byte, v uint16) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
}

func writeUint32LE(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

func writeUint64LE(dst []byte, v uint64) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
	dst[4] = byte(v >> 32)
	dst[5] = byte(v >> 40)
	dst[6] = byte(v >> 48)
	dst[7] = byte(v >> 56)
}

// TestJanosCanonicalHashDivinedHappy: fully-divined Mach-O fixture
// with a valid slot, one guild + release pubkey embed each, a
// valid build-ID marker, LC_CODE_SIGNATURE, and LC_UUID.  Runtime
// hash must match the manually-computed expected digest.
func TestJanosCanonicalHashDivinedHappy(t *testing.T) {
	f := buildFixture(fixtureOpts{
		machO:          true,
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		includeBuildID: true,
		includeCodesig: true,
		includeUUID:    true,
	})
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashDivinedMultiOccurrence: two occurrences of
// each pubkey pattern.  Both must be zeroed.
func TestJanosCanonicalHashDivinedMultiOccurrence(t *testing.T) {
	f := buildFixture(fixtureOpts{
		machO:          true,
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     2,
		includeBuildID: true,
		includeCodesig: true,
		includeUUID:    true,
	})
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashUndivined: fixture with a JANOSCRT slot but
// version = 0 (undivined).  The slot must NOT be zeroed.  Nothing
// else is embedded, so the digest reduces to plain SHA-256 of the
// fixture bytes.
func TestJanosCanonicalHashUndivined(t *testing.T) {
	f := buildFixture(fixtureOpts{
		machO:       true,
		includeSlot: true,
		divinedSlot: false, // undivined — algorithm should leave it alone
	})
	want := expectedDigest(f) // slotOff is set but f.divined=false, so it isn't zeroed
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashGarbageBuildIDMarker: fixture with a build
// ID marker prefix but a suffix that fails the `"\n \xff` check.
// The algorithm must refuse to zero, so the ID bytes stay in the
// hash.  expectedDigest models the fixture with buildIDOff == -1
// (no zeroing), matching what the runtime should do.
func TestJanosCanonicalHashGarbageBuildIDMarker(t *testing.T) {
	f := buildFixture(fixtureOpts{
		machO:          true,
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		garbageBuildID: true,
		includeCodesig: true,
		includeUUID:    true,
	})
	want := expectedDigest(f) // buildIDOff == -1, so ID stays
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashNonMachONonELF: fixture with a random magic
// that's neither Mach-O nor ELF.  Both parsers must decline; the
// rest of the algorithm (slot / pubkeys / build ID) still runs.
func TestJanosCanonicalHashNonMachONonELF(t *testing.T) {
	f := buildFixture(fixtureOpts{
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		includeBuildID: true,
	})
	// No Mach-O / ELF header, so buildFixture left codesig/uuid/
	// elfNote fields at their -1 sentinels.
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashElfDivinedHappy: ELF64 fixture with a
// .note.gnu.build-id section, valid slot, pubkey embeds, build-ID
// marker.  All the same regions as Mach-O plus the note-payload
// range must be zeroed.
func TestJanosCanonicalHashElfDivinedHappy(t *testing.T) {
	f := buildFixture(fixtureOpts{
		elf:            true,
		includeElfNote: true,
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		includeBuildID: true,
	})
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashElfWithoutNote: ELF64 fixture whose section
// table does NOT include a .note.gnu.build-id section.  The runtime
// must find nothing to zero and produce a digest that matches the
// same fixture with no ELF exclusion applied.
func TestJanosCanonicalHashElfWithoutNote(t *testing.T) {
	f := buildFixture(fixtureOpts{
		elf:            true,
		includeElfNote: false, // no note section — nothing to zero
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		includeBuildID: true,
	})
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

// TestJanosCanonicalHashElfGoBuildID: ELF64 fixture with a
// .note.go.buildid section carrying a distinctive ID plus one extra
// stamp of that ID somewhere else in the buffer.  The runtime must
// extract the ID from the note descriptor and zero every occurrence
// — both the note descriptor and the extra stamp.  This is the code
// path Linux divined boots depend on.
func TestJanosCanonicalHashElfGoBuildID(t *testing.T) {
	f := buildFixture(fixtureOpts{
		elf:                 true,
		includeElfNote:      true, // .note.gnu.build-id present
		includeElfGoBuildID: true, // .note.go.buildid present + one extra stamp
		includeSlot:         true,
		divinedSlot:         true,
		pubkeyReps:          1,
	})
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

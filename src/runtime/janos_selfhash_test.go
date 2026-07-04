// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
}

// buildFixture constructs a Mach-O-shaped byte buffer with the
// features controlled by the opts.  It returns a description of
// what was embedded so the test can compute the expected digest.
type fixtureOpts struct {
	machO            bool  // if false, skip the Mach-O header (produces a plain buffer)
	includeSlot      bool  // if true, embed a JANOSCRT slot
	divinedSlot      bool  // if includeSlot: version 1 (divined) vs version 0 (undivined)
	pubkeyReps       int   // number of times to embed each pubkey (0, 1, or 2)
	includeBuildID   bool  // if true, embed a valid Go build ID marker
	garbageBuildID   bool  // if true, embed a marker with bad suffix (should be ignored)
	includeCodesig   bool  // if true, LC_CODE_SIGNATURE present, blob at end of buffer
	includeUUID      bool  // if true, LC_UUID present
	bufSize          int   // total buffer size
}

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
	} else {
		// Non-Mach-O input: put arbitrary bytes at the start.  The
		// Mach-O parser must decline to touch anything.
		f.buf[0] = 0x7F
		f.buf[1] = 'E'
		f.buf[2] = 'L'
		f.buf[3] = 'F'
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

	// Step 4: Go build ID (every occurrence of the ID string).
	if f.buildIDOff >= 0 {
		// The ID lives at f.buildIDOff + 16 .. + 16 + len(id).  In
		// the fixture it appears exactly once at that position.
		// The runtime searches for any occurrence of the ID string,
		// so this test computation should mirror that — but our
		// fixture only puts the ID at one place, so a single zero
		// is correct.
		start := f.buildIDOff + 16
		for j := 0; j < len(f.buildIDID); j++ {
			buf[start+j] = 0
		}
	}

	return runtime.JanosSHA256ForTest(buf)
}

func writeUint32LE(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
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

// TestJanosCanonicalHashNonMachO: fixture with an ELF-like magic
// instead of Mach-O.  The Mach-O parser must decline — no LC_CODE_
// SIGNATURE or LC_UUID zeroing — and the rest of the algorithm
// (slot / pubkeys / build ID) still runs.
func TestJanosCanonicalHashNonMachO(t *testing.T) {
	f := buildFixture(fixtureOpts{
		machO:          false,
		includeSlot:    true,
		divinedSlot:    true,
		pubkeyReps:     1,
		includeBuildID: true,
	})
	// No Mach-O header, so buildFixture skipped both LC_UUID and
	// LC_CODE_SIGNATURE — codesigOff and uuidOff are already -1.
	want := expectedDigest(f)
	got := runtime.JanosCanonicalHashForTest(f.buf, f.guildPat[:], f.releasePat[:])
	if got != want {
		t.Errorf("hash mismatch\n want %x\n got  %x", want, got)
	}
}

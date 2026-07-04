package runtime_test

import (
	"runtime"
	"testing"
	"unsafe"
)

// TestJanosSanitizeSweepZeroesFreedSmallObjects allocates many small
// objects, fills them with a distinctive non-zero byte pattern,
// records their addresses, drops the references, and forces two GC
// cycles.  With JanOS zero-on-sweep active, none of the recorded
// addresses should still contain the pattern — every slot must
// either read as zero (sanitized, unallocated) or have been reused
// (in which case the allocator zeroed it before handing it out).
//
// Upstream Go without sanitize would keep the pattern in most of the
// unreused slots, since sweep never touches payload bytes and
// mallocgc's lazy-zero fires only on re-allocation.
func TestJanosSanitizeSweepZeroesFreedSmallObjects(t *testing.T) {
	const (
		n       = 512
		payload = 96
		pattern = 0xA5
	)

	// Use a size class the runtime doesn't churn on: 96-byte
	// objects sit in a distinct size class from the tiny/small
	// churn the scheduler generates during a test.
	type block [payload]byte
	addrs := make([]uintptr, n)
	holders := make([]*block, n)

	for i := range holders {
		b := new(block)
		for j := range b {
			b[j] = pattern
		}
		holders[i] = b
		addrs[i] = uintptr(unsafe.Pointer(b))
	}
	runtime.KeepAlive(holders)

	// Drop every strong reference, then force two GC cycles.
	// The first cycle marks; the second guarantees sweep of any
	// span the first cycle only just marked.
	for i := range holders {
		holders[i] = nil
	}
	holders = nil
	runtime.GC()
	runtime.GC()

	// Any recorded slot that still contains the pattern means
	// sanitize did not fire (nor was the slot reused by an
	// allocator that zeroed it).  Either way it is a security-
	// visible leak of freed plaintext.
	var stillLeaked int
	for _, a := range addrs {
		b := (*block)(unsafe.Pointer(a))
		full := true
		for _, v := range b {
			if v != pattern {
				full = false
				break
			}
		}
		if full {
			stillLeaked++
		}
	}
	if stillLeaked != 0 {
		t.Errorf("janos sanitize: %d/%d freed 96-byte slots still hold pattern 0x%02X after GC; sweep-time zero did not fire",
			stillLeaked, n, pattern)
	}
}

// TestJanosSanitizeStackZeroesOnFree runs a goroutine that writes a
// distinctive byte pattern into a local buffer on its own stack,
// records the frame address, then exits.  When the goroutine dies
// its stack goes back through stackfree, which should memclr the
// stack range before the pool insert.  Reading the recorded address
// afterwards should not find the pattern.
//
// The test can race with the runtime reusing the stack range for
// another goroutine (which would also overwrite the pattern via
// normal frame use), so we check "pattern gone" rather than "all
// zeros" — both outcomes indicate the sanitize did its job, and
// only "pattern still present" indicates leakage.
func TestJanosSanitizeStackZeroesOnFree(t *testing.T) {
	const (
		payload = 512
		pattern = 0xC3
	)

	// The exit synchronization is done via a channel; the stack
	// address of the transient buffer is captured through the
	// closure into a heap-allocated *uintptr that survives the
	// goroutine.
	addr := new(uintptr)
	done := make(chan struct{})

	go func() {
		defer close(done)
		writeAndRecord := func() {
			var buf [payload]byte
			for i := range buf {
				buf[i] = pattern
			}
			*addr = uintptr(unsafe.Pointer(&buf[0]))
			runtime.KeepAlive(&buf)
		}
		writeAndRecord()
	}()
	<-done

	// Force one GC to make sure the dead goroutine's stack has
	// been reclaimed (and thus stackfree called on it).
	runtime.GC()
	runtime.GC()

	// Peek at the recorded stack address.  Reading a freed stack
	// via a raw uintptr is defined by the runtime here because we
	// know the pool either keeps the pages mapped (stackpool /
	// stackcache) or the memory got scavenged (large stacks) —
	// either way the read completes, and the value either shows
	// the pattern (sanitize failed) or something else (sanitize
	// succeeded or the range was overwritten).
	base := *addr
	if base == 0 {
		t.Fatal("stack address was not recorded")
	}
	var stillHasPattern int
	for i := uintptr(0); i < payload; i++ {
		if *(*byte)(unsafe.Pointer(base + i)) == pattern {
			stillHasPattern++
		}
	}
	if stillHasPattern == payload {
		t.Errorf("janos stack sanitize: all %d bytes at freed stack address still hold pattern 0x%02X; stackfree memclr did not fire",
			payload, pattern)
	}
}

// TestJanosSanitizeSweepZeroesFreedLargeObject allocates a large
// object (well above the 32 KiB small/large boundary), fills it with
// a pattern, records the address, drops the reference, and forces GC.
// With janosSanitizeLargeSpan active, the freed page range must not
// still contain the pattern.
func TestJanosSanitizeSweepZeroesFreedLargeObject(t *testing.T) {
	const (
		size    = 128 << 10 // 128 KiB, definitely a large-object span
		pattern = 0x5A
	)

	buf := make([]byte, size)
	for i := range buf {
		buf[i] = pattern
	}
	addr := uintptr(unsafe.Pointer(&buf[0]))
	runtime.KeepAlive(buf)

	buf = nil
	runtime.GC()
	runtime.GC()

	// Read a handful of samples across the freed span.  If any
	// sample still holds the pattern, sanitize did not fire.
	samples := []uintptr{0, size / 4, size / 2, 3 * size / 4, size - 1}
	for _, off := range samples {
		v := *(*byte)(unsafe.Pointer(addr + off))
		if v == pattern {
			t.Errorf("janos sanitize: large-span byte at +%d still holds pattern 0x%02X after GC; janosSanitizeLargeSpan did not fire",
				off, pattern)
		}
	}
}

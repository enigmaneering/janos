// JanOS: sweep-time memory sanitization.
//
// Stock Go's mark-sweep collector never zeroes freed heap memory; it
// defers clearing until the next allocation of the same slot, gated
// by the span's needzero bit.  That leaves an unbounded window in
// which the old contents of a freed slot remain visible to anyone
// who can read process memory: a coredump, /proc/pid/mem, a paged-
// out page swapped to disk, a cold-boot attacker with DRAM refresh
// interrupted, a debugger attach.
//
// JanOS closes that window unconditionally.  For small-object spans,
// the memclr is folded into the existing "find newly freed objects"
// loop in (*mspan).sweep — see mgcsweep.go, in the same block that
// dispatches the debug/trace/race/msan/asan callbacks.  Piggy-backing
// on that loop guarantees we walk the mark bitmap only once and
// touch the exact same slots stock Go's tooling already expected to
// be safely writable at that moment.  For large-object spans, the
// whole page range is zeroed by janosSanitizeLargeSpan below just
// before mheap_.freeSpan hands the pages back.
//
// This is JanOS's default and cannot be disabled.  The invariant
// "freed heap memory is always zero" is load-bearing for the future
// Secret[T] container and for the more general claim that a divined
// binary can make about what plaintext might have survived in RAM
// after logical death.
//
// Overhead is modest.  The sweeper already touches every freed span
// (mark bitmap walk, allocBits update, free-list threading); adding
// a memclrNoHeapPointers per freed slot is incremental work on
// data structures already hot in cache.  Modern x86/arm64 memclr
// runs at 25–35 GB/s; under a ~500 MB/s server allocation rate the
// added cost is roughly 2% of one core.
//
// What this covers:
//   - Small-object heap spans: freed slots memclr'd in (*mspan).sweep,
//     folded into the existing "find newly freed objects" loop.
//   - Large-object heap spans: janosSanitizeLargeSpan zeroes the
//     whole page range before mheap_.freeSpan returns pages to the
//     heap.
//   - Goroutine stacks: janosSanitizeStack zeroes the entire stack
//     range in stackfree, before the stack goes to stackpool /
//     stackcache / stackLarge / freeManual.
//
// What is covered elsewhere by construction:
//   - User arena chunks: arena.go calls setUserArenaChunkToFault
//     before a chunk enters the quarantineList, which sysFault's
//     the whole chunk (unmaps the pages).  On reuse from the ready
//     list, allocUserArenaChunk sysMap's fresh pages back in; the
//     kernel guarantees those are zero-filled.  See arena.go's
//     "A user arena chunk is always fresh from the OS" comment.
//     No JanOS hook is needed.
//
// What this does NOT cover:
//   - CPU registers (compiler intrinsic territory; see additions.md
//     "compiler-directed function-level scrubbing").
//   - The tiny-block carry-over cursor in mcache (still holds the
//     tail of the last tiny allocation until the block retires).
//   - Anything outside the Go heap: mmap'd file regions, cgo
//     buffers, memory obtained via runtime.mmap directly.

package runtime

import "unsafe"

// janosSanitizeLargeSpan zeroes the entire page range of a large-
// object span (spc.sizeclass() == 0) whose sole object died this GC
// cycle.  Called from (*mspan).sweep right before mheap_.freeSpan
// hands the pages back.
//
// We clear s.npages*pageSize rather than just s.elemsize because the
// heap may reuse the pages without a scavenger pass in between; any
// tail padding beyond the requested object size could still hold
// plaintext otherwise.
func janosSanitizeLargeSpan(s *mspan) {
	if s.npages == 0 {
		return
	}
	memclrNoHeapPointers(unsafe.Pointer(s.base()), s.npages*pageSize)
	s.needzero = 0
}

// janosSanitizeStack zeroes a stack region before it is returned to
// any reuse pool.  Called from stackfree, once per free, before the
// dispatch to stackpool / stackcache / stackLarge / freeManual.
//
// Stack pages hold function arguments, local variables, spilled
// registers, and crypto ephemerals produced by short-lived helper
// functions.  Without this hook, a stack range freed by one
// goroutine (via death or shrinkstack) is handed out to the next
// goroutine with the previous goroutine's plaintext still in it.
//
// Cost: negligible.  Stacks are typically 2–32 KiB; a memclr at
// arm64 / x86 memory-bandwidth is sub-microsecond.  Steady-state
// stackfree rate is dominated by goroutine death and stack shrink,
// both infrequent compared to allocation.
//
//go:nosplit
func janosSanitizeStack(v unsafe.Pointer, n uintptr) {
	if n == 0 {
		return
	}
	memclrNoHeapPointers(v, n)
}


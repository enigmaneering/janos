package sync_test

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe" // for go:linkname
)

// runtimeJanosSpark is runtime.janosSpark reached via linkname.  The
// primitive is unexported in runtime — user code spawns fresh-identity
// goroutines only through runtime/genesis.SparkAs — but tests in this
// package need distinct identities to exercise Idempotent's per-
// identity slotting.  Linkname is the sanctioned escape hatch for
// this exact scenario.
//
//go:linkname runtimeJanosSpark runtime.janosSpark
func runtimeJanosSpark(f func())

// -----------------------------------------------------------------
// Basic sanity
// -----------------------------------------------------------------

func TestIdempotentZeroValueReady(t *testing.T) {
	var idem sync.Idempotent
	// Zero-value Idempotent's first Do must succeed without panic or
	// deadlock — the entries map is lazily allocated.
	idem.Do(func() {})
}

// -----------------------------------------------------------------
// Inheritance: goroutines sharing an identity share a once-slot
// -----------------------------------------------------------------

// TestIdempotentInheritedIdentityFiresOnce spawns N goroutines with
// plain `go`, so all share the test goroutine's identity.  Every
// concurrent Do call keys on that same identity and the function
// runs exactly once.
func TestIdempotentInheritedIdentityFiresOnce(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32
	var wg sync.WaitGroup
	const n = 100
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			idem.Do(func() { count.Add(1) })
		}()
	}
	idem.Do(func() { count.Add(1) }) // parent also fires
	wg.Wait()
	if got := count.Load(); got != 1 {
		t.Fatalf("inherited-identity Do fired %d times, want 1", got)
	}
}

// -----------------------------------------------------------------
// Sparks: distinct identities fire independently
// -----------------------------------------------------------------

// TestIdempotentDistinctSparksFireIndependently spawns N goroutines
// each with a fresh identity via runtimeJanosSpark.  Each spark has
// its own once-slot, so f runs once per spark — N fires total.
func TestIdempotentDistinctSparksFireIndependently(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32
	const n = 8
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		runtimeJanosSpark(func() {
			idem.Do(func() { count.Add(1) })
			done <- struct{}{}
		})
	}
	for i := 0; i < n; i++ {
		<-done
	}
	if got := count.Load(); got != n {
		t.Fatalf("per-Spark Do fired %d times, want %d", got, n)
	}
}

// TestIdempotentSameIdentityAcrossMultipleDosIdempotent verifies that
// repeated Do calls from the same goroutine's identity do not re-fire.
func TestIdempotentSameIdentityAcrossMultipleDosIdempotent(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32
	for i := 0; i < 10; i++ {
		idem.Do(func() { count.Add(1) })
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("10 sequential Dos from same identity fired %d times, want 1", got)
	}
}

// -----------------------------------------------------------------
// Cleanup on block finalization
// -----------------------------------------------------------------

// TestIdempotentCleanupOnBlockFinalization verifies that entries in
// an Idempotent map are evicted when the identityBlock they keyed on
// becomes GC-unreachable.  Runs several rounds of Sparks; if entries
// were NOT evicted, they would accumulate, but the map is unexported
// so we can't inspect it directly.  Instead we assert that behavior
// remains correct across rounds (no false collisions, no leaks that
// would manifest as f not firing when it should).
func TestIdempotentCleanupOnBlockFinalization(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int64
	const rounds = 3
	const sparksPerRound = 20

	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < sparksPerRound; i++ {
			wg.Add(1)
			runtimeJanosSpark(func() {
				defer wg.Done()
				idem.Do(func() { count.Add(1) })
			})
		}
		wg.Wait()

		// Let the runtime drop last references to dead identityBlocks.
		time.Sleep(20 * time.Millisecond)
		for k := 0; k < 5; k++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
	}

	want := int64(rounds) * int64(sparksPerRound)
	got := count.Load()
	if got != want {
		t.Fatalf("total fires across %d rounds of %d Sparks: got %d, want %d — either identities collided (mint broken) or the primitive broke",
			rounds, sparksPerRound, got, want)
	}
}

// TestIdempotentEntriesEvictedOnBlockFinalization directly observes
// the block-finalized hook draining the entries map.  The behavioral
// cleanup test above cannot distinguish "entries evicted" from
// "entries leaked but addresses never reused" — this one watches the
// count itself.
//
// Two-phase convergence: sparked goroutines exit, but their g
// descriptors sit on the scheduler's free list still holding
// provenance pointers to the identity blocks.  Spawning waves of
// plain goroutines recycles those g's (newproc1 overwrites their
// provenance with the spawner's), dropping the last references so
// GC can finalize the blocks and the hook can evict.
func TestIdempotentEntriesEvictedOnBlockFinalization(t *testing.T) {
	var idem sync.Idempotent
	const n = 16
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		runtimeJanosSpark(func() {
			idem.Do(func() {})
			done <- struct{}{}
		})
	}
	for i := 0; i < n; i++ {
		<-done
	}
	// All n sparks registered; the test goroutine itself never called
	// Do, so exactly n entries exist.
	if got := sync.IdempotentEntryCountForTest(&idem); got != n {
		t.Fatalf("after %d sparks, entries = %d, want %d", n, got, n)
	}

	deadline := time.Now().Add(10 * time.Second)
	for sync.IdempotentEntryCountForTest(&idem) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("entries not evicted after 10s; %d remain — block-finalized hook broken?",
				sync.IdempotentEntryCountForTest(&idem))
		}
		// Recycle dead g's so they release their identity blocks.
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() { wg.Done() }()
		}
		wg.Wait()
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	// Converged to zero: every dead identity's slot was evicted.
}

package sync_test

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------
// No-args behavior: identical to sync.Once
// -----------------------------------------------------------------

func TestIdempotentNoArgsRunsOnce(t *testing.T) {
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
	wg.Wait()
	if got := count.Load(); got != 1 {
		t.Fatalf("f ran %d times across %d concurrent Do calls, want 1", got, n)
	}
}

func TestIdempotentZeroValueReady(t *testing.T) {
	var idem sync.Idempotent
	// Should not panic or deadlock on first use of a zero-value
	// Idempotent, including with lazy internal map allocation.
	idem.Do(func() {})
}

// -----------------------------------------------------------------
// Single-identity: shared vs distinct
// -----------------------------------------------------------------

func TestIdempotentSharedIdentityFiresOnce(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32
	me := runtime.Identify()

	var wg sync.WaitGroup
	const n = 100
	for i := 0; i < n; i++ {
		wg.Add(1)
		// go-inheritance means the child sees the same Identity.
		go func() {
			defer wg.Done()
			idem.Do(func() { count.Add(1) }, runtime.Identify())
		}()
	}
	idem.Do(func() { count.Add(1) }, me) // parent also fires
	wg.Wait()
	if got := count.Load(); got != 1 {
		t.Fatalf("shared-identity Do fired %d times, want 1", got)
	}
}

func TestIdempotentDistinctSparksFireIndependently(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32
	const n = 8
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		runtime.Spark(func() {
			idem.Do(func() { count.Add(1) }, runtime.Identify())
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

// -----------------------------------------------------------------
// Collective idempotency: order-independence + slot distinctness
// -----------------------------------------------------------------

func TestIdempotentCollectiveOrderIndependent(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32

	idA, idB := twoIdentities(t)
	idem.Do(func() { count.Add(1) }, idA, idB)
	idem.Do(func() { count.Add(1) }, idB, idA) // same collective, reversed
	if got := count.Load(); got != 1 {
		t.Fatalf("collective {A,B} vs {B,A}: fired %d times, want 1", got)
	}
}

func TestIdempotentCollectiveDistinctFromSubsets(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32

	idA, idB := twoIdentities(t)
	idem.Do(func() { count.Add(1) }, idA, idB)
	if got := count.Load(); got != 1 {
		t.Fatalf("first {A,B} call: fired %d times, want 1", got)
	}
	idem.Do(func() { count.Add(1) }, idA) // solo A: distinct slot
	if got := count.Load(); got != 2 {
		t.Fatalf("after {A} solo: fired %d times, want 2", got)
	}
	idem.Do(func() { count.Add(1) }, idB) // solo B: another distinct slot
	if got := count.Load(); got != 3 {
		t.Fatalf("after {B} solo: fired %d times, want 3", got)
	}
}

func TestIdempotentEmptyCollectiveIsProgramWide(t *testing.T) {
	var idem sync.Idempotent
	var count atomic.Int32

	idem.Do(func() { count.Add(1) })                          // no identities
	idem.Do(func() { count.Add(1) })                          // still program-wide
	idem.Do(func() { count.Add(1) }, runtime.Identify())      // solo-me slot
	if got := count.Load(); got != 2 {
		t.Fatalf("empty-collective vs solo-me distinguishability: fired %d times, want 2",
			got)
	}
}

// -----------------------------------------------------------------
// Cleanup on block finalization
// -----------------------------------------------------------------

// TestIdempotentCleanupOnBlockFinalization verifies that entries in
// an Idempotent map are evicted when the identityBlock they keyed on
// becomes GC-unreachable.  Runs several rounds of Sparks; if entries
// were NOT evicted, they would accumulate, but the map is unexported
// so we can't inspect it directly.  Instead we assert the behavior
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
			runtime.Spark(func() {
				defer wg.Done()
				idem.Do(func() { count.Add(1) }, runtime.Identify())
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
		t.Fatalf("total fires across %d rounds of %d Sparks: got %d, want %d — either identities collided (mint broken) or cleanup broken",
			rounds, sparksPerRound, got, want)
	}
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

// twoIdentities returns two distinct Identity values via Spark.  The
// Sparked goroutines exit before returning to the caller; the
// caller uses these values from its own goroutine.  Note: Derive
// would reject calls from a non-owning goroutine, but map-key
// operations (including Idempotent.Do) don't invoke Derive — they
// just compare byte representations.
func twoIdentities(t *testing.T) (runtime.Identity, runtime.Identity) {
	t.Helper()
	ch := make(chan runtime.Identity, 2)
	runtime.Spark(func() { ch <- runtime.Identify() })
	runtime.Spark(func() { ch <- runtime.Identify() })
	a := <-ch
	b := <-ch
	if a == b {
		t.Fatalf("twoIdentities helper produced identical Identities: %d", a.Index)
	}
	return a, b
}

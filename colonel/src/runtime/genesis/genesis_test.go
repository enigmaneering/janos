// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genesis

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// inSpark runs body on a fresh JanOS identity so each test starts
// with a clean genesis phase.  Fails the test if body doesn't
// complete within timeout.
func inSpark(t *testing.T, body func(*testing.T)) {
	t.Helper()
	done := make(chan struct{})
	runtimeJanosSpark(func() {
		defer close(done)
		body(t)
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("test body did not complete within 5s")
	}
}

type traitA struct{ value string }
type traitB struct{ n int }
type traitAlias = traitA
type traitPrimary struct{ role string }

// -- Internal-path tests ----------------------------------------------
//
// These call the unexported registerTrait / closePhase / phaseWaitGroup
// helpers directly.  Register (the public API) can't be tested from a
// test function because its mustBeInInitPhase guard panics outside
// package init; those semantics are covered separately below.

func TestRegisterTraitAndTraitOf(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "hello"}); err != nil {
			t.Fatalf("registerTrait: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		got, err := TraitOf[traitA]()
		if err != nil {
			t.Fatalf("TraitOf: %v", err)
		}
		if got.value != "hello" {
			t.Fatalf("TraitOf: value = %q, want %q", got.value, "hello")
		}
	})
}

func TestRegisterTraitDuplicateType(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "first"}); err != nil {
			t.Fatalf("first registerTrait: %v", err)
		}
		err := registerTrait(traitA{value: "second"})
		if !errors.Is(err, errDuplicateType) {
			t.Fatalf("second registerTrait: expected errDuplicateType, got %v", err)
		}
	})
}

func TestRegisterTraitTypeAliasesCollide(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "concrete"}); err != nil {
			t.Fatalf("first registerTrait: %v", err)
		}
		err := registerTrait(traitAlias{value: "alias"})
		if !errors.Is(err, errDuplicateType) {
			t.Fatalf("alias registerTrait: expected errDuplicateType, got %v", err)
		}
	})
}

func TestRegisterTraitDistinctTypesCoexist(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "a"}); err != nil {
			t.Fatalf("registerTrait A: %v", err)
		}
		if err := registerTrait(traitB{n: 42}); err != nil {
			t.Fatalf("registerTrait B: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		a, err := TraitOf[traitA]()
		if err != nil {
			t.Fatalf("TraitOf A: %v", err)
		}
		b, err := TraitOf[traitB]()
		if err != nil {
			t.Fatalf("TraitOf B: %v", err)
		}
		if a.value != "a" {
			t.Errorf("A value = %q, want %q", a.value, "a")
		}
		if b.n != 42 {
			t.Errorf("B n = %d, want %d", b.n, 42)
		}
	})
}

func TestTraitOfBeforeCloseErrsPhaseOpen(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "hi"}); err != nil {
			t.Fatalf("registerTrait: %v", err)
		}
		_, err := TraitOf[traitA]()
		if !errors.Is(err, ErrPhaseOpen) {
			t.Fatalf("TraitOf before close: expected ErrPhaseOpen, got %v", err)
		}
	})
}

func TestRegisterAfterCloseErrsPhaseClosed(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		err := registerTrait(traitA{value: "late"})
		if !errors.Is(err, errPhaseClosed) {
			t.Fatalf("registerTrait after close: expected errPhaseClosed, got %v", err)
		}
	})
}

func TestTraitOfNotFound(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "just A"}); err != nil {
			t.Fatalf("registerTrait: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		_, err := TraitOf[traitB]()
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("TraitOf B: expected ErrNotFound, got %v", err)
		}
	})
}

func TestTraitOfModuleFilter(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "hi"}); err != nil {
			t.Fatalf("registerTrait: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		_, err := TraitOf[traitA]("nonexistent/module")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("non-matching filter: expected ErrNotFound, got %v", err)
		}
	})
}

func TestClosePhaseTwiceErrs(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := closePhase(); err != nil {
			t.Fatalf("first closePhase: %v", err)
		}
		err := closePhase()
		if !errors.Is(err, errPhaseClosed) {
			t.Fatalf("second closePhase: expected errPhaseClosed, got %v", err)
		}
	})
}

func TestSparkAsInheritsAndPrimaryFlowsToWork(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := registerTrait(traitA{value: "from-parent"}); err != nil {
			t.Fatalf("parent registerTrait: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("parent closePhase: %v", err)
		}

		var (
			primaryReceived atomic.Pointer[traitPrimary]
			inheritedA      atomic.Pointer[traitA]
			addedB          atomic.Pointer[traitB]
			done            = make(chan struct{})
		)
		err := SparkAs(
			func(p traitPrimary) {
				defer close(done)
				primaryReceived.Store(&p)
				a, aErr := TraitOf[traitA]()
				if aErr != nil {
					t.Errorf("child TraitOf[A]: %v", aErr)
					return
				}
				b, bErr := TraitOf[traitB]()
				if bErr != nil {
					t.Errorf("child TraitOf[B]: %v", bErr)
					return
				}
				inheritedA.Store(&a)
				addedB.Store(&b)
			},
			func() traitPrimary { return traitPrimary{role: "child"} },
			func() any { return traitB{n: 7} },
		)
		if err != nil {
			t.Fatalf("SparkAs: %v", err)
		}
		<-done
		p := primaryReceived.Load()
		if p == nil || p.role != "child" {
			t.Errorf("primary received = %v, want role=child", p)
		}
		a := inheritedA.Load()
		if a == nil || a.value != "from-parent" {
			t.Errorf("inherited traitA = %v, want value=from-parent", a)
		}
		b := addedB.Load()
		if b == nil || b.n != 7 {
			t.Errorf("added traitB = %v, want n=7", b)
		}
	})
}

func TestSparkAsRequiresParentPhaseClosed(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		err := SparkAs(
			func(p traitPrimary) {},
			func() traitPrimary { return traitPrimary{role: "child"} },
		)
		if !errors.Is(err, ErrPhaseOpen) {
			t.Fatalf("SparkAs before parent close: expected ErrPhaseOpen, got %v", err)
		}
	})
}

// SparkAs propagates a child-side registration collision by panicking
// on the child goroutine.  A panic on that goroutine tears down the
// test binary — Go's testing framework cannot recover it — so we
// don't test the panic directly here.  Coverage comes from composition:
// TestRegisterTraitDuplicateType proves the collision check fires,
// and TestSparkAsInheritsAndPrimaryFlowsToWork proves inheritance
// populates the child's typeIdx before the child's own initializers
// run.

func TestPhaseWaitGroupHoldsCloseUntilDone(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		wg := phaseWaitGroup()
		if wg == nil {
			t.Fatal("phaseWaitGroup returned nil for a fresh phase")
		}
		var mu sync.Mutex
		var asyncTraitRegistered bool

		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			if err := registerTrait(traitB{n: 99}); err != nil {
				t.Errorf("async registerTrait: %v", err)
			}
			mu.Lock()
			asyncTraitRegistered = true
			mu.Unlock()
		}()

		start := time.Now()
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		elapsed := time.Since(start)
		if elapsed < 40*time.Millisecond {
			t.Errorf("closePhase returned in %v — expected >=~50ms wait for async", elapsed)
		}
		mu.Lock()
		registered := asyncTraitRegistered
		mu.Unlock()
		if !registered {
			t.Fatal("async goroutine did not mark trait registration before closePhase returned")
		}

		got, err := TraitOf[traitB]()
		if err != nil {
			t.Fatalf("TraitOf B: %v", err)
		}
		if got.n != 99 {
			t.Errorf("got.n = %d, want %d", got.n, 99)
		}
	})
}

func TestPhaseWaitGroupNilAfterClose(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		if wg := phaseWaitGroup(); wg != nil {
			t.Error("phaseWaitGroup after close: expected nil")
		}
	})
}

func TestTraitOfEmptySelf(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		_, err := TraitOf[traitA]()
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("TraitOf on empty Self: expected ErrNotFound, got %v", err)
		}
		self, err := CurrentSelf()
		if err != nil {
			t.Fatalf("CurrentSelf: %v", err)
		}
		if len(self.Traits) != 0 {
			t.Errorf("empty Self.Traits length = %d, want 0", len(self.Traits))
		}
	})
}

// -- Register dispatch tests -----------------------------------------

type registerValueTrait struct{ tag string }
type registerFuncTrait struct{ n int }
type registerAsyncTrait struct{ ready bool }

func TestRegisterDispatchPlainValue(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		out := registerDispatch(registerValueTrait{tag: "direct"})
		v, ok := out.(registerValueTrait)
		if !ok || v.tag != "direct" {
			t.Errorf("registerDispatch return = %v, want registerValueTrait{tag:direct}", out)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		back, err := TraitOf[registerValueTrait]()
		if err != nil {
			t.Fatalf("TraitOf: %v", err)
		}
		if back.tag != "direct" {
			t.Errorf("TraitOf = %v, want tag=direct", back)
		}
	})
}

func TestRegisterDispatchSyncFunc(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		out := registerDispatch(func() registerFuncTrait { return registerFuncTrait{n: 3} })
		v, ok := out.(registerFuncTrait)
		if !ok || v.n != 3 {
			t.Errorf("registerDispatch return = %v, want registerFuncTrait{n:3}", out)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		back, err := TraitOf[registerFuncTrait]()
		if err != nil {
			t.Fatalf("TraitOf: %v", err)
		}
		if back.n != 3 {
			t.Errorf("TraitOf = %v, want n=3", back)
		}
	})
}

func TestRegisterDispatchAsyncFunc(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		var completed atomic.Bool
		out := registerDispatch(func(wg *sync.WaitGroup) registerAsyncTrait {
			r := registerAsyncTrait{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(50 * time.Millisecond)
				completed.Store(true)
			}()
			return r
		})
		if _, ok := out.(registerAsyncTrait); !ok {
			t.Errorf("registerDispatch return = %v, want registerAsyncTrait", out)
		}
		start := time.Now()
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		if time.Since(start) < 40*time.Millisecond {
			t.Errorf("closePhase returned too quickly (async work not awaited)")
		}
		if !completed.Load() {
			t.Error("async work did not complete before closePhase returned")
		}
	})
}

func TestRegisterDispatchUnsupportedFunctionPanics(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic on unsupported function shape")
			}
		}()
		// Multi-return: not sync init and not async init.
		registerDispatch(func() (int, error) { return 0, nil })
	})
}

func TestRegisterDispatchNilPanics(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic on nil argument")
			}
		}()
		registerDispatch(nil)
	})
}

// TestRegisterOutsideInitPanics verifies the mustBeInInitPhase guard
// on Register — calling Register from a test function (not under
// runtime.doInit) MUST panic.  This is JanOS's runtime enforcement
// that Register lives only in package-init scope.
func TestRegisterOutsideInitPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when Register is called outside package init")
		}
		msg, _ := r.(string)
		if err, ok := r.(error); ok {
			msg = err.Error()
		}
		if msg == "" {
			t.Errorf("panic value has no error message: %#v", r)
		}
	}()
	Register(registerValueTrait{tag: "should not reach"})
}

// -- Main-init-done hook --------------------------------------------

// TestMainPhaseClosedAtTestStart verifies runtime.main's genesis
// close hook fired before any test runs.  The test's outer goroutine
// inherits main's identity via `go`, so it shares main's selfState —
// which should already be frozen by the time tests execute.
func TestMainPhaseClosedAtTestStart(t *testing.T) {
	_, err := CurrentSelf()
	if err != nil {
		t.Fatalf("main goroutine's phase should be closed at test start, got: %v", err)
	}
	err = registerTrait(traitA{value: "post-hook"})
	if !errors.Is(err, errPhaseClosed) {
		t.Errorf("registerTrait on frozen main: expected errPhaseClosed, got %v", err)
	}
}

// -- Exit deferral ----------------------------------------------------

// TestRunDeferredLIFOAndAsyncWait drives the shared drain helper
// directly: three cleanups registered in order 1,2,3 must run 3,2,1,
// and an async cleanup must complete before runDeferred returns.
func TestRunDeferredLIFOAndAsyncWait(t *testing.T) {
	var order []int
	var mu sync.Mutex
	var asyncDone atomic.Bool

	fns := []func(*sync.WaitGroup){
		func(wg *sync.WaitGroup) {
			mu.Lock()
			order = append(order, 1)
			mu.Unlock()
		},
		func(wg *sync.WaitGroup) {
			mu.Lock()
			order = append(order, 2)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(50 * time.Millisecond)
				asyncDone.Store(true)
			}()
		},
		func(wg *sync.WaitGroup) {
			mu.Lock()
			order = append(order, 3)
			mu.Unlock()
		},
	}
	start := time.Now()
	runDeferred(fns)
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("runDeferred returned in %v — expected to wait ~50ms for async cleanup", elapsed)
	}
	if !asyncDone.Load() {
		t.Error("async cleanup did not complete before runDeferred returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != 3 || order[1] != 2 || order[2] != 1 {
		t.Errorf("cleanup order = %v, want [3 2 1] (LIFO)", order)
	}
}

// TestRunDeferredPanickingCleanupDoesNotBlockOthers verifies the
// per-cleanup recover: a panicking cleanup is contained and the
// remaining cleanups still run.
func TestRunDeferredPanickingCleanupDoesNotBlockOthers(t *testing.T) {
	var ran []string
	var mu sync.Mutex
	fns := []func(*sync.WaitGroup){
		func(wg *sync.WaitGroup) {
			mu.Lock()
			ran = append(ran, "first-registered")
			mu.Unlock()
		},
		func(wg *sync.WaitGroup) {
			panic("cleanup bug")
		},
		func(wg *sync.WaitGroup) {
			mu.Lock()
			ran = append(ran, "last-registered")
			mu.Unlock()
		},
	}
	runDeferred(fns) // must not panic outward
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 || ran[0] != "last-registered" || ran[1] != "first-registered" {
		t.Errorf("ran = %v, want [last-registered first-registered]", ran)
	}
}

// TestDrainShutdownHonorsMidDrainRegistration verifies the loop: a
// cleanup that Defers another cleanup during the drain gets that
// second cleanup run too.
func TestDrainShutdownHonorsMidDrainRegistration(t *testing.T) {
	var cascaded atomic.Bool
	Defer(func(wg *sync.WaitGroup) {
		Defer(func(wg *sync.WaitGroup) {
			cascaded.Store(true)
		})
	})
	drainShutdown()
	if !cascaded.Load() {
		t.Error("cleanup registered during drain did not run")
	}
	// Registry must be empty afterward so the real exit-hook drain
	// at test-binary exit is a no-op.
	shutdown.mu.Lock()
	n := len(shutdown.funcs)
	shutdown.mu.Unlock()
	if n != 0 {
		t.Errorf("shutdown registry has %d leftover entries after drain", n)
	}
}

// TestDeferSelfDrainsOnSparkExit is the end-to-end: a spark registers
// exit cleanups from BOTH an init function and the work body; when
// work returns, both run LIFO on the spark goroutine, async work
// included, before the spark is considered exited.
func TestDeferSelfDrainsOnSparkExit(t *testing.T) {
	// Parent phase must be closed to SparkAs.
	if err := closePhase(); err != nil && !errors.Is(err, errPhaseClosed) {
		t.Fatalf("parent closePhase: %v", err)
	}

	events := make(chan string, 4)
	done := make(chan struct{})
	err := SparkAs(
		func(p traitPrimary) {
			DeferSelf(func(wg *sync.WaitGroup) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					time.Sleep(30 * time.Millisecond)
					events <- "work-cleanup-async"
					close(done)
				}()
			})
			events <- "work-ran"
		},
		func() traitPrimary {
			// Cleanup registered at creation time, inside the init.
			DeferSelf(func(wg *sync.WaitGroup) {
				events <- "init-cleanup"
			})
			return traitPrimary{role: "deferral-e2e"}
		},
	)
	if err != nil {
		t.Fatalf("SparkAs: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("spark exit deferrals did not complete within 5s")
	}
	close(events)
	var got []string
	for e := range events {
		got = append(got, e)
	}
	// work-ran, then LIFO drain: work's cleanup (async) fires Done
	// after init's cleanup already ran synchronously.  Order of the
	// two cleanup EVENTS: init-cleanup is synchronous and runs during
	// the LIFO pass (after work's cleanup *started* its goroutine);
	// work-cleanup-async lands ~30ms later.  So observed order:
	// work-ran, init-cleanup, work-cleanup-async.
	want := []string{"work-ran", "init-cleanup", "work-cleanup-async"}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}

// TestDeferSelfFromMainIdentityRoutesToProcess: the test goroutine
// shares main's identity, so DeferSelf must land in the process
// shutdown registry, not a selfState.
func TestDeferSelfFromMainIdentityRoutesToProcess(t *testing.T) {
	shutdown.mu.Lock()
	before := len(shutdown.funcs)
	shutdown.mu.Unlock()

	DeferSelf(func(wg *sync.WaitGroup) {}) // harmless no-op at real exit

	shutdown.mu.Lock()
	after := len(shutdown.funcs)
	shutdown.mu.Unlock()
	if after != before+1 {
		t.Fatalf("shutdown registry grew by %d, want 1 (DeferSelf from main identity must route to Defer)", after-before)
	}

	// And main's selfState must NOT have accumulated a deferred entry.
	st := stateForCurrent()
	if st == nil {
		t.Fatal("no selfState for main identity")
	}
	st.mu.Lock()
	n := len(st.deferred)
	st.mu.Unlock()
	if n != 0 {
		t.Errorf("main selfState.deferred has %d entries, want 0", n)
	}
}

// TestDeferNilPanics / TestDeferSelfNilPanics: nil cleanups are
// programming errors, caught at registration.
func TestDeferNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil Defer")
		}
	}()
	Defer(nil)
}

func TestDeferSelfNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil DeferSelf")
		}
	}()
	DeferSelf(nil)
}

// -- Inception --------------------------------------------------------

// TestInceptionMainIsBootStamp: the main identity's inception comes
// from the genesis-package-init wall-clock stamp — nonzero, in the past,
// and recent (this test binary just booted).  Two reads agree.
func TestInceptionMainIsBootStamp(t *testing.T) {
	self, err := CurrentSelf()
	if err != nil {
		t.Fatalf("CurrentSelf: %v", err)
	}
	inc := self.Inception()
	if inc.IsZero() {
		t.Fatal("main inception is zero — boot stamp did not propagate")
	}
	if !inc.Before(time.Now()) {
		t.Errorf("main inception %v is not in the past", inc)
	}
	if age := time.Since(inc); age > 10*time.Minute {
		t.Errorf("main inception %v is %v old — implausible for a test binary that just started", inc, age)
	}
	again, err := CurrentSelf()
	if err != nil {
		t.Fatalf("second CurrentSelf: %v", err)
	}
	if !again.Inception().Equal(inc) {
		t.Errorf("inception not stable: %v then %v", inc, again.Inception())
	}
}

// TestInceptionSparkAsBounds: a spark's inception is captured at the
// top of the SparkAs call — at or after a timestamp taken just before
// the call, and at or before one taken inside the work function.
func TestInceptionSparkAsBounds(t *testing.T) {
	if err := closePhase(); err != nil && !errors.Is(err, errPhaseClosed) {
		t.Fatalf("parent closePhase: %v", err)
	}
	before := time.Now()
	done := make(chan struct{})
	var inc, during time.Time
	err := SparkAs(
		func(p traitPrimary) {
			defer close(done)
			during = time.Now()
			self, err := CurrentSelf()
			if err != nil {
				t.Errorf("child CurrentSelf: %v", err)
				return
			}
			inc = self.Inception()
		},
		func() traitPrimary { return traitPrimary{role: "inception"} },
	)
	if err != nil {
		t.Fatalf("SparkAs: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("spark did not complete")
	}
	if inc.IsZero() {
		t.Fatal("spark inception is zero")
	}
	if inc.Before(before) {
		t.Errorf("inception %v predates the SparkAs call (before=%v)", inc, before)
	}
	if during.Before(inc) {
		t.Errorf("work ran at %v, before its own inception %v", during, inc)
	}
}

// TestInceptionSharedByGoChildren: a `go` child shares the spark's
// identity and therefore its inception.
func TestInceptionSharedByGoChildren(t *testing.T) {
	if err := closePhase(); err != nil && !errors.Is(err, errPhaseClosed) {
		t.Fatalf("parent closePhase: %v", err)
	}
	done := make(chan struct{})
	var sparkInc, childInc time.Time
	err := SparkAs(
		func(p traitPrimary) {
			self, _ := CurrentSelf()
			sparkInc = self.Inception()
			inner := make(chan struct{})
			go func() {
				defer close(inner)
				cs, err := CurrentSelf()
				if err != nil {
					t.Errorf("go-child CurrentSelf: %v", err)
					return
				}
				childInc = cs.Inception()
			}()
			<-inner
			close(done)
		},
		func() traitPrimary { return traitPrimary{role: "inheritance"} },
	)
	if err != nil {
		t.Fatalf("SparkAs: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("spark did not complete")
	}
	if !childInc.Equal(sparkInc) {
		t.Errorf("go-child inception %v != spark inception %v", childInc, sparkInc)
	}
}

// TestInceptionDistinctAcrossSequentialSparks: two sparks created in
// sequence carry ordered, distinct inceptions.
func TestInceptionDistinctAcrossSequentialSparks(t *testing.T) {
	if err := closePhase(); err != nil && !errors.Is(err, errPhaseClosed) {
		t.Fatalf("parent closePhase: %v", err)
	}
	grab := func() time.Time {
		done := make(chan time.Time, 1)
		err := SparkAs(
			func(p traitPrimary) {
				self, _ := CurrentSelf()
				done <- self.Inception()
			},
			func() traitPrimary { return traitPrimary{role: "seq"} },
		)
		if err != nil {
			t.Fatalf("SparkAs: %v", err)
		}
		select {
		case v := <-done:
			return v
		case <-time.After(5 * time.Second):
			t.Fatal("spark did not report")
			return time.Time{}
		}
	}
	first := grab()
	time.Sleep(5 * time.Millisecond)
	second := grab()
	if !first.Before(second) {
		t.Errorf("sequential sparks not ordered: first=%v second=%v", first, second)
	}
}

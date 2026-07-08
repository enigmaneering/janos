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

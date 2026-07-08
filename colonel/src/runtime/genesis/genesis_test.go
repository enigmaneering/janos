// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genesis

import (
	"errors"
	"runtime"
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
	runtime.Spark(func() {
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
type complexMain struct{ role string }

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
		// traitAlias is a type alias for traitA — reflect treats them
		// as the same reflect.Type, so registration must be rejected.
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
		// Deliberately do not close.
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
		// Non-matching filter — must reject.
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

func TestSetComplexAndCurrentSelf(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := setComplex(complexMain{role: "controller"}); err != nil {
			t.Fatalf("setComplex: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("closePhase: %v", err)
		}
		self, err := CurrentSelf()
		if err != nil {
			t.Fatalf("CurrentSelf: %v", err)
		}
		cm, ok := self.Complex.(complexMain)
		if !ok {
			t.Fatalf("Self.Complex = %#v, want complexMain", self.Complex)
		}
		if cm.role != "controller" {
			t.Errorf("Self.Complex.role = %q, want %q", cm.role, "controller")
		}
	})
}

func TestSetComplexTwiceErrs(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := setComplex(complexMain{role: "a"}); err != nil {
			t.Fatalf("first setComplex: %v", err)
		}
		err := setComplex(complexMain{role: "b"})
		if !errors.Is(err, errComplexAlreadySet) {
			t.Fatalf("second setComplex: expected errComplexAlreadySet, got %v", err)
		}
	})
}

func TestSparkAsInheritsTraitsAndSetsFreshComplex(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		// Parent side: register a trait, close.
		if err := registerTrait(traitA{value: "from-parent"}); err != nil {
			t.Fatalf("parent registerTrait: %v", err)
		}
		if err := setComplex(complexMain{role: "parent"}); err != nil {
			t.Fatalf("parent setComplex: %v", err)
		}
		if err := closePhase(); err != nil {
			t.Fatalf("parent closePhase: %v", err)
		}

		// Spark a child that adds its own Trait and gets a fresh Complex.
		var (
			childComplex atomic.Pointer[complexMain]
			childTraitA  atomic.Pointer[traitA]
			childTraitB  atomic.Pointer[traitB]
			done         = make(chan struct{})
		)
		err := SparkAs(
			func(c complexMain) {
				defer close(done)
				childComplex.Store(&c)
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
				childTraitA.Store(&a)
				childTraitB.Store(&b)
			},
			func() complexMain { return complexMain{role: "child"} },
			func() any { return traitB{n: 7} },
		)
		if err != nil {
			t.Fatalf("SparkAs: %v", err)
		}
		<-done
		cc := childComplex.Load()
		if cc == nil {
			t.Fatal("child Complex was never captured")
		}
		if cc.role != "child" {
			t.Errorf("child Complex.role = %q, want %q", cc.role, "child")
		}
		ca := childTraitA.Load()
		if ca == nil || ca.value != "from-parent" {
			t.Errorf("child inherited traitA = %v, want value=from-parent", ca)
		}
		cb := childTraitB.Load()
		if cb == nil || cb.n != 7 {
			t.Errorf("child own traitB = %v, want n=7", cb)
		}
	})
}

func TestSparkAsRequiresParentPhaseClosed(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		// Parent has NOT closed phase.
		err := SparkAs(
			func(c complexMain) {},
			func() complexMain { return complexMain{role: "child"} },
		)
		if !errors.Is(err, ErrPhaseOpen) {
			t.Fatalf("SparkAs before parent close: expected ErrPhaseOpen, got %v", err)
		}
	})
}

// SparkAs propagates a child-side registration collision by panicking
// on the child goroutine.  A panic on that goroutine tears down the
// test binary — Go's testing framework cannot recover it — so we
// don't test the panic directly here.  The behaviour is covered by
// composition: TestRegisterTraitDuplicateType proves the collision
// check fires, and TestSparkAsInheritsTraitsAndSetsFreshComplex
// proves inheritance populates the child's typeIdx before the child's
// own initializers run, so any inherited-vs-local collision goes
// through the same tested path.

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
			// Register a trait from the async goroutine.  Because
			// the runtime goroutine minting this trait is a plain
			// `go` (not a Spark), it inherits the parent identity and
			// therefore registers into the same selfState.
			if err := registerTrait(traitB{n: 99}); err != nil {
				t.Errorf("async registerTrait: %v", err)
			}
			mu.Lock()
			asyncTraitRegistered = true
			mu.Unlock()
		}()

		// closePhase must block until the goroutine's Done() fires.
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

		// TraitOf now sees the async trait.
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
		if self.Complex != nil {
			t.Errorf("empty Self.Complex = %v, want nil", self.Complex)
		}
	})
}

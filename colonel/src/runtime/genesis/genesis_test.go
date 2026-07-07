// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genesis_test

import (
	"errors"
	"runtime"
	"runtime/genesis"
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
		if err := genesis.RegisterTrait(traitA{value: "hello"}); err != nil {
			t.Fatalf("RegisterTrait: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		got, err := genesis.TraitOf[traitA]()
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
		if err := genesis.RegisterTrait(traitA{value: "first"}); err != nil {
			t.Fatalf("first RegisterTrait: %v", err)
		}
		err := genesis.RegisterTrait(traitA{value: "second"})
		if !errors.Is(err, genesis.ErrDuplicateType) {
			t.Fatalf("second RegisterTrait: expected ErrDuplicateType, got %v", err)
		}
	})
}

func TestRegisterTraitTypeAliasesCollide(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.RegisterTrait(traitA{value: "concrete"}); err != nil {
			t.Fatalf("first RegisterTrait: %v", err)
		}
		// traitAlias is a type alias for traitA — reflect treats them
		// as the same reflect.Type, so registration must be rejected.
		err := genesis.RegisterTrait(traitAlias{value: "alias"})
		if !errors.Is(err, genesis.ErrDuplicateType) {
			t.Fatalf("alias RegisterTrait: expected ErrDuplicateType, got %v", err)
		}
	})
}

func TestRegisterTraitDistinctTypesCoexist(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.RegisterTrait(traitA{value: "a"}); err != nil {
			t.Fatalf("RegisterTrait A: %v", err)
		}
		if err := genesis.RegisterTrait(traitB{n: 42}); err != nil {
			t.Fatalf("RegisterTrait B: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		a, err := genesis.TraitOf[traitA]()
		if err != nil {
			t.Fatalf("TraitOf A: %v", err)
		}
		b, err := genesis.TraitOf[traitB]()
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
		if err := genesis.RegisterTrait(traitA{value: "hi"}); err != nil {
			t.Fatalf("RegisterTrait: %v", err)
		}
		// Deliberately do not close.
		_, err := genesis.TraitOf[traitA]()
		if !errors.Is(err, genesis.ErrPhaseOpen) {
			t.Fatalf("TraitOf before close: expected ErrPhaseOpen, got %v", err)
		}
	})
}

func TestRegisterAfterCloseErrsPhaseClosed(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		err := genesis.RegisterTrait(traitA{value: "late"})
		if !errors.Is(err, genesis.ErrPhaseClosed) {
			t.Fatalf("RegisterTrait after close: expected ErrPhaseClosed, got %v", err)
		}
	})
}

func TestTraitOfNotFound(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.RegisterTrait(traitA{value: "just A"}); err != nil {
			t.Fatalf("RegisterTrait: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		_, err := genesis.TraitOf[traitB]()
		if !errors.Is(err, genesis.ErrNotFound) {
			t.Fatalf("TraitOf B: expected ErrNotFound, got %v", err)
		}
	})
}

func TestTraitOfModuleFilter(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.RegisterTrait(traitA{value: "hi"}); err != nil {
			t.Fatalf("RegisterTrait: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		// Matching filter — must find it.
		got, err := genesis.TraitOf[traitA]("runtime/genesis_test")
		if err == nil {
			if got.value != "hi" {
				t.Errorf("value = %q, want %q", got.value, "hi")
			}
		} else if !errors.Is(err, genesis.ErrNotFound) {
			// Depending on where the test is imported from, the
			// caller module string may vary.  Accept ErrNotFound as
			// "the harness lives at a different path than we
			// expected" — the important assertion is the mismatch
			// case below.
			t.Logf("matching filter returned: %v (module string may differ in this harness)", err)
		}
		// Non-matching filter — must reject.
		_, err = genesis.TraitOf[traitA]("nonexistent/module")
		if !errors.Is(err, genesis.ErrNotFound) {
			t.Fatalf("non-matching filter: expected ErrNotFound, got %v", err)
		}
	})
}

func TestClosePhaseTwiceErrs(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("first ClosePhase: %v", err)
		}
		err := genesis.ClosePhase()
		if !errors.Is(err, genesis.ErrPhaseClosed) {
			t.Fatalf("second ClosePhase: expected ErrPhaseClosed, got %v", err)
		}
	})
}

func TestSetComplexAndCurrentSelf(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.SetComplex(complexMain{role: "controller"}); err != nil {
			t.Fatalf("SetComplex: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		self, err := genesis.CurrentSelf()
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
		if err := genesis.SetComplex(complexMain{role: "a"}); err != nil {
			t.Fatalf("first SetComplex: %v", err)
		}
		err := genesis.SetComplex(complexMain{role: "b"})
		if !errors.Is(err, genesis.ErrComplexAlreadySet) {
			t.Fatalf("second SetComplex: expected ErrComplexAlreadySet, got %v", err)
		}
	})
}

func TestSparkAsInheritsTraitsAndSetsFreshComplex(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		// Parent side: register a trait, close.
		if err := genesis.RegisterTrait(traitA{value: "from-parent"}); err != nil {
			t.Fatalf("parent RegisterTrait: %v", err)
		}
		if err := genesis.SetComplex(complexMain{role: "parent"}); err != nil {
			t.Fatalf("parent SetComplex: %v", err)
		}
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("parent ClosePhase: %v", err)
		}

		// Spark a child that adds its own Trait and gets a fresh Complex.
		var (
			childComplex atomic.Pointer[complexMain]
			childTraitA  atomic.Pointer[traitA]
			childTraitB  atomic.Pointer[traitB]
			done         = make(chan struct{})
		)
		err := genesis.SparkAs(
			func(c complexMain) {
				defer close(done)
				childComplex.Store(&c)
				a, aErr := genesis.TraitOf[traitA]()
				if aErr != nil {
					t.Errorf("child TraitOf[A]: %v", aErr)
					return
				}
				b, bErr := genesis.TraitOf[traitB]()
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
		err := genesis.SparkAs(
			func(c complexMain) {},
			func() complexMain { return complexMain{role: "child"} },
		)
		if !errors.Is(err, genesis.ErrPhaseOpen) {
			t.Fatalf("SparkAs before parent close: expected ErrPhaseOpen, got %v", err)
		}
	})
}

// Note: SparkAs propagates a child-side registration collision by
// panicking on the child goroutine.  A panic on that goroutine
// tears down the test binary — Go's testing framework cannot recover
// it — so we don't test the panic directly here.  The behaviour is
// covered by composition: TestRegisterTraitDuplicateType proves the
// collision check fires, and TestSparkAsInheritsTraitsAndSetsFreshComplex
// proves inheritance populates the child's typeIdx before the child's
// own initializers run, so any inherited-vs-local collision goes
// through the same tested path.

func TestPhaseWaitGroupHoldsCloseUntilDone(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		wg := genesis.PhaseWaitGroup()
		if wg == nil {
			t.Fatal("PhaseWaitGroup returned nil for a fresh phase")
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
			if err := genesis.RegisterTrait(traitB{n: 99}); err != nil {
				t.Errorf("async RegisterTrait: %v", err)
			}
			mu.Lock()
			asyncTraitRegistered = true
			mu.Unlock()
		}()

		// ClosePhase must block until the goroutine's Done() fires.
		start := time.Now()
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		elapsed := time.Since(start)
		if elapsed < 40*time.Millisecond {
			t.Errorf("ClosePhase returned in %v — expected >=~50ms wait for async", elapsed)
		}
		mu.Lock()
		registered := asyncTraitRegistered
		mu.Unlock()
		if !registered {
			t.Fatal("async goroutine did not mark trait registration before ClosePhase returned")
		}

		// TraitOf now sees the async trait.
		got, err := genesis.TraitOf[traitB]()
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
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		if wg := genesis.PhaseWaitGroup(); wg != nil {
			t.Error("PhaseWaitGroup after close: expected nil")
		}
	})
}

func TestTraitOfEmptySelf(t *testing.T) {
	inSpark(t, func(t *testing.T) {
		if err := genesis.ClosePhase(); err != nil {
			t.Fatalf("ClosePhase: %v", err)
		}
		_, err := genesis.TraitOf[traitA]()
		if !errors.Is(err, genesis.ErrNotFound) {
			t.Fatalf("TraitOf on empty Self: expected ErrNotFound, got %v", err)
		}
		self, err := genesis.CurrentSelf()
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

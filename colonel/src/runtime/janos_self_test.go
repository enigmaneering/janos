package runtime_test

import (
	"fmt"
	"runtime"
	"testing"
)

func TestSelfReturnsNonNil(t *testing.T) {
	if runtime.Self() == nil {
		t.Fatal("runtime.Self() returned nil on main goroutine")
	}
}

func TestSelfStableOnSameGoroutine(t *testing.T) {
	a := runtime.Self()
	b := runtime.Self()
	if a != b {
		t.Fatal("runtime.Self() returned different pointers on the same goroutine")
	}
}

func TestSelfDistinctAcrossGoroutines(t *testing.T) {
	main := runtime.Self()
	type childResult struct {
		p any // any because the concrete type is unexported
	}
	ch := make(chan childResult, 1)
	go func() { ch <- childResult{p: runtime.Self()} }()
	child := (<-ch).p
	// We can't compare the unexported type directly, so compare
	// through fmt.Sprintf("%p", ...) which extracts addresses
	// without touching the type.  Two goroutines on distinct g
	// structs must present distinct addresses because _self is
	// stored inside gProvenance (a non-empty struct), which
	// prevents zero-size folding.
	if sprintP(main) == sprintP(child) {
		t.Fatalf("child goroutine Self() shares main's address: %s == %s",
			sprintP(main), sprintP(child))
	}
}

func TestSelfFirstClassFunctionValue(t *testing.T) {
	// runtime.Self is a first-class value that can be captured and
	// re-invoked, matching the "colonels share the function; each
	// side calls it locally" pattern.
	fn := runtime.Self
	if fn() == nil {
		t.Fatal("runtime.Self as a func value returned nil")
	}
	if fn() != runtime.Self() {
		t.Fatal("invoking runtime.Self via a captured func value gave a different result than direct invocation on the same goroutine")
	}
}

// sprintP renders a pointer's address as a string.  We can't do a
// real pointer comparison because the concrete type is unexported;
// fmt.Sprintf("%p", ...) reads the address without needing the type.
func sprintP(p any) string {
	return fmt.Sprintf("%p", p)
}

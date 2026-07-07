// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package genesis is JanOS's genetic-boot substrate.
//
// A goroutine's "sense of self" is a Self struct: a primary Complex
// value (the top-level classification of this execution) and a set of
// orthogonal Traits (secondary classifications, each type-unique).
// Every goroutine that has a JanOS identity has a Self; go-descendants
// share their parent's Self, spark-descendants (via SparkAs) get a
// fresh one built from parent-inherited Traits plus their own new
// contributions.
//
// Package inits contribute Traits at program boot: each package that
// calls RegisterTrait during its init() imprints one Trait on the main
// goroutine's Self.  Once every init has run, the main goroutine calls
// ClosePhase and Self "opens" — TraitOf begins returning values, and
// no further Traits can be registered on this identity.
//
// SparkAs spawns a fresh-identity goroutine whose Self is built the
// same way: parent's Traits are inherited verbatim, then the caller's
// variadic init functions contribute the child's own Complex and any
// new Traits, then the child's phase closes and its work function
// runs with a fully-formed Self.
//
// # Atomic-on-open
//
// Traits registered during a genesis phase are not observable via
// TraitOf until ClosePhase is called.  This makes the phase a
// well-defined transition: user code either sees no Self (before
// close) or a complete Self (after).  There is no partially-formed
// state visible to observers.
//
// # Async initialization
//
// PhaseWaitGroup returns the *sync.WaitGroup for the current phase.
// A trait initializer that needs to do background work calls
// wg.Add(1), spawns a goroutine, and that goroutine calls
// RegisterTrait followed by wg.Done before the goroutine exits.
// ClosePhase waits on the WaitGroup before freezing the phase — so
// async traits appear together with synchronous ones when the phase
// opens.
//
// # Uniqueness
//
// Within a single identity's Self, each Trait's Complex type is
// unique.  RegisterTrait rejects a second contribution of the same
// type on the same identity.  Independent Spark subtrees can each
// hold their own trait of the same type; the constraint is per-
// identity, not global.
//
// This restriction is currently enforced at runtime.  A future
// compiler pass will hoist most cases into compile-time errors.
//
// # Phase 1
//
// This package is the runtime-only surface of the genesis system.
// User code registers traits explicitly.  A subsequent compiler phase
// will make `func init() T` (and its *sync.WaitGroup variant)
// implicitly emit these calls, along with cross-package uniqueness
// checks at link time.  The runtime semantics won't change; the
// language surface will get thinner.
package genesis

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	_ "unsafe" // for go:linkname
)

// Trait is one package's contribution to a Self.  Module and Package
// record the fully qualified origin of the contribution — used by
// TraitOf's variadic filters when a type is (unusually) registered by
// more than one origin under different filter granularities.
//
// Complex is the value returned by that package's typed init function.
// It is stored as any and recovered by TraitOf via its generic type
// parameter.
type Trait struct {
	Module  string
	Package string
	Complex any
}

// Self is a running spark's classified execution surface: a top-level
// Complex (typed as any at this layer; recovered by callers when they
// know the concrete type) and a set of orthogonal Traits.
type Self struct {
	Complex any
	Traits  []Trait
}

// Sentinel errors surfaced by the package.
var (
	// ErrNoIdentity: the current goroutine has no JanOS identity block
	// (should not normally occur — main and every descendant have one).
	ErrNoIdentity = errors.New("genesis: no identity on current goroutine")

	// ErrPhaseOpen: TraitOf or CurrentSelf called before ClosePhase.
	// Self is not observable during the gathering phase.
	ErrPhaseOpen = errors.New("genesis: phase still open; Self is not yet observable")

	// ErrPhaseClosed: RegisterTrait or SetComplex called after
	// ClosePhase.  The Self is frozen and no further contributions
	// are permitted.
	ErrPhaseClosed = errors.New("genesis: phase already closed; Self is frozen")

	// ErrDuplicateType: RegisterTrait attempted to add a Trait whose
	// Complex type already exists in this Self (whether contributed
	// locally or inherited from a parent Spark).
	ErrDuplicateType = errors.New("genesis: trait type already registered on this identity")

	// ErrComplexAlreadySet: SetComplex called more than once on the
	// same phase.
	ErrComplexAlreadySet = errors.New("genesis: Complex already set on this identity")

	// ErrNotFound: TraitOf found no Trait matching the requested type
	// (and any filters).
	ErrNotFound = errors.New("genesis: no matching trait")

	// ErrAmbiguous: TraitOf found more than one Trait matching the
	// requested type (and any filters).  Add filters to narrow.
	ErrAmbiguous = errors.New("genesis: multiple matching traits; add filters")

	// ErrPhaseNotOpen: internal — the current identity has no active
	// phase.  Should not surface to well-formed callers.
	ErrPhaseNotOpen = errors.New("genesis: no active phase on this identity")
)

// selfState is the internal per-identity backing of a Self.  One
// instance per identityBlock; go-descendants share via the block,
// SparkAs children get a fresh one.  Registry keys are identityBlock
// addresses (obtained via linkname to runtime.janosIdentityBlockAddr).
type selfState struct {
	mu      sync.Mutex
	complex any
	traits  []Trait
	// typeIdx maps reflect.Type -> index into traits, for O(1)
	// uniqueness check and TraitOf lookup.
	typeIdx map[reflect.Type]int
	// wg is the phase's WaitGroup.  Async trait initializers Add/Done
	// on it; ClosePhase waits on it before freezing.
	wg sync.WaitGroup
	// frozen flips true when ClosePhase completes.  After that,
	// TraitOf and CurrentSelf answer; RegisterTrait and SetComplex
	// refuse.
	frozen bool
	// complexSet distinguishes "SetComplex explicitly called" from
	// "complex is still the zero value".
	complexSet bool
}

// registry maps identityBlock address -> selfState.  Populated
// lazily by stateForCurrent; entries are evicted when the identity
// block becomes GC-unreachable (via a finalizer hook installed in
// init).
var (
	registryMu sync.Mutex
	registry   = map[uintptr]*selfState{}
)

// runtimeIdentityBlockAddr is the (unexported) runtime helper that
// yields the identityBlock address behind an Identity value.  Reached
// via linkname because the block field is private to runtime.  The
// address serves as a lifecycle key; it is not dereference-able from
// this package.
//
//go:linkname runtimeIdentityBlockAddr runtime.janosIdentityBlockAddr
func runtimeIdentityBlockAddr(id runtime.Identity) uintptr

// runtimeRegisterBlockFinalizedHook lets us subscribe to block-death
// notifications from the runtime finalizer goroutine.  We use this to
// evict our registry entry so a long-running program doesn't leak
// selfStates for GC'd identities.
//
//go:linkname runtimeRegisterBlockFinalizedHook runtime.janosRegisterBlockFinalizedHook
func runtimeRegisterBlockFinalizedHook(fn func(uintptr))

func init() {
	runtimeRegisterBlockFinalizedHook(onBlockFinalized)
}

// onBlockFinalized runs on the runtime finalizer goroutine when an
// identityBlock becomes GC-unreachable.  Drops the state entry so
// this package doesn't hold the selfState after nothing references
// the identity anymore.
func onBlockFinalized(addr uintptr) {
	registryMu.Lock()
	delete(registry, addr)
	registryMu.Unlock()
}

// stateForCurrent returns the selfState for the current goroutine's
// identity, allocating one on first use.  Returns nil if the current
// goroutine has no identity block.
func stateForCurrent() *selfState {
	addr := runtimeIdentityBlockAddr(runtime.Identify())
	if addr == 0 {
		return nil
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if st, ok := registry[addr]; ok {
		return st
	}
	st := &selfState{typeIdx: map[reflect.Type]int{}}
	registry[addr] = st
	return st
}

// callerOrigin walks the call stack to find the first frame outside
// this package.  Returns (module, package) parsed from the fully
// qualified function name.  Best-effort: on stripped or inlined
// builds, either field may be empty.
func callerOrigin() (module, pkg string) {
	// Skip: 0 runtime.Callers, 1 callerOrigin, 2 exported wrapper
	// (RegisterTrait/SetComplex), 3 user code.
	var pcs [8]uintptr
	n := runtime.Callers(3, pcs[:])
	if n == 0 {
		return "", ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if f.Function == "" {
			if !more {
				return "", ""
			}
			continue
		}
		// f.Function is like "github.com/enigmaneering/janos/example/pkg.init.0"
		// Split at the last "/" to isolate the package tail from
		// the module prefix; then split at the final "." to get
		// the package name.
		module, pkg = parseFuncOrigin(f.Function)
		if pkg != "" {
			return module, pkg
		}
		if !more {
			return "", ""
		}
	}
}

// parseFuncOrigin extracts (module, package) from a fully qualified
// function name like "example.com/foo/bar.Baz" -> ("example.com/foo",
// "bar").  Nested types (methods on struct/interface) show up with a
// "*Type." or "Type." suffix on the receiver — we strip everything
// past the first "." after the last "/".
func parseFuncOrigin(fn string) (module, pkg string) {
	slash := -1
	for i := len(fn) - 1; i >= 0; i-- {
		if fn[i] == '/' {
			slash = i
			break
		}
	}
	// Look for the "." that separates package from symbol.  On a
	// no-slash function name (e.g. "main.init"), scan from the start.
	dot := -1
	scanStart := 0
	if slash != -1 {
		scanStart = slash + 1
	}
	for i := scanStart; i < len(fn); i++ {
		if fn[i] == '.' {
			dot = i
			break
		}
	}
	if dot == -1 {
		return "", ""
	}
	if slash == -1 {
		return "", fn[:dot]
	}
	return fn[:slash], fn[slash+1 : dot]
}

// RegisterTrait contributes t as a Trait on the current goroutine's
// Self.  The Trait's Module and Package are derived from the caller's
// fully qualified function name.
//
// Errors:
//
//   - ErrNoIdentity if the current goroutine has no identity block.
//   - ErrPhaseClosed if ClosePhase has already been called.
//   - ErrDuplicateType if a Trait of type T is already registered on
//     this identity (either locally or inherited from a parent Spark).
//
// The registered Trait is not observable via TraitOf until ClosePhase
// completes.
func RegisterTrait[T any](t T) error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	typ := reflect.TypeOf((*T)(nil)).Elem()
	module, pkg := callerOrigin()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return ErrPhaseClosed
	}
	if existing, dup := st.typeIdx[typ]; dup {
		return fmt.Errorf("%w: %v already contributed by %s/%s",
			ErrDuplicateType, typ,
			st.traits[existing].Module, st.traits[existing].Package)
	}
	st.traits = append(st.traits, Trait{
		Module:  module,
		Package: pkg,
		Complex: t,
	})
	st.typeIdx[typ] = len(st.traits) - 1
	return nil
}

// SetComplex records t as the primary Complex of the current
// goroutine's Self.  For a main goroutine this is called from the
// main package's typed init; for a SparkAs child it is called
// internally by SparkAs and users need not invoke it themselves.
//
// Errors:
//
//   - ErrNoIdentity if the current goroutine has no identity block.
//   - ErrPhaseClosed if ClosePhase has already been called.
//   - ErrComplexAlreadySet if SetComplex was already invoked on this
//     phase.
func SetComplex[T any](t T) error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return ErrPhaseClosed
	}
	if st.complexSet {
		return ErrComplexAlreadySet
	}
	st.complex = t
	st.complexSet = true
	return nil
}

// PhaseWaitGroup returns the *sync.WaitGroup for the current
// identity's genesis phase.  Callers that need to do background work
// before the phase closes should Add(1) before spawning the goroutine
// and Done() from within it (after any RegisterTrait call).
// ClosePhase blocks on this WaitGroup before freezing the phase, so
// async trait registrations complete before Self opens.
//
// Returns nil if the current goroutine has no identity block or the
// phase has already closed.
func PhaseWaitGroup() *sync.WaitGroup {
	st := stateForCurrent()
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return nil
	}
	return &st.wg
}

// ClosePhase freezes the current goroutine's genesis phase.  Blocks
// until any background work Add-ed to PhaseWaitGroup has completed.
// After ClosePhase returns:
//
//   - RegisterTrait and SetComplex refuse further contributions.
//   - TraitOf and CurrentSelf begin returning the assembled Self.
//
// Calling ClosePhase twice on the same identity returns
// ErrPhaseClosed.
func ClosePhase() error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	// Take the mutex briefly to check state, then release for Wait to
	// avoid holding the mutex while background goroutines might want
	// to RegisterTrait.
	st.mu.Lock()
	if st.frozen {
		st.mu.Unlock()
		return ErrPhaseClosed
	}
	st.mu.Unlock()
	// Wait outside the mutex so async initializers can register.
	st.wg.Wait()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		// Someone else raced us to close.  Idempotent-ish, but flag
		// the double-close as an error so callers notice.
		return ErrPhaseClosed
	}
	st.frozen = true
	return nil
}

// CurrentSelf returns the current goroutine's Self.  Errors with
// ErrPhaseOpen if ClosePhase has not been called yet; errors with
// ErrNoIdentity if the current goroutine has no identity block.
//
// The returned Self's Traits slice is a fresh copy — callers may
// mutate it freely without affecting the underlying state.
func CurrentSelf() (Self, error) {
	st := stateForCurrent()
	if st == nil {
		return Self{}, ErrNoIdentity
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.frozen {
		return Self{}, ErrPhaseOpen
	}
	traits := make([]Trait, len(st.traits))
	copy(traits, st.traits)
	return Self{Complex: st.complex, Traits: traits}, nil
}

// TraitOf returns the Trait of type T from the current goroutine's
// Self.  Filters narrow the search: zero filters searches all
// traits; one filter matches Module; two filters match (Module,
// Package).
//
// Errors:
//
//   - ErrNoIdentity if the current goroutine has no identity block.
//   - ErrPhaseOpen if ClosePhase has not been called yet.
//   - ErrNotFound if no trait matches the type-and-filters.
//   - ErrAmbiguous if more than one trait matches.
func TraitOf[T any](filters ...string) (T, error) {
	var zero T
	st := stateForCurrent()
	if st == nil {
		return zero, ErrNoIdentity
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.frozen {
		return zero, ErrPhaseOpen
	}
	typ := reflect.TypeOf((*T)(nil)).Elem()
	// Fast path: no filters, unique registration -> typeIdx lookup.
	if len(filters) == 0 {
		if idx, ok := st.typeIdx[typ]; ok {
			return st.traits[idx].Complex.(T), nil
		}
		return zero, ErrNotFound
	}
	// With filters we scan (traits are typically small).
	var matchedIdx = -1
	for i, tr := range st.traits {
		if reflect.TypeOf(tr.Complex) != typ {
			continue
		}
		if len(filters) >= 1 && tr.Module != filters[0] {
			continue
		}
		if len(filters) >= 2 && tr.Package != filters[1] {
			continue
		}
		if matchedIdx != -1 {
			return zero, ErrAmbiguous
		}
		matchedIdx = i
	}
	if matchedIdx == -1 {
		return zero, ErrNotFound
	}
	return st.traits[matchedIdx].Complex.(T), nil
}

// SparkAs spawns a fresh-identity goroutine, runs a genesis phase on
// it, and then invokes work with the resulting Complex.
//
// Genesis on the child:
//
//  1. The parent's Traits are inherited verbatim (parent must have
//     ClosePhase'd; otherwise ErrPhaseOpen is returned to the parent).
//  2. complexInit runs on the child and its result becomes Self.Complex.
//  3. Each function in traitInits runs on the child; its result is
//     registered as a Trait (type-erased through the variadic; the
//     runtime uses reflect to derive type identity for uniqueness).
//  4. The child's phase closes.
//  5. work runs on the child with the freshly-produced Complex.
//
// A Trait registered by a traitInit whose type collides with an
// inherited Trait panics on the child — child code cannot silently
// override an inherited classification.
func SparkAs[TC any](
	work func(TC),
	complexInit func() TC,
	traitInits ...func() any,
) error {
	if work == nil {
		return errors.New("genesis: SparkAs work function is nil")
	}
	if complexInit == nil {
		return errors.New("genesis: SparkAs complexInit is nil")
	}
	parentSelf, err := CurrentSelf()
	if err != nil {
		return fmt.Errorf("genesis: SparkAs called on parent whose phase is not closed: %w", err)
	}
	runtime.Spark(func() {
		st := stateForCurrent()
		if st == nil {
			panic("genesis: SparkAs child has no identity block")
		}
		// Inherit parent's traits under the mutex, then release for
		// user init to be able to RegisterTrait via the exported API.
		st.mu.Lock()
		for _, tr := range parentSelf.Traits {
			typ := reflect.TypeOf(tr.Complex)
			st.typeIdx[typ] = len(st.traits)
			st.traits = append(st.traits, tr)
		}
		st.mu.Unlock()

		// Complex is the child's own — call complexInit on the child
		// so it can observe the child's identity if it wants.
		c := complexInit()
		if err := SetComplex(c); err != nil {
			panic(fmt.Errorf("genesis: SparkAs SetComplex failed: %w", err))
		}
		// Trait initializers.  Type-erased through the variadic.
		for i, init := range traitInits {
			if init == nil {
				panic(fmt.Errorf("genesis: SparkAs traitInit[%d] is nil", i))
			}
			v := init()
			if err := registerTraitAny(v); err != nil {
				panic(fmt.Errorf("genesis: SparkAs traitInit[%d] failed: %w", i, err))
			}
		}
		if err := ClosePhase(); err != nil {
			panic(fmt.Errorf("genesis: SparkAs ClosePhase failed: %w", err))
		}
		work(c)
	})
	return nil
}

// registerTraitAny is the internal type-erased helper used by
// SparkAs.  It registers v as a Trait using reflect.TypeOf(v) as the
// uniqueness key.  Called from inside SparkAs on the child goroutine.
func registerTraitAny(v any) error {
	if v == nil {
		return errors.New("genesis: cannot register nil trait")
	}
	typ := reflect.TypeOf(v)
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	// Origin here would be SparkAs itself; walk one more frame back
	// to find the caller of SparkAs.
	module, pkg := callerOrigin()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return ErrPhaseClosed
	}
	if existing, dup := st.typeIdx[typ]; dup {
		return fmt.Errorf("%w: %v already contributed by %s/%s",
			ErrDuplicateType, typ,
			st.traits[existing].Module, st.traits[existing].Package)
	}
	st.traits = append(st.traits, Trait{
		Module:  module,
		Package: pkg,
		Complex: v,
	})
	st.typeIdx[typ] = len(st.traits) - 1
	return nil
}

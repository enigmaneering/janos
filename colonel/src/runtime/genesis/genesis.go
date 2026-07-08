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
// # Public API
//
// Registration:
//
//   - Register[T](func() T) T — contribute a Trait; idiomatic use is
//     `var _ = genesis.Register(func() T { ... })` at package scope.
//   - SetMainComplex[T](func() T) T — set the primary Complex; only
//     the main package should call this.
//   - RegisterAsync[T](func(*sync.WaitGroup) T) T — like Register but
//     the init function receives the phase's WaitGroup for background
//     work.  The phase does not close until all Add-ed work drains.
//
// Query and spawning:
//
//   - TraitOf[T](filters ...string) — query a trait by type,
//     optionally narrowed by module and/or package.
//   - CurrentSelf() — read the assembled Self.
//   - SparkAs[TC] — spawn a fresh-identity goroutine with its own
//     genesis phase.
//
// The runtime automatically closes the main goroutine's phase after
// package init completes, before main.main runs.  Users never invoke
// the close explicitly for the top-level phase; SparkAs handles the
// close for child phases internally.
//
// # Language integration
//
// In the intended shape of the JanOS/Glitter stack, the Register /
// SetMainComplex / RegisterAsync surface is what the Glitter compiler
// lowers to when user code writes:
//
//	func init() T                        // Register
//	func init() T             in main    // SetMainComplex
//	func init(wg *sync.WaitGroup) T      // RegisterAsync
//
// The runtime substrate does not require compiler surgery — Glitter
// carries the ergonomic weight of the source syntax and emits plain
// Go that JanOS runs.
//
// # Atomic-on-open
//
// The phase transitions atomically from "gathering" to "open".
// Traits contributed during gathering are not observable via TraitOf
// until the phase closes; once it does, they all become observable
// together.  User code sees either no Self or a complete Self —
// never a partially-formed one.
//
// # Uniqueness
//
// Within a single identity's Self, each Trait's Complex type is
// unique.  Independent Spark subtrees can each hold their own trait
// of the same type; the constraint is per-identity, not global.
// A future compiler pass will lift most cases into compile-time
// errors.
//
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
// record the fully qualified origin of the contribution — surfaced
// so TraitOf's variadic filters can disambiguate when a type is
// contributed under different origins.
//
// Complex is the value produced by that package's typed init
// function.  It is stored as any and recovered by TraitOf via its
// generic type parameter.
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

// Sentinel errors returned by the public API.
var (
	// ErrNoIdentity: the current goroutine has no JanOS identity block.
	// Should not normally occur — main and every descendant have one.
	ErrNoIdentity = errors.New("genesis: no identity on current goroutine")

	// ErrPhaseOpen: TraitOf, CurrentSelf, or SparkAs (on the parent)
	// was called before the current identity's genesis phase closed.
	// Self is not observable during the gathering phase.
	ErrPhaseOpen = errors.New("genesis: phase still open; Self is not yet observable")

	// ErrNotFound: TraitOf found no Trait matching the requested type
	// (and any filters).
	ErrNotFound = errors.New("genesis: no matching trait")

	// ErrAmbiguous: TraitOf found more than one Trait matching the
	// requested type (and any filters).  Add filters to narrow.
	ErrAmbiguous = errors.New("genesis: multiple matching traits; add filters")
)

// Internal-only sentinel errors.  Surface through panics from
// compiler-emitted code (or SparkAs's child) when the invariants
// they guard are violated.
var (
	errPhaseClosed       = errors.New("genesis: phase already closed; Self is frozen")
	errDuplicateType     = errors.New("genesis: trait type already registered on this identity")
	errComplexAlreadySet = errors.New("genesis: Complex already set on this identity")
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
	// on it; closePhase waits on it before freezing.
	wg sync.WaitGroup
	// frozen flips true when closePhase completes.  After that,
	// TraitOf and CurrentSelf answer; registerTrait and setComplex
	// refuse.
	frozen bool
	// complexSet distinguishes "setComplex explicitly called" from
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

// runtimeSetGenesisClosePhaseHook installs the main-goroutine
// phase-close callback that runtime.main invokes between doInit and
// main.main.  We register at package-init time so the runtime has
// the hook in place well before doInit completes.
//
//go:linkname runtimeSetGenesisClosePhaseHook runtime.janosSetGenesisClosePhaseHook
func runtimeSetGenesisClosePhaseHook(fn func())

func init() {
	runtimeRegisterBlockFinalizedHook(onBlockFinalized)
	runtimeSetGenesisClosePhaseHook(mainPhaseCloseHook)
}

// mainPhaseCloseHook is the function runtime.main invokes to close
// the main goroutine's genesis phase.  Errors from closePhase are
// impossible in the normal path (main was the sole registrant during
// doInit and no one has closed the phase yet), so we surface them as
// a panic — the program should crash loudly rather than silently
// leave Self malformed.
func mainPhaseCloseHook() {
	if err := closePhase(); err != nil {
		panic(fmt.Errorf("genesis: main-goroutine closePhase failed: %w", err))
	}
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
	// Skip: 0 runtime.Callers, 1 callerOrigin, 2 internal wrapper
	// (registerTrait/setComplex), 3 user code.
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

// registerTrait contributes t as a Trait on the current goroutine's
// Self.  Called by compiler-emitted code for each package that has a
// typed `func init() T`; not part of the public API.
//
// The Trait's Module and Package are derived from the caller's fully
// qualified function name.
//
// Errors: ErrNoIdentity, errPhaseClosed, errDuplicateType.
func registerTrait[T any](t T) error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	typ := reflect.TypeOf((*T)(nil)).Elem()
	module, pkg := callerOrigin()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return errPhaseClosed
	}
	if existing, dup := st.typeIdx[typ]; dup {
		return fmt.Errorf("%w: %v already contributed by %s/%s",
			errDuplicateType, typ,
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

// setComplex records t as the primary Complex of the current
// goroutine's Self.  For a main goroutine this is emitted by the
// compiler from the main package's typed init; for a SparkAs child
// SparkAs invokes it directly.  Not part of the public API.
//
// Errors: ErrNoIdentity, errPhaseClosed, errComplexAlreadySet.
func setComplex[T any](t T) error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return errPhaseClosed
	}
	if st.complexSet {
		return errComplexAlreadySet
	}
	st.complex = t
	st.complexSet = true
	return nil
}

// phaseWaitGroup returns the *sync.WaitGroup for the current
// identity's genesis phase.  Compiler-emitted async initializers
// (from `func init(wg *sync.WaitGroup) T`) receive this WG.  Not
// part of the public API.
//
// Returns nil if the current goroutine has no identity block or the
// phase has already closed.
func phaseWaitGroup() *sync.WaitGroup {
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

// closePhase freezes the current goroutine's genesis phase.  Blocks
// until any background work Add-ed to phaseWaitGroup has completed.
// Emitted by the compiler at the end of the program-init sequence and
// invoked internally by SparkAs before its work function runs.  Not
// part of the public API.
//
// Errors: ErrNoIdentity, errPhaseClosed.
func closePhase() error {
	st := stateForCurrent()
	if st == nil {
		return ErrNoIdentity
	}
	// Take the mutex briefly to check state, then release for Wait to
	// avoid holding the mutex while background goroutines might want
	// to registerTrait.
	st.mu.Lock()
	if st.frozen {
		st.mu.Unlock()
		return errPhaseClosed
	}
	st.mu.Unlock()
	// Wait outside the mutex so async initializers can register.
	st.wg.Wait()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return errPhaseClosed
	}
	st.frozen = true
	return nil
}

// CurrentSelf returns the current goroutine's Self.  Errors with
// ErrPhaseOpen if the phase has not closed yet; errors with
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
// Errors: ErrNoIdentity, ErrPhaseOpen, ErrNotFound, ErrAmbiguous.
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
	matchedIdx := -1
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

// Register runs init immediately, contributes the result as a Trait
// on the current goroutine's Self, and returns the same value so it
// can be captured by the caller.
//
// The idiomatic use is a package-level variable initializer, which
// Go invokes during package init in dependency-topological order:
//
//	package pwm
//
//	var Bus = genesis.Register(func() *Bus {
//	    return &Bus{...}
//	})
//
// Register panics on any registration error (identity missing,
// phase already closed, duplicate type on this identity).  These
// conditions represent program bugs — silently ignoring them would
// leave Self malformed — so the program terminates loudly.
//
// This function replaces what a `func init() T` signature would
// express with compiler support.  When Glitter emits its lowering
// to Go, it produces the equivalent Register call.
func Register[T any](init func() T) T {
	v := init()
	if err := registerTrait(v); err != nil {
		panic(fmt.Errorf("genesis: Register failed: %w", err))
	}
	return v
}

// SetMainComplex runs init immediately, records the result as the
// primary Complex of the main goroutine's Self, and returns the same
// value so it can be captured by the caller.
//
// The idiomatic use is in the main package:
//
//	package main
//
//	var Self = genesis.SetMainComplex(func() *App {
//	    return &App{...}
//	})
//
// SetMainComplex panics on any error (identity missing, phase
// already closed, Complex already set on this identity).  Only the
// main package should call this — a non-main package that does so
// will race with main's contribution and produce ErrComplexAlreadySet.
//
// This function replaces what a `func init() T` in the main package
// would express with compiler support.
func SetMainComplex[T any](init func() T) T {
	v := init()
	if err := setComplex(v); err != nil {
		panic(fmt.Errorf("genesis: SetMainComplex failed: %w", err))
	}
	return v
}

// RegisterAsync runs init immediately, passing the current genesis
// phase's *sync.WaitGroup, contributes init's return as a Trait, and
// returns the same value so it can be captured.  The caller decides
// what background work to attach to the WaitGroup — the phase does
// not close until every wg.Add is matched by a wg.Done.
//
// The idiomatic use, in a package that needs to do slow init work
// without blocking the whole genesis phase:
//
//	package hardware
//
//	var Radio = genesis.RegisterAsync(func(wg *sync.WaitGroup) *Radio {
//	    r := &Radio{}
//	    wg.Add(1)
//	    go func() {
//	        defer wg.Done()
//	        r.Calibrate()  // takes 200ms
//	    }()
//	    return r
//	})
//
// The returned Radio is immediately visible in Self (once the phase
// closes), but the caller can rely on Self opening only after all
// async work has drained.
//
// Panics on registration errors, same as Register.
//
// This function replaces what a `func init(wg *sync.WaitGroup) T`
// signature would express with compiler support.
func RegisterAsync[T any](init func(*sync.WaitGroup) T) T {
	wg := phaseWaitGroup()
	if wg == nil {
		panic(fmt.Errorf("genesis: RegisterAsync called with no active phase (already closed?)"))
	}
	v := init(wg)
	if err := registerTrait(v); err != nil {
		panic(fmt.Errorf("genesis: RegisterAsync failed: %w", err))
	}
	return v
}

// SparkAs spawns a fresh-identity goroutine, runs a genesis phase on
// it, and then invokes work with the resulting Complex.
//
// Genesis on the child:
//
//  1. The parent's Traits are inherited verbatim (parent must have
//     closed its phase; otherwise ErrPhaseOpen is returned).
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
		// user init to be able to registerTrait via the internal
		// helper.
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
		if err := setComplex(c); err != nil {
			panic(fmt.Errorf("genesis: SparkAs setComplex failed: %w", err))
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
		if err := closePhase(); err != nil {
			panic(fmt.Errorf("genesis: SparkAs closePhase failed: %w", err))
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
	module, pkg := callerOrigin()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.frozen {
		return errPhaseClosed
	}
	if existing, dup := st.typeIdx[typ]; dup {
		return fmt.Errorf("%w: %v already contributed by %s/%s",
			errDuplicateType, typ,
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

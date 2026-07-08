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
//   - Register(any) any — contribute a Trait.  Idiomatic use is
//     `var Bus = genesis.Register(func() *Bus { ... }).(*Bus)` at
//     package scope.  Register accepts one of three shapes and
//     dispatches at runtime:
//   - a plain value T                  → registered directly
//   - a function `func() T`            → invoked, result registered
//   - `func(*sync.WaitGroup) T`        → invoked with the phase WG,
//     result registered (async init)
//     Register MUST be called during package init — an invocation
//     from any other scope panics loudly with a message describing
//     the required pattern.
//   - TraitOf[T](filters ...string) — query a trait by type,
//     optionally narrowed by module and/or package.
//   - CurrentSelf() — read the assembled Self (the frozen bag of
//     Traits for this goroutine's identity).  Self.Inception()
//     reports the moment the spark was created: schedinit's identity
//     mint for main, the top of the SparkAs call for children.
//   - SparkAs[TC] — spawn a fresh-identity goroutine with its own
//     genesis phase; the primary init produces the value that the
//     child's work function receives directly.
//
// The runtime automatically closes the main goroutine's phase after
// package init completes and before main.main runs.  Users never
// invoke the close explicitly for the top-level phase; SparkAs
// handles the close for child phases internally.
//
// # Exit
//
// Deferral mirrors genesis at both scales.  Two identities are
// implicitly recognizable to every line of code — the program
// (runtime) and the current spark (self) — and each has a Defer:
//
//   - Defer(func(*sync.WaitGroup)) — run at process shutdown
//     (main.main returning, or os.Exit).
//   - DeferSelf(func(*sync.WaitGroup)) — run at the current spark's
//     exit (its SparkAs work function returning).  From the main
//     identity this is equivalent to Defer, because main's
//     self-lifetime is the process lifetime.
//
// Cleanups run LIFO and receive the exit WaitGroup — the same async
// idiom initialization uses: cleanup that can proceed in the
// background does wg.Add(1) and wg.Done, and the exiting scope does
// not complete until the group drains.  Deferral is registered
// beside the creation code it unwinds; there is deliberately no
// init-time registration form, because cleanup only exists once
// something real has been created.
//
// # Language integration
//
// In the intended shape of the JanOS/Glitter stack, Register is what
// the Glitter compiler lowers to when user source writes any of:
//
//	func init() T
//	func init(wg *sync.WaitGroup) T
//
// The runtime substrate takes no compiler surgery — Glitter carries
// the ergonomic weight of the source syntax and emits plain Go that
// JanOS runs.
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
// # Missing identity is fatal
//
// Every JanOS goroutine has an identity: schedinit mints main's,
// `go` inherits the parent's pointer, janosSpark mints fresh
// identities for spark children.  If any API in this package
// discovers the current goroutine has NO identity block, the
// runtime security invariant has been violated — either a runtime
// bug or a tampered process state — and the package writes a
// diagnostic to stderr, dumps every goroutine's stack, and calls
// os.Exit(2).  There is no exported ErrNoIdentity because user code
// cannot recover from it.
//
package genesis

import (
	"errors"
	"fmt"
	"internal/runtime/exithook"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"
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

// Self is a running spark's classified execution surface: a bag of
// Traits, each classified by the type of its Complex.  Main's
// contribution appears as one of the Traits (Package == "main");
// downstream code can find it via TraitOf[T](...) or by filter.
type Self struct {
	Traits []Trait
	// inception is when this spark came into being.  Unexported so a
	// Self cannot be forged with a fabricated birth time; read it via
	// the Inception method.
	inception time.Time
}

// Inception returns the moment this spark was created.
//
// For the main identity this is stamped at schedinit — when the
// runtime mints the program's identity, before any package init or
// user code runs.  For a SparkAs child it is captured as the very
// first action of the SparkAs call, on the parent's goroutine,
// before the child is spawned.  Goroutines sharing an identity via
// `go` inheritance share their spark's inception.
func (s Self) Inception() time.Time {
	return s.inception
}

// Sentinel errors returned by the public API.
var (
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

// fatalMissingIdentity terminates the process when the current
// goroutine is discovered to have no JanOS identity block.  Under
// normal runtime operation this cannot happen: schedinit mints the
// main goroutine's identity, `go` descendants inherit their parent's
// pointer, and janosSpark mints fresh identities for spark children.
// A missing identity would mean either a runtime bug or an actively
// tampered process state — either way, we cannot trust anything the
// caller is trying to do (registration, query, spawn), and continuing
// would violate the security posture the whole substrate is built to
// hold.
//
// So we write a diagnostic to stderr, dump every goroutine's stack
// for the incident report, and os.Exit(2).  No possibility of
// recover().  No cleanup handlers.  The program is gone.
func fatalMissingIdentity(where string) {
	fmt.Fprintf(os.Stderr,
		"genesis: FATAL: %s called on a goroutine with no JanOS identity — "+
			"runtime security invariant violated; aborting\n",
		where)
	var buf [8192]byte
	n := runtime.Stack(buf[:], true)
	os.Stderr.Write(buf[:n])
	os.Exit(2)
}

// Internal-only sentinel errors.  Surface through panics from
// Register or SparkAs's child when the invariants they guard are
// violated.
var (
	errPhaseClosed   = errors.New("genesis: phase already closed; Self is frozen")
	errDuplicateType = errors.New("genesis: trait type already registered on this identity")
)

// selfState is the internal per-identity backing of a Self.  One
// instance per identityBlock; go-descendants share via the block,
// SparkAs children get a fresh one.  Registry keys are identityBlock
// addresses (obtained via linkname to runtime.janosIdentityBlockAddr).
type selfState struct {
	mu     sync.Mutex
	traits []Trait
	// typeIdx maps reflect.Type -> index into traits, for O(1)
	// uniqueness check and TraitOf lookup.
	typeIdx map[reflect.Type]int
	// wg is the phase's WaitGroup.  Async trait initializers Add/Done
	// on it; closePhase waits on it before freezing.
	wg sync.WaitGroup
	// frozen flips true when closePhase completes.  After that,
	// TraitOf and CurrentSelf answer; registerTrait refuses.
	frozen bool
	// deferred holds this identity's spark-exit cleanups, registered
	// via DeferSelf.  Drained LIFO when the spark's work function
	// returns (or panics).  Unlike traits, registration is allowed at
	// any point in the spark's life — cleanup code appears wherever
	// the resource it releases was created.
	deferred []func(*sync.WaitGroup)
	// inception is when this spark came into being.  Main's is the
	// runtime's boot walltime stamp (schedinit); a SparkAs child's is
	// captured at the top of the SparkAs call.  Identities minted
	// outside the public lifecycle (internal test paths) leave it
	// zero.
	inception time.Time
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

// runtimeJanosSpark is runtime.janosSpark reached via linkname.  It
// mints a fresh identity, spawns a goroutine on it, and runs f.  The
// primitive is unexported in runtime because SparkAs is the only
// public path a spark should take — direct primitive access would
// allow spawning a fresh identity without engaging the genesis phase
// machinery, which is exactly the misuse we're preventing.
//
//go:linkname runtimeJanosSpark runtime.janosSpark
func runtimeJanosSpark(f func())

// runtimeBootWalltime is runtime.janosBootWalltime reached via
// linkname: the wall-clock stamp taken at schedinit when the main
// goroutine's identity was minted.  Backs Self.Inception for the
// main identity.
//
//go:linkname runtimeBootWalltime runtime.janosBootWalltime
func runtimeBootWalltime() (int64, int32)

func init() {
	runtimeRegisterBlockFinalizedHook(onBlockFinalized)
	runtimeSetGenesisClosePhaseHook(mainPhaseCloseHook)
	// Package inits run on the main goroutine, so the identity we see
	// here IS main's.  Recorded so DeferSelf can recognize "self ==
	// the program" and route to the process-shutdown registry.
	mainBlockAddr = runtimeIdentityBlockAddr(runtime.Identify())
	// Process-shutdown deferrals ride the runtime's exit-hook
	// machinery, which fires both when main.main returns and when
	// os.Exit is called.  RunOnFailure: cleanup still runs on nonzero
	// exits — a de-energize-the-servo cleanup matters MORE on failure
	// paths, not less.  (Panics and runtime throws never run exit
	// hooks; deferral is for orderly exits only.)
	exithook.Add(exithook.Hook{F: drainShutdown, RunOnFailure: true})
}

// mainBlockAddr is the identityBlock address of the main goroutine,
// captured at package-init time (inits run on the main goroutine).
var mainBlockAddr uintptr

// shutdown is the process-level deferral registry.  Drained LIFO by
// drainShutdown when the program exits.
var shutdown struct {
	mu    sync.Mutex
	funcs []func(*sync.WaitGroup)
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
	if addr == mainBlockAddr {
		// Main's inception is the runtime's schedinit stamp — the
		// moment the program's identity was minted, before any
		// package init ran.
		sec, nsec := runtimeBootWalltime()
		st.inception = time.Unix(sec, int64(nsec))
	}
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
// Errors: errPhaseClosed, errDuplicateType.  A missing identity is
// fatal (the process aborts) rather than returned as an error.
func registerTrait[T any](t T) error {
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("registerTrait")
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

// phaseWaitGroup returns the *sync.WaitGroup for the current
// identity's genesis phase.  Compiler-emitted async initializers
// (from `func init(wg *sync.WaitGroup) T`) receive this WG.  Not
// part of the public API.
//
// Returns nil if the phase has already closed.  A missing identity
// is fatal, matching the rest of the package's contract.
func phaseWaitGroup() *sync.WaitGroup {
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("phaseWaitGroup")
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
// Errors: errPhaseClosed.  A missing identity is fatal.
func closePhase() error {
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("closePhase")
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
// ErrPhaseOpen if the phase has not closed yet.  A missing identity
// is fatal — the process terminates rather than returning an error,
// since a missing identity means the runtime security invariant has
// been violated.
//
// The returned Self's Traits slice is a fresh copy — callers may
// mutate it freely without affecting the underlying state.
func CurrentSelf() (Self, error) {
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("CurrentSelf")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.frozen {
		return Self{}, ErrPhaseOpen
	}
	traits := make([]Trait, len(st.traits))
	copy(traits, st.traits)
	return Self{Traits: traits, inception: st.inception}, nil
}

// TraitOf returns the Trait of type T from the current goroutine's
// Self.  Filters narrow the search: zero filters searches all
// traits; one filter matches Module; two filters match (Module,
// Package).
//
// Errors: ErrPhaseOpen, ErrNotFound, ErrAmbiguous.  A missing
// identity is fatal (see CurrentSelf).
func TraitOf[T any](filters ...string) (T, error) {
	var zero T
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("TraitOf")
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

// waitGroupType is the reflect.Type of *sync.WaitGroup, precomputed
// once for use by Register's function-shape dispatch.
var waitGroupType = reflect.TypeOf((*sync.WaitGroup)(nil))

// Register contributes something to the current goroutine's Self and
// returns the registered value as any.  The caller casts back to the
// concrete type at the callsite:
//
//	var Bus = genesis.Register(func() *Bus { return &Bus{...} }).(*Bus)
//	var App = genesis.Register(func() *App { return &App{...} }).(*App)
//	var Radio = genesis.Register(func(wg *sync.WaitGroup) *Radio {
//	    r := &Radio{}
//	    wg.Add(1)
//	    go func() { defer wg.Done(); r.Calibrate() }()
//	    return r
//	}).(*Radio)
//
// Register dispatches at runtime based on what it receives:
//
//   - A function `func() T` — invoked; result registered as a Trait.
//   - `func(*sync.WaitGroup) T` — invoked with the phase's WaitGroup;
//     result registered.  Async work Add-ed to the WG holds the
//     phase open until Done fires.
//   - Any other value — registered directly as a Trait.
//
// Functions with unsupported shapes (multiple returns, non-WG
// arguments, no return) panic with a descriptive message rather
// than being silently registered as function-valued traits.
//
// Register MUST be called during package init.  Invoking it from
// anywhere else — main.main, a spawned goroutine at runtime, a
// SparkAs work function — panics loudly with a message describing
// the required `var _ = genesis.Register(...)` at package-scope
// pattern.  A misused Register would leave Self malformed or
// silently drop contributions, which is worse than a boot-time
// crash.
//
// In the JanOS/Glitter stack, Register is what the Glitter compiler
// lowers to when user source writes `func init() T` or
// `func init(wg *sync.WaitGroup) T`.  Direct use in Go is supported
// but Glitter-authored code produces the same calls.
func Register(thing any) any {
	mustBeInInitPhase()
	return registerDispatch(thing)
}

// registerDispatch is Register's implementation without the
// init-scope check.  Extracted so tests can exercise the dispatch
// logic directly — Register itself always errors from a test
// goroutine because tests never run under runtime.doInit.
func registerDispatch(thing any) any {
	if thing == nil {
		panic("genesis.Register: nil argument")
	}
	rv := reflect.ValueOf(thing)
	if rv.Kind() != reflect.Func {
		return registerValue(thing)
	}
	rft := rv.Type()
	switch {
	case rft.NumIn() == 0 && rft.NumOut() == 1:
		out := rv.Call(nil)
		return registerValue(out[0].Interface())
	case rft.NumIn() == 1 && rft.NumOut() == 1 && rft.In(0) == waitGroupType:
		wg := phaseWaitGroup()
		if wg == nil {
			panic("genesis.Register: no active phase; caller does not hold an open genesis phase")
		}
		out := rv.Call([]reflect.Value{reflect.ValueOf(wg)})
		return registerValue(out[0].Interface())
	default:
		panic(fmt.Errorf("genesis.Register: unsupported function shape %s — must be func() T or func(*sync.WaitGroup) T", rft))
	}
}

// registerValue is the shared tail of Register (and SparkAs's
// child-side init) that stores an any as a Trait and panics on
// error.  Any registration error is a program bug at genesis time.
func registerValue(v any) any {
	if err := registerTraitAny(v); err != nil {
		panic(fmt.Errorf("genesis.Register: %w", err))
	}
	return v
}

// mustBeInInitPhase walks the current goroutine's call stack looking
// for runtime.doInit or runtime.doInit1.  If neither is an ancestor
// frame the call is not inside a package init sequence and Register
// panics.  This is JanOS's guardrail against Register drifting into
// runtime contexts where the phase machinery is either closed or
// meaningless.
func mustBeInInitPhase() {
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	if n == 0 {
		panic("genesis.Register: unable to inspect call stack")
	}
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if f.Function == "runtime.doInit1" || f.Function == "runtime.doInit" {
			return
		}
		if !more {
			break
		}
	}
	panic("genesis.Register: must be called during package init — use `var _ = genesis.Register(...)` at package scope")
}

// Defer registers f to run at process shutdown — when main.main
// returns or os.Exit is called.  (Panics and runtime throws never
// reach orderly shutdown; deferral cannot help a crashing process.)
//
// Cleanups run LIFO — the most recently registered runs first,
// mirroring Go's defer statement — and each receives the shutdown
// WaitGroup.  Synchronous cleanup happens inline; cleanup that can
// proceed in the background does wg.Add(1), spawns its goroutine,
// and calls wg.Done when finished:
//
//	gpuBuf := allocateGPU()
//	genesis.Defer(func(wg *sync.WaitGroup) {
//	    wg.Add(1)
//	    go func() {
//	        defer wg.Done()
//	        gpuBuf.Release()
//	    }()
//	})
//
// The process does not exit until every registered cleanup has been
// invoked and the WaitGroup has fully drained.  A cleanup registered
// DURING shutdown (by another cleanup) is honored — the drain loops
// until the registry is empty.
//
// This is the same WaitGroup idiom the genesis phase uses for async
// initialization: creation and destruction are symmetric, at both
// scales.  Deferral is registered next to the creation code it
// unwinds — there is deliberately no init-time registration form,
// because cleanup only exists once something real has been created.
//
// A cleanup that panics is caught, reported to stderr, and does not
// prevent the remaining cleanups from running.
func Defer(f func(*sync.WaitGroup)) {
	if f == nil {
		panic("genesis.Defer: nil function")
	}
	shutdown.mu.Lock()
	shutdown.funcs = append(shutdown.funcs, f)
	shutdown.mu.Unlock()
}

// DeferSelf registers f to run when the current spark exits — when
// the work function passed to SparkAs returns (or panics).  Cleanups
// run LIFO on the spark's own goroutine and receive the spark's exit
// WaitGroup, with the same synchronous-or-async contract as Defer.
//
// DeferSelf may be called from anywhere in the spark's life: inside
// SparkAs's primaryInit or additionalInits (cleanup registered next
// to creation), inside the work function, or from any `go` child
// sharing the spark's identity.  Registration after the spark's work
// function has returned is not honored — the drain has already run.
//
// Called from the main goroutine's identity (or any of its `go`
// descendants), DeferSelf is equivalent to Defer: main's self-lifetime
// IS the process lifetime, so its cleanup belongs to process shutdown.
func DeferSelf(f func(*sync.WaitGroup)) {
	if f == nil {
		panic("genesis.DeferSelf: nil function")
	}
	addr := runtimeIdentityBlockAddr(runtime.Identify())
	if addr == 0 {
		fatalMissingIdentity("DeferSelf")
	}
	if addr == mainBlockAddr {
		Defer(f)
		return
	}
	st := stateForCurrent()
	if st == nil {
		fatalMissingIdentity("DeferSelf")
	}
	st.mu.Lock()
	st.deferred = append(st.deferred, f)
	st.mu.Unlock()
}

// drainShutdown is the process-shutdown drain, invoked by the
// runtime's exit-hook machinery.  Loops so that cleanups registered
// during the drain (teardown cascades) are honored.
func drainShutdown() {
	for {
		shutdown.mu.Lock()
		fns := shutdown.funcs
		shutdown.funcs = nil
		shutdown.mu.Unlock()
		if len(fns) == 0 {
			return
		}
		runDeferred(fns)
	}
}

// drainSelfDeferred drains a spark's exit deferrals.  Runs on the
// spark's goroutine when its work function returns or panics.  Loops
// for the same registered-during-drain reason as drainShutdown.
func drainSelfDeferred(st *selfState) {
	for {
		st.mu.Lock()
		fns := st.deferred
		st.deferred = nil
		st.mu.Unlock()
		if len(fns) == 0 {
			return
		}
		runDeferred(fns)
	}
}

// runDeferred invokes a batch of deferral cleanups LIFO, sharing one
// WaitGroup across the batch, then blocks until the group drains.
// Each cleanup is individually recovered: a panicking cleanup is
// reported to stderr and the remaining cleanups still run.  (The
// runtime's exit-hook runner turns an escaping panic into a hard
// throw with no context — catching per-cleanup keeps shutdown
// diagnosable and best-effort.)
func runDeferred(fns []func(*sync.WaitGroup)) {
	var wg sync.WaitGroup
	for i := len(fns) - 1; i >= 0; i-- {
		func(f func(*sync.WaitGroup)) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "genesis: deferred cleanup panicked: %v\n", r)
				}
			}()
			f(&wg)
		}(fns[i])
	}
	wg.Wait()
}

// SparkAs spawns a fresh-identity goroutine, runs a genesis phase on
// it, and then invokes work with the value produced by primaryInit.
//
// Genesis on the child:
//
//  1. The parent's Traits are inherited verbatim (parent must have
//     closed its phase; otherwise ErrPhaseOpen is returned).
//  2. primaryInit runs on the child; its result is registered as a
//     Trait and also carried forward to work.
//  3. Each function in additionalInits runs on the child; its result
//     is registered as a Trait (type-erased through the variadic).
//  4. The child's phase closes.
//  5. work runs on the child with primaryInit's return value.
//
// The primary trait is what distinguishes this Spark's role at
// compile time: work's argument type TC is inferred from primaryInit's
// return type, so the caller gets full typing on the value it acts
// on.  Additional inits contribute traits alongside the primary; all
// go into the same per-identity Self.
//
// A trait registered by an additionalInit whose type collides with
// an inherited trait panics on the child — child code cannot
// silently override an inherited classification.
func SparkAs[TC any](
	work func(TC),
	primaryInit func() TC,
	additionalInits ...func() any,
) error {
	// Inception is the very first thing a spark acquires — captured
	// before validation, before the child exists.  The spark's birth
	// is the moment its creation was asked for.
	inception := time.Now()
	if work == nil {
		return errors.New("genesis: SparkAs work function is nil")
	}
	if primaryInit == nil {
		return errors.New("genesis: SparkAs primaryInit is nil")
	}
	parentSelf, err := CurrentSelf()
	if err != nil {
		return fmt.Errorf("genesis: SparkAs called on parent whose phase is not closed: %w", err)
	}
	runtimeJanosSpark(func() {
		st := stateForCurrent()
		if st == nil {
			fatalMissingIdentity("SparkAs child")
		}
		// The child's first recorded fact is its birth time.
		st.mu.Lock()
		st.inception = inception
		st.mu.Unlock()
		// Spark-exit deferral: drain when work returns OR panics.
		// Installed before the inits so a cleanup registered inside
		// primaryInit/additionalInits still runs if a later init (or
		// work itself) panics — created resources unwind either way.
		defer drainSelfDeferred(st)
		// Inherit parent's traits under the mutex, then release for
		// child inits to be able to registerTraitAny via the internal
		// helper.
		st.mu.Lock()
		for _, tr := range parentSelf.Traits {
			typ := reflect.TypeOf(tr.Complex)
			st.typeIdx[typ] = len(st.traits)
			st.traits = append(st.traits, tr)
		}
		st.mu.Unlock()

		// Primary: the child's own top-of-its-Self trait — call on
		// the child so it can observe the child's identity if it
		// wants.  Registered like any other trait.
		primary := primaryInit()
		if err := registerTraitAny(primary); err != nil {
			panic(fmt.Errorf("genesis: SparkAs primaryInit failed: %w", err))
		}
		// Additional trait initializers.  Type-erased through the
		// variadic.
		for i, init := range additionalInits {
			if init == nil {
				panic(fmt.Errorf("genesis: SparkAs additionalInits[%d] is nil", i))
			}
			v := init()
			if err := registerTraitAny(v); err != nil {
				panic(fmt.Errorf("genesis: SparkAs additionalInits[%d] failed: %w", i, err))
			}
		}
		if err := closePhase(); err != nil {
			panic(fmt.Errorf("genesis: SparkAs closePhase failed: %w", err))
		}
		work(primary)
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
		fatalMissingIdentity("registerTraitAny")
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

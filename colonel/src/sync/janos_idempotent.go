// JanOS: per-identity idempotency primitive.
//
// Idempotent generalizes Once from "once per program" to "once per
// identity".  Each identity that touches an Idempotent gets its own
// once-slot: the function runs the first time that identity's
// goroutine (or any goroutine sharing that identity via `go`
// inheritance) calls Do; subsequent calls from the same identity are
// no-ops.  Different identities each get their own slot, so f runs
// once per identity that touches the Idempotent.
//
// Identity is drawn from the calling goroutine — runtime.Identify()
// under the hood.  Callers cannot pass foreign identities to fire
// their slots; each goroutine is idempotent-scoped to itself.  For
// program-wide once semantics, use sync.Once.  For collective
// coordination (a fixed set of peers cooperating on a shared
// once-fires), pass a plain sync.Once by handle to just those peers —
// scope is enforced by whom you share the handle with, not by an
// argument to Do.
//
// Cleanup: when an identity block dies (all goroutines referring to
// it have been GC'd), the corresponding once-slot is evicted.  This
// is driven by a runtime-side finalizer: sync registers a hook at
// package init that the runtime calls when a block goes unreachable.
// Idempotent instances hold weak.Pointer registry entries so a
// locally-scoped Idempotent gets GC'd normally when its user drops
// the reference.

package sync

import (
	"runtime"
	"weak"
	_ "unsafe" // for go:linkname
)

// runtimeRegisterBlockFinalizedHook lets sync be notified when any
// identity block becomes GC-unreachable.  Reached via linkname because
// runtime exposes it as an unexported package-level function.
//
//go:linkname runtimeRegisterBlockFinalizedHook runtime.janosRegisterBlockFinalizedHook
func runtimeRegisterBlockFinalizedHook(fn func(blockAddr uintptr))

// runtimeIdentityBlockAddr yields the block address behind an Identity
// as a uintptr.  Reached via linkname; unexported in runtime so user
// code cannot obtain it.  The uintptr is a lifecycle key, not a
// dereference-able pointer to anything containing private-key material.
//
//go:linkname runtimeIdentityBlockAddr runtime.janosIdentityBlockAddr
func runtimeIdentityBlockAddr(id runtime.Identity) uintptr

// runtimeThrow is runtime.throw reached via linkname.  Used when
// Idempotent.Do discovers the current goroutine has no identity
// block — a runtime security invariant violation — and the safest
// course is to abort with a fatal diagnostic rather than paper over
// the state with a nil-key slot.
//
//go:linkname runtimeThrow runtime.throw
func runtimeThrow(msg string)

// idempotentRegistry holds weak references to every Idempotent
// instance that has been used at least once.  Block-finalized hooks
// walk this list to evict entries; stale (nil-Value) weak refs are
// swept on the same walk.
var idempotentRegistry struct {
	mu   Mutex
	list []weak.Pointer[Idempotent]
}

func init() {
	runtimeRegisterBlockFinalizedHook(idempotentOnBlockFinalized)
}

// idempotentOnBlockFinalized is called by the runtime finalizer
// goroutine when any identity block becomes GC-unreachable.  Walks
// the Idempotent registry, evicting the once-slot that keyed on this
// block and dropping weak refs whose Idempotent has itself been GC'd.
func idempotentOnBlockFinalized(blockAddr uintptr) {
	idempotentRegistry.mu.Lock()
	kept := idempotentRegistry.list[:0]
	for _, wp := range idempotentRegistry.list {
		idem := wp.Value()
		if idem == nil {
			continue // Idempotent was GC'd; drop the stale weak ref
		}
		kept = append(kept, wp)
		idem.evictBlock(blockAddr)
	}
	idempotentRegistry.list = kept
	idempotentRegistry.mu.Unlock()
}

// Idempotent runs a function at most once per identity.
//
// The zero value is ready to use.  An Idempotent should not be copied
// after first use.
//
// Automatic cleanup: when all goroutines holding an identity die and
// the block is GC'd, the once-slot keyed on that block is evicted.
// A truly-local Idempotent that itself becomes unreachable is
// likewise GC'd — the registry holds only weak references.
type Idempotent struct {
	mu         Mutex
	entries    map[uintptr]*Once // identity block addr → once-slot
	registered bool              // has this Idempotent been added to the registry?
}

// Do runs f exactly once for the current goroutine's identity.
//
// If the current identity has never called Do on this Idempotent,
// f runs; if it has, f is a no-op.  Goroutines sharing an identity
// via `go` inheritance share a once-slot; genesis.SparkAs children
// get distinct identities and therefore distinct slots.
//
// Panics fatally (via runtime.throw) if the current goroutine has
// no JanOS identity — this represents a runtime security invariant
// violation and the process cannot safely continue.
func (i *Idempotent) Do(f func()) {
	addr := runtimeIdentityBlockAddr(runtime.Identify())
	if addr == 0 {
		runtimeThrow("sync.Idempotent.Do: current goroutine has no JanOS identity")
	}
	i.mu.Lock()
	if i.entries == nil {
		i.entries = make(map[uintptr]*Once)
	}
	if !i.registered {
		i.registered = true
		i.selfRegister()
	}
	entry, ok := i.entries[addr]
	if !ok {
		entry = &Once{}
		i.entries[addr] = entry
	}
	i.mu.Unlock()
	entry.Do(f)
}

// selfRegister adds a weak pointer to this Idempotent to the global
// registry.  Called at most once per Idempotent (first Do).  Held
// under i.mu by the caller; takes idempotentRegistry.mu.
func (i *Idempotent) selfRegister() {
	wp := weak.Make(i)
	idempotentRegistry.mu.Lock()
	idempotentRegistry.list = append(idempotentRegistry.list, wp)
	idempotentRegistry.mu.Unlock()
}

// evictBlock removes the once-slot keyed on the given block address.
// Invoked by idempotentOnBlockFinalized from the finalizer goroutine.
func (i *Idempotent) evictBlock(addr uintptr) {
	i.mu.Lock()
	delete(i.entries, addr)
	i.mu.Unlock()
}

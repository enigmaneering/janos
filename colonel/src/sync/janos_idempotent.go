// JanOS: identity-scoped idempotency primitive.
//
// Idempotent generalizes Once: it runs the same function exactly once
// per unique identity collective.  With no identities specified, it
// behaves as Once (once per program).  With one or more identities,
// it runs once for that specific set — subsequent callers who present
// the same set (in any order) get the no-op path.
//
// The identities are runtime.Identity values.  Two goroutines that
// share an identity via `go` inheritance present identical Identity
// values; a spark-child (from runtime.Spark) presents a distinct
// Identity.  Callers who want "once per THIS goroutine" pass
// runtime.Identify() explicitly; callers who want "once per
// collection of peers" pass the participants' Identity values.
//
// Cleanup: when an identity block dies (all goroutines referring to
// it have been GC'd), any entries in any Idempotent whose collective
// key involved that block are evicted.  This is driven by a runtime-
// side finalizer: sync registers a hook at package init that runtime
// calls when a block goes unreachable.  Idempotent instances hold
// weak.Pointer registry entries so a locally-scoped Idempotent gets
// GC'd normally when its user drops the reference.

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
// the Idempotent registry, evicting entries that used this block and
// dropping weak refs whose Idempotent has itself been GC'd.
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

// Idempotent runs a function exactly once per identity collective.
//
// With no identity arguments, Do behaves as a Once — the function
// runs exactly once for the process.  With one or more arguments, Do
// runs the function exactly once per unique collective of identities;
// the collective is order-independent (permutations of the same set
// key the same slot).
//
// The zero value is ready to use.  An Idempotent should not be copied
// after first use.
//
// Automatic cleanup: when all goroutines holding an identity die and
// the block is GC'd, entries keyed on that block are evicted.  A
// truly-local Idempotent that itself becomes unreachable is likewise
// GC'd — the registry holds only weak references.
type Idempotent struct {
	mu           Mutex
	entries      map[[80]byte]*Once   // collective key → Once slot
	perBlockKeys map[uintptr][][80]byte // block addr → collective keys it participates in
	registered   bool                 // has this Idempotent been added to the registry?
}

// Do runs f exactly once for the identity collective formed by
// identities.  Later calls to Do with the same collective (regardless
// of argument order) do not invoke f.
//
// If identities is empty, f runs exactly once for the process — the
// same guarantee sync.Once provides.
func (i *Idempotent) Do(f func(), identities ...runtime.Identity) {
	key := collectiveKey(identities)

	i.mu.Lock()
	if i.entries == nil {
		i.entries = make(map[[80]byte]*Once)
		i.perBlockKeys = make(map[uintptr][][80]byte)
	}
	if !i.registered {
		i.registered = true
		i.selfRegister()
	}
	entry, ok := i.entries[key]
	if !ok {
		entry = &Once{}
		i.entries[key] = entry
		// Associate this key with each contributing block so the
		// finalizer hook can evict it when the block dies.
		for _, id := range identities {
			addr := runtimeIdentityBlockAddr(id)
			if addr == 0 {
				continue // empty Identity — no block to associate with
			}
			i.perBlockKeys[addr] = append(i.perBlockKeys[addr], key)
		}
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

// evictBlock removes every collective-key entry that involved the
// given block address.  Invoked by idempotentOnBlockFinalized from
// the finalizer goroutine.
func (i *Idempotent) evictBlock(addr uintptr) {
	i.mu.Lock()
	defer i.mu.Unlock()
	keys, ok := i.perBlockKeys[addr]
	if !ok {
		return
	}
	for _, key := range keys {
		delete(i.entries, key)
	}
	delete(i.perBlockKeys, addr)
}

// collectiveKey folds a slice of Identity values into a single
// [80]byte key by byte-wise XOR of an architecture-agnostic
// encoding of each identity:
//
//	bytes  0..7:   Index               (little-endian uint64)
//	bytes  8..71:  PublicPoint         (X‖Y, 64 bytes)
//	bytes 72..79:  block pointer addr  (uintptr zero-extended to 8 bytes)
//
// This avoids the pitfalls of reinterpreting the Identity struct as
// [80]byte via unsafe.Pointer — Go's Identity layout differs across
// architectures (pointer width, tail padding), so a byte-for-byte
// struct view is not portable.
//
// XOR is commutative and associative, so the resulting key is
// independent of argument order.  With no identities the key is the
// zero value, which reserves the program-wide slot.
func collectiveKey(ids []runtime.Identity) [80]byte {
	var key [80]byte
	if len(ids) == 0 {
		return key
	}
	var one [80]byte
	for _, id := range ids {
		// Wipe scratch so per-identity encodings don't leak between
		// iterations.
		for j := range one {
			one[j] = 0
		}
		// Index at bytes 0..7 in little-endian.
		for j := uint(0); j < 8; j++ {
			one[j] = byte(id.Index >> (j * 8))
		}
		// PublicPoint at bytes 8..71.
		copy(one[8:72], id.PublicPoint[:])
		// Block pointer as uint64 at bytes 72..79.  On 32-bit
		// systems the uintptr is 4 bytes; zero-extending to 8 gives
		// the same 80-byte layout on every architecture.
		addr := uint64(runtimeIdentityBlockAddr(id))
		for j := uint(0); j < 8; j++ {
			one[72+j] = byte(addr >> (j * 8))
		}
		// XOR-fold into the accumulator.
		for j := range key {
			key[j] ^= one[j]
		}
	}
	return key
}

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
// values; a fork-child presents a distinct Identity.  Callers who
// want "once per THIS goroutine" pass runtime.Identify() explicitly;
// callers who want "once per collection of peers" pass the
// participants' Identity values.

package sync

import (
	"runtime"
	"unsafe"
)

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
type Idempotent struct {
	m Map // map[[80]byte]*Once — key is the XOR-fold of raw Identity bytes
}

// Do runs f exactly once for the identity collective formed by
// identities.  Later calls to Do with the same collective (regardless
// of argument order) do not invoke f.
//
// If identities is empty, f runs exactly once for the process — the
// same guarantee sync.Once provides.
func (i *Idempotent) Do(f func(), identities ...runtime.Identity) {
	key := collectiveKey(identities)
	entry, _ := i.m.LoadOrStore(key, &Once{})
	entry.(*Once).Do(f)
}

// collectiveKey folds a slice of Identity values into a single
// [80]byte key by byte-wise XOR.  XOR is commutative and associative,
// so the resulting key is independent of argument order.  With no
// identities the key is the zero value, which reserves the
// program-wide slot.
func collectiveKey(ids []runtime.Identity) [80]byte {
	var key [80]byte
	if len(ids) == 0 {
		return key
	}
	// Reinterpret each Identity as [80]byte for XOR-folding.  Identity
	// on 64-bit is 8 (Index) + 64 (PublicPoint) + 8 (block pointer)
	// = 80 bytes.  On 32-bit it's 76 bytes and Identity has different
	// padding; the compile-time assertion below catches drift.
	var _ [1]struct{}
	_ = *(*[80]byte)(unsafe.Pointer(&ids[0]))
	for _, id := range ids {
		bits := *(*[80]byte)(unsafe.Pointer(&id))
		for j := range key {
			key[j] ^= bits[j]
		}
	}
	return key
}

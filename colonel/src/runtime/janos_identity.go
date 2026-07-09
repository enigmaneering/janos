// JanOS: per-goroutine cryptographic identity.
//
// Every goroutine — main and all descendants — has an Identity from
// birth.  The identity holds:
//
//   - A random 64-bit derivation index (private; the derivation salt).
//   - A P-256 public point d·G (published in Identity.PublicPoint).
//   - A private scalar d that never leaves the runtime.
//
// `go`-spawned children pointer-copy the parent's identityBlock — same
// keys, same signatures, same Identity by ==.  runtime/genesis.SparkAs
// spawns a child with a fresh identityBlock (new Index, new derived
// keys) — this is the fundamental "certified ignition" primitive from
// which all identity-fresh execution contexts descend.  A Glitter
// program's `spark` entry point lowers to genesis.SparkAs for the
// standard-goroutine path; compute-shader entry points and sparklet subprocesses follow
// their own codepaths but are the same primitive at the identity
// layer — every spark begins with a fresh derived identity.
//
// The private-key material is guarded by three layers:
//
//   1. Identity.block is an unexported pointer to an unexported struct
//      type.  Well-formed Go code outside the runtime package cannot
//      dereference it, cannot spell its fields, cannot forge one.
//   2. Derive detects tampering with the visible fields of the caller's
//      Identity (Index and PublicPoint) by comparing against the
//      authoritative values stored on the block.
//   3. The block is reachable through the current goroutine's
//      provenance.identity, and Derive rejects any caller whose
//      current provenance.identity points at a different block —
//      independent of whether the caller can spell an Identity value
//      that references this block.
//
// v0 note: the root key backing derivation is presently a per-process
// random buffer generated at schedinit.  Under attestation this becomes
// a key unsealed from the host's hardware root of trust — whatever the
// platform uses to fill that role (a TPM 2.0 device on Linux/Windows,
// Apple's Secure Enclave on Darwin, an on-board secure element on
// bare-metal targets) — bound to the divined-boot measurements, and
// per-goroutine keys become wrapped by that root so they are useless
// without the specific machine that minted them.  JanOS treats "the
// root of trust" as a role, not a particular hardware specification:
// the Secure Enclave and a TPM are interchangeable to the identity
// system, and the attest package models exactly this (a role-neutral
// API over a Mechanism that names the concrete variant).

package runtime

import (
	"internal/runtime/atomic"
	"internal/runtime/janos_hash"
	"unsafe"
)

// janosRootKey backs all per-goroutine identity derivation for this
// process.  Populated once at schedinit with 32 random bytes; never
// rotated.
var janosRootKey [32]byte

// identityBlock is per-goroutine identity storage.  Pointer to it
// lives in gProvenance.identity.  `go`-descendants share a pointer to
// the parent's block; `fork`-descendants get a fresh block.
type identityBlock struct {
	// parentInstanceID records who forked this goroutine, or is zero
	// on descendants of the main goroutine that were never forked.
	parentInstanceID [16]byte

	// index is the public integer identifier.  Randomly generated at
	// mint time.
	index uint64

	// privateKey is the P-256 scalar d.  Never surfaced to user code.
	// All access is mediated by the derive function and the
	// goroutine-owner check inside it.
	privateKey [32]byte

	// publicPoint is d·G, computed once at mint time and cached so
	// Derive() with no argument is a memcpy rather than a
	// scalar-mult.
	publicPoint [64]byte
}

// Identity is what runtime.Identify() returns.  Value type, fully
// comparable — safe as a map key and safe to compare with ==.  Two
// goroutines that inherit the same identityBlock via `go` return
// equal Identity values.
type Identity struct {
	// index is the per-identity derivation salt.  Deliberately
	// unexported: it is the secret input to priv = HMAC(root, index),
	// so keeping it off the public surface means an attacker who
	// obtains the derivation root still cannot reconstruct a scalar
	// without also brute-forcing this 64-bit value against the public
	// point.  Two identities are distinguished publicly by PublicPoint
	// and compared for equality with ==; nothing outside the runtime
	// needs the raw index.
	index uint64
	// PublicPoint is d·G in 64-byte uncompressed X‖Y encoding.  Safe
	// to share with peers; ECDH partners need this to compute the
	// shared secret.  This is the public handle for "which identity".
	PublicPoint [64]byte
	// block points at the identityBlock backing this Identity.
	// Unexported, and points at an unexported struct type — well-
	// formed Go code outside runtime cannot spell it, dereference it,
	// or forge one.
	block *identityBlock
}

// Derive performs elliptic-curve scalar multiplication on this
// identity's private key.
//
// With no argument, returns d·G (the identity's PublicPoint, 64 bytes).
// With a peer's public point in uncompressed X‖Y form (64 bytes) as
// the argument, performs the ECDH computation d·peer and returns 32
// bytes of key material derived from the shared point via HKDF-
// Expand-SHA256 with the info string "JanOS-Ambrosia" and a salt
// formed by concatenating the two public points in lexicographic
// order.
//
// Returns an error if:
//
//   - The identity is empty (no block pointer — zero-valued struct).
//   - The Index or PublicPoint fields of the caller's Identity have
//     been tampered with since mint time.
//   - The caller is not on the goroutine that minted this identity.
//   - The peer bytes, when non-empty, are not a valid P-256 point.
func (id Identity) Derive(other ...byte) ([]byte, error) {
	ib := id.block
	if ib == nil {
		return nil, janosIdentityErrEmpty
	}
	if id.index != ib.index || id.PublicPoint != ib.publicPoint {
		return nil, janosIdentityErrTampered
	}
	if getg().provenance.identity != ib {
		return nil, janosIdentityErrCrossGoroutine
	}
	if len(other) == 0 {
		out := make([]byte, 64)
		copy(out, ib.publicPoint[:])
		return out, nil
	}
	return janosIdentityECDH(&ib.privateKey, &ib.publicPoint, other)
}

// janosMintIdentity allocates and populates a fresh identityBlock.
// Called from schedinit for the main goroutine and from Spark for
// spark-descendants.  Ownership is not tracked at mint time — Derive
// authorizes the caller by comparing their current
// provenance.identity to the block, so any goroutine that inherits
// the block via the normal newproc1 copy is a valid caller.
//
// Attaches a finalizer so packages that keyed cleanup state on this
// block (e.g. sync.Idempotent) can be notified when the block
// becomes GC-unreachable.
func janosMintIdentity(parentInstanceID [16]byte) *identityBlock {
	var idx uint64
	{
		hi := rand()
		lo := rand()
		idx = uint64(hi)<<32 | uint64(lo)
	}
	priv, pub := janosDeriveIdentityKey(idx)
	b := &identityBlock{
		parentInstanceID: parentInstanceID,
		index:            idx,
		privateKey:       priv,
		publicPoint:      pub,
	}
	// SetFinalizer is unsafe to call during runtime.schedinit (before
	// the finalizer subsystem is up).  Attach the finalizer only if
	// the runtime has completed the pre-main init sequence.
	if janosFinalizersReady.Load() {
		SetFinalizer(b, janosBlockFinalized)
	} else {
		// The main goroutine's block is created at schedinit; queue it
		// for later finalizer attachment.  A single block deferred is
		// enough: schedinit only mints one before finalizers are up.
		janosDeferredFinalizerBlock = b
	}
	return b
}

// janosFinalizersReady flips true from runtime.main once the finalizer
// goroutine and package inits are safe to reach.  See
// janosLateFinalizerInit below.
var janosFinalizersReady janosAtomicBool

// janosDeferredFinalizerBlock holds the single identityBlock minted
// before finalizers are ready (the main goroutine's).  Attached later
// by janosLateFinalizerInit.
var janosDeferredFinalizerBlock *identityBlock

// janosAtomicBool is a tiny local atomic bool to avoid pulling in
// sync/atomic (which would break the runtime's import graph).
type janosAtomicBool struct{ v uint32 }

//go:nosplit
func (b *janosAtomicBool) Load() bool { return atomic.Load(&b.v) != 0 }

//go:nosplit
func (b *janosAtomicBool) Store(v bool) {
	if v {
		atomic.Store(&b.v, 1)
	} else {
		atomic.Store(&b.v, 0)
	}
}

// janosLateFinalizerInit is called from runtime.main just before user
// main runs.  Attaches the deferred finalizer to the main goroutine's
// identityBlock and flips janosFinalizersReady so subsequent Spark
// calls attach synchronously.
func janosLateFinalizerInit() {
	if janosDeferredFinalizerBlock != nil {
		SetFinalizer(janosDeferredFinalizerBlock, janosBlockFinalized)
		janosDeferredFinalizerBlock = nil
	}
	janosFinalizersReady.Store(true)
}

// janosFreshInstanceID draws 16 random bytes to form a new
// InstanceID.  Used by Spark so the child is distinguishable at the
// InstanceID level in addition to having a distinct identityBlock.
//
//go:nosplit
func janosFreshInstanceID() [16]byte {
	var iid [16]byte
	hi := rand()
	lo := rand()
	for i := 0; i < 8; i++ {
		iid[i] = byte(hi >> (i * 8))
		iid[i+8] = byte(lo >> (i * 8))
	}
	return iid
}

// janosDeriveIdentityKey deterministically derives a P-256 private
// scalar and its corresponding public point from janosRootKey and the
// per-identity index.
//
//	priv = HMAC-SHA256(janosRootKey, index_bytes) mod n_P256
//	pub  = priv · G
//
// If the initial HMAC output happens to be >= n (probability ~2^-32
// for P-256), reseed once by hashing the seed with the index.
func janosDeriveIdentityKey(idx uint64) (priv [32]byte, pub [64]byte) {
	var idxBytes [8]byte
	for i := uint(0); i < 8; i++ {
		idxBytes[i] = byte(idx >> (i * 8))
	}
	seed := janosHMACSHA256(janosRootKey[:], idxBytes[:])

	var s janosP256Scalar
	if _, ok := s.SetBytesBE(seed[:]); !ok {
		reseed := janosHMACSHA256(seed[:], idxBytes[:])
		if _, ok2 := s.SetBytesBE(reseed[:]); !ok2 {
			throw("runtime: identity key derivation failed twice")
		}
		priv = reseed
	} else {
		priv = seed
	}

	var p janosP256Point
	if _, ok := p.ScalarBaseMult(priv[:]); !ok {
		throw("runtime: identity ScalarBaseMult failed")
	}
	x, y, ok := janosP256AffineXY(&p)
	if !ok {
		throw("runtime: identity public point at infinity")
	}
	copy(pub[0:32], x[:])
	copy(pub[32:64], y[:])
	return priv, pub
}

// janosP256AffineXY extracts the affine coordinates from a projective
// point.
func janosP256AffineXY(p *janosP256Point) (x, y [32]byte, ok bool) {
	if p.IsInfinity() {
		return x, y, false
	}
	var zinv, xa, ya janosP256Element
	zinv.Invert(&p.z)
	xa.Mul(&p.x, &zinv)
	ya.Mul(&p.y, &zinv)
	return xa.Bytes(), ya.Bytes(), true
}

// janosIdentityECDH performs the ECDH shared-secret computation and
// KDF for Derive.
func janosIdentityECDH(priv *[32]byte, ourPub *[64]byte, peerBytes []byte) ([]byte, error) {
	if len(peerBytes) != 64 {
		return nil, janosIdentityErrPeerLen
	}
	var peer janosP256Point
	if _, ok := peer.SetUncompressedBytes(peerBytes); !ok {
		return nil, janosIdentityErrPeerInvalid
	}
	var shared janosP256Point
	if _, ok := shared.ScalarMult(&peer, priv[:]); !ok {
		return nil, janosIdentityErrPeerInvalid
	}
	sx, sy, ok := janosP256AffineXY(&shared)
	if !ok {
		return nil, janosIdentityErrPeerInvalid
	}
	var sharedBytes [64]byte
	copy(sharedBytes[0:32], sx[:])
	copy(sharedBytes[32:64], sy[:])

	salt := janosIdentityKDFSalt(ourPub[:], peerBytes)
	prk := janosHMACSHA256(salt, sharedBytes[:])
	okm := janosHKDFExpand32(prk[:], []byte("JanOS-Ambrosia"))
	out := make([]byte, 32)
	copy(out, okm[:])
	return out, nil
}

// janosIdentityKDFSalt sorts the two 64-byte public points byte-wise
// and concatenates them.  Both ECDH parties compute the same salt.
func janosIdentityKDFSalt(a, b []byte) []byte {
	first, second := a, b
	for i := 0; i < 64; i++ {
		if a[i] < b[i] {
			break
		}
		if a[i] > b[i] {
			first, second = b, a
			break
		}
	}
	out := make([]byte, 128)
	copy(out[0:64], first)
	copy(out[64:128], second)
	return out
}

// janosHMACSHA256 computes HMAC-SHA256(key, msg).
func janosHMACSHA256(key, msg []byte) [32]byte {
	const blockSize = janos_hash.SHA256Chunk
	var k [blockSize]byte
	if len(key) > blockSize {
		var h janos_hash.SHA256
		h.Reset()
		h.Write(key)
		s := h.Sum()
		copy(k[:], s[:])
	} else {
		copy(k[:], key)
	}

	var ipad, opad [blockSize]byte
	for i := 0; i < blockSize; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}

	var inner janos_hash.SHA256
	inner.Reset()
	inner.Write(ipad[:])
	inner.Write(msg)
	innerSum := inner.Sum()

	var outer janos_hash.SHA256
	outer.Reset()
	outer.Write(opad[:])
	outer.Write(innerSum[:])
	return outer.Sum()
}

// janosHKDFExpand32 is HKDF-Expand-SHA256 specialized to a 32-byte
// output (single T(1) block).
func janosHKDFExpand32(prk, info []byte) [32]byte {
	buf := make([]byte, 0, len(info)+1)
	buf = append(buf, info...)
	buf = append(buf, 0x01)
	return janosHMACSHA256(prk, buf)
}

// janosInitIdentity is called from schedinit after janosInitInstanceID
// runs so the InstanceID is available for future parent-InstanceID
// recording.
//
// Main's inception timestamp is NOT captured here: schedinit runs
// before package time is initialized and before a portable wall-clock
// reading is available (several platforms implement time.now directly
// in assembly with no Go-callable walltime).  runtime/genesis captures
// it instead, at the earliest point a wall-clock time.Time can be
// formed — its own package init, still before user main.
//
//go:nosplit
func janosInitIdentity() {
	for i := 0; i < 4; i++ {
		r := rand()
		for j := 0; j < 8; j++ {
			janosRootKey[i*8+j] = byte(r >> (j * 8))
		}
	}
	var noParent [16]byte
	getg().provenance.identity = janosMintIdentity(noParent)
}

// Identify returns the current goroutine's Identity.
//
// Every goroutine has a valid Identity from spawn time — main gets one
// at schedinit; every child inherits or mints on spawn.
//
//go:nosplit
func Identify() Identity {
	ib := getg().provenance.identity
	if ib == nil {
		return Identity{}
	}
	return Identity{
		index:       ib.index,
		PublicPoint: ib.publicPoint,
		block:       ib,
	}
}

// janosSpark spawns f as a new goroutine with a fresh identity — the
// fundamental "certified ignition" primitive from which all identity-
// fresh execution contexts descend.  The parent's InstanceID is
// recorded on the child's identityBlock; a fresh InstanceID is also
// assigned to the child so the spark is distinguishable at that
// level too.
//
// The identityBlock and the fresh InstanceID are minted in the PARENT
// goroutine before the go spawn.  The child's very first instructions
// install the pre-minted identity into its provenance; no user code
// runs on the child with the inherited-then-replaced identity in
// scope.
//
// Distinct from `go`: `go`-spawned goroutines share the parent's
// identityBlock (equal Identity by ==); spark-spawned goroutines mint
// their own.  A Glitter program's `spark` entry point lowers to
// runtime/genesis.SparkAs, which reaches this primitive via linkname.
// User code has no direct access; the identity-mint step at the head
// of every spark is universal but exposed only through the SparkAs
// public API so a spawn cannot happen without genesis's phase
// machinery being engaged.
//
// Do not change signature: used via linkname from runtime/genesis.
//
//go:linkname janosSpark
func janosSpark(f func()) {
	parentInstanceID := getg().provenance.instanceID
	newBlock := janosMintIdentity(parentInstanceID)
	freshIID := janosFreshInstanceID()
	go func() {
		gp := getg()
		gp.provenance.identity = newBlock
		gp.provenance.instanceID = freshIID
		f()
	}()
}

// janosBlockFinalizedHooks is the list of callbacks registered by
// packages that key cleanup state on identityBlock addresses.  The
// hook is invoked from the finalizer goroutine when a block becomes
// GC-unreachable; each hook receives the block's address as a
// uintptr, which cannot be dereferenced to reach the private key.
var janosBlockFinalizedHooks struct {
	mu  mutex
	fns []func(uintptr)
}

// janosBlockFinalized is the finalizer attached to every
// identityBlock at mint time.  Runs on the finalizer goroutine when
// the block becomes GC-unreachable — i.e. when no live goroutine
// still has this block in its gProvenance.identity.
func janosBlockFinalized(b *identityBlock) {
	addr := uintptr(unsafe.Pointer(b))
	lock(&janosBlockFinalizedHooks.mu)
	// Snapshot under the lock; invoke outside to avoid lock inversion
	// with any hook that takes its own locks.
	fns := make([]func(uintptr), len(janosBlockFinalizedHooks.fns))
	copy(fns, janosBlockFinalizedHooks.fns)
	unlock(&janosBlockFinalizedHooks.mu)
	for _, fn := range fns {
		fn(addr)
	}
}

// janosRegisterBlockFinalizedHook is reached from sync (and any
// future package that wants block-lifecycle notifications) via
// //go:linkname.  Deliberately unexported: user code has no way to
// register hooks that would learn block addresses.
//
// Do not change signature: used via linkname from sync.
//
//go:nosplit
//go:linkname janosRegisterBlockFinalizedHook
func janosRegisterBlockFinalizedHook(fn func(uintptr)) {
	lock(&janosBlockFinalizedHooks.mu)
	janosBlockFinalizedHooks.fns = append(janosBlockFinalizedHooks.fns, fn)
	unlock(&janosBlockFinalizedHooks.mu)
}

// janosIdentityBlockAddr returns the identityBlock address for id as
// a uintptr.  Reached from sync via //go:linkname.  Deliberately
// unexported: user code has no way to extract the address from an
// Identity value.  The uintptr is a lifecycle key, not a pointer —
// it cannot be dereferenced without knowing the identityBlock struct
// layout (which is unexported).
//
// Do not change signature: used via linkname from sync.
//
//go:nosplit
//go:linkname janosIdentityBlockAddr
func janosIdentityBlockAddr(id Identity) uintptr {
	return uintptr(unsafe.Pointer(id.block))
}

// Sentinel errors returned by Identity.Derive.
var (
	janosIdentityErrEmpty          = &janosIdentityError{"identity: empty"}
	janosIdentityErrTampered       = &janosIdentityError{"identity: struct tampering detected"}
	janosIdentityErrCrossGoroutine = &janosIdentityError{"identity: derive called from foreign goroutine"}
	janosIdentityErrPeerLen        = &janosIdentityError{"identity: peer public point must be 64 bytes"}
	janosIdentityErrPeerInvalid    = &janosIdentityError{"identity: peer public point is not a valid P-256 point"}
)

type janosIdentityError struct{ msg string }

func (e *janosIdentityError) Error() string { return e.msg }

package runtime_test

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"testing"
)

// -----------------------------------------------------------------
// Identify + inheritance
// -----------------------------------------------------------------

func TestIdentifyMainReturnsValid(t *testing.T) {
	id := runtime.Identify()
	if id.Index == 0 {
		t.Fatal("main goroutine's Identity.Index is zero")
	}
	var zero [64]byte
	if id.PublicPoint == zero {
		t.Fatal("main goroutine's Identity.PublicPoint is zero")
	}
}

func TestIdentifyGoInheritance(t *testing.T) {
	me := runtime.Identify()
	ch := make(chan runtime.Identity, 1)
	go func() { ch <- runtime.Identify() }()
	child := <-ch
	if child != me {
		t.Fatalf("go-child Identity != main:\n  child: Index=%d\n  main:  Index=%d",
			child.Index, me.Index)
	}
}

func TestIdentifyStableAcrossCalls(t *testing.T) {
	a := runtime.Identify()
	b := runtime.Identify()
	if a != b {
		t.Fatalf("two Identify() calls on same goroutine differ:\n  a: %d\n  b: %d",
			a.Index, b.Index)
	}
}

// -----------------------------------------------------------------
// Spark: fresh identity per spawn
// -----------------------------------------------------------------

func TestSparkMintsDistinctIdentity(t *testing.T) {
	me := runtime.Identify()
	ch := make(chan runtime.Identity, 1)
	runtime.Spark(func() { ch <- runtime.Identify() })
	sparked := <-ch
	if sparked == me {
		t.Fatal("Sparked Identity equals main's — mint did not fire")
	}
	if sparked.Index == me.Index {
		t.Fatalf("Sparked Index collides with main's: %d", sparked.Index)
	}
	if sparked.PublicPoint == me.PublicPoint {
		t.Fatal("Sparked PublicPoint matches main's — derivation broken")
	}
}

func TestSparkNIndependentSparks(t *testing.T) {
	const n = 32
	ch := make(chan runtime.Identity, n)
	for i := 0; i < n; i++ {
		runtime.Spark(func() { ch <- runtime.Identify() })
	}
	seen := make(map[uint64]bool)
	for i := 0; i < n; i++ {
		id := <-ch
		if seen[id.Index] {
			t.Fatalf("two Sparked goroutines got the same Index: %d", id.Index)
		}
		seen[id.Index] = true
	}
}

func TestSparkGoDescendantsInheritSparkedIdentity(t *testing.T) {
	sparkedCh := make(chan runtime.Identity, 1)
	childCh := make(chan runtime.Identity, 1)
	runtime.Spark(func() {
		sparkedCh <- runtime.Identify()
		go func() { childCh <- runtime.Identify() }()
	})
	sparked := <-sparkedCh
	child := <-childCh
	if child != sparked {
		t.Fatal("go-child of a Sparked goroutine did not inherit its identity")
	}
}

// -----------------------------------------------------------------
// Derive: public point
// -----------------------------------------------------------------

func TestDeriveNoArgsReturnsPublicPoint(t *testing.T) {
	me := runtime.Identify()
	out, err := me.Derive()
	if err != nil {
		t.Fatalf("Derive() failed: %v", err)
	}
	if !bytes.Equal(out, me.PublicPoint[:]) {
		t.Fatal("Derive() with no args did not return PublicPoint bytes")
	}
}

func TestDerivePublicPointStableAcrossCalls(t *testing.T) {
	me := runtime.Identify()
	a, _ := me.Derive()
	b, _ := me.Derive()
	if !bytes.Equal(a, b) {
		t.Fatal("two Derive() calls returned different public points")
	}
}

func TestDerivePublicPointMatchesRederivation(t *testing.T) {
	me := runtime.Identify()
	_, pub := runtime.JanosDeriveIdentityKeyForTest(me.Index)
	if pub != me.PublicPoint {
		t.Fatal("stored PublicPoint disagrees with fresh derivation from Index")
	}
}

// -----------------------------------------------------------------
// Derive: ECDH between two Sparks
// -----------------------------------------------------------------

func TestDeriveECDHTwoSparksAgree(t *testing.T) {
	aPubCh := make(chan []byte, 1)
	bPubCh := make(chan []byte, 1)
	aSharedCh := make(chan []byte, 1)
	bSharedCh := make(chan []byte, 1)

	runtime.Spark(func() {
		me := runtime.Identify()
		aPubCh <- append([]byte(nil), me.PublicPoint[:]...)
		peer := <-bPubCh
		shared, err := me.Derive(peer...)
		if err != nil {
			t.Errorf("A ECDH failed: %v", err)
			aSharedCh <- nil
			return
		}
		aSharedCh <- shared
	})
	runtime.Spark(func() {
		me := runtime.Identify()
		bPubCh <- append([]byte(nil), me.PublicPoint[:]...)
		peer := <-aPubCh
		shared, err := me.Derive(peer...)
		if err != nil {
			t.Errorf("B ECDH failed: %v", err)
			bSharedCh <- nil
			return
		}
		bSharedCh <- shared
	})

	a := <-aSharedCh
	b := <-bSharedCh
	if a == nil || b == nil {
		t.FailNow()
	}
	if len(a) != 32 {
		t.Fatalf("shared secret length = %d, want 32", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("ECDH secrets disagree:\n  A: %s\n  B: %s",
			hex.EncodeToString(a), hex.EncodeToString(b))
	}
}

// -----------------------------------------------------------------
// Derive: rejection paths
// -----------------------------------------------------------------

func TestDeriveEmptyIdentityRejected(t *testing.T) {
	var empty runtime.Identity
	_, err := empty.Derive()
	if err == nil {
		t.Fatal("Derive on zero-valued Identity did not error")
	}
}

func TestDeriveCrossGoroutineRejected(t *testing.T) {
	ch := make(chan runtime.Identity, 1)
	runtime.Spark(func() { ch <- runtime.Identify() })
	sparked := <-ch
	_, err := sparked.Derive()
	if err == nil {
		t.Fatal("Derive on a foreign goroutine's Identity did not error")
	}
}

func TestDeriveTamperedIndexRejected(t *testing.T) {
	me := runtime.Identify()
	tampered := runtime.TamperIdentityIndexForTest(me, me.Index^0xDEADBEEF)
	if !runtime.IdentityBlockPointerEqualForTest(me, tampered) {
		t.Fatal("test helper broke block pointer identity")
	}
	_, err := tampered.Derive()
	if err == nil {
		t.Fatal("Derive on tampered-Index Identity did not error")
	}
}

func TestDeriveTamperedPublicPointRejected(t *testing.T) {
	me := runtime.Identify()
	tampered := runtime.TamperIdentityPublicPointForTest(me)
	_, err := tampered.Derive()
	if err == nil {
		t.Fatal("Derive on tampered-PublicPoint Identity did not error")
	}
}

func TestDeriveInvalidPeerLengthRejected(t *testing.T) {
	me := runtime.Identify()
	shortPeer := make([]byte, 32) // wrong length
	_, err := me.Derive(shortPeer...)
	if err == nil {
		t.Fatal("Derive with 32-byte peer did not error (expected 64-byte requirement)")
	}
}

func TestDeriveInvalidPeerPointRejected(t *testing.T) {
	me := runtime.Identify()
	// 64 zero bytes: the additive identity's X‖Y encoding does not
	// satisfy the P-256 curve equation, so the parser rejects it.
	invalidPeer := make([]byte, 64)
	_, err := me.Derive(invalidPeer...)
	if err == nil {
		t.Fatal("Derive with all-zero peer did not error")
	}
}

// -----------------------------------------------------------------
// KDF salt: order-independence + shape
// -----------------------------------------------------------------

func TestKDFSaltOrderIndependent(t *testing.T) {
	a := make([]byte, 64)
	b := make([]byte, 64)
	for i := 0; i < 64; i++ {
		a[i] = byte(i)
		b[i] = byte(255 - i)
	}
	salt1 := runtime.JanosIdentityKDFSaltForTest(a, b)
	salt2 := runtime.JanosIdentityKDFSaltForTest(b, a)
	if !bytes.Equal(salt1, salt2) {
		t.Fatal("KDF salt is not order-independent (sort broken)")
	}
	if len(salt1) != 128 {
		t.Fatalf("KDF salt length = %d, want 128", len(salt1))
	}
}

func TestKDFSaltDistinguishesInputs(t *testing.T) {
	a := make([]byte, 64)
	b := make([]byte, 64)
	c := make([]byte, 64)
	for i := 0; i < 64; i++ {
		a[i] = byte(i)
		b[i] = byte(i + 1)
		c[i] = byte(i + 2)
	}
	saltAB := runtime.JanosIdentityKDFSaltForTest(a, b)
	saltAC := runtime.JanosIdentityKDFSaltForTest(a, c)
	if bytes.Equal(saltAB, saltAC) {
		t.Fatal("KDF salt for {a,b} collides with {a,c}")
	}
}

// -----------------------------------------------------------------
// HMAC-SHA256: RFC 4231 test vector 1
// -----------------------------------------------------------------

func TestHMACSHA256RFC4231Vector1(t *testing.T) {
	// From RFC 4231 §4.2 test case 1:
	//   Key  = 0x0b × 20
	//   Data = "Hi There"
	//   HMAC-SHA-256 = b0344c61 d8db3853 5ca8afce af0bf12b
	//                  881dc200 c9833da7 26e9376c 2e32cff7
	key := make([]byte, 20)
	for i := range key {
		key[i] = 0x0b
	}
	msg := []byte("Hi There")
	want, _ := hex.DecodeString(
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	got := runtime.JanosHMACSHA256ForTest(key, msg)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("HMAC-SHA256 mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want))
	}
}

func TestHMACSHA256RFC4231Vector2(t *testing.T) {
	// From RFC 4231 §4.3 test case 2:
	//   Key  = "Jefe"
	//   Data = "what do ya want for nothing?"
	//   HMAC-SHA-256 = 5bdcc146 bf60754e 6a042426 089575c7
	//                  5a003f08 9d273983 9dec58b9 64ec3843
	key := []byte("Jefe")
	msg := []byte("what do ya want for nothing?")
	want, _ := hex.DecodeString(
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	got := runtime.JanosHMACSHA256ForTest(key, msg)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("HMAC-SHA256 (RFC vec2) mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want))
	}
}

func TestHMACSHA256LongKeyPath(t *testing.T) {
	// From RFC 4231 §4.7 test case 6:
	//   Key  = 0xaa × 131  (longer than 64-byte block size — hash-shortened)
	//   Data = "Test Using Larger Than Block-Size Key - Hash Key First"
	//   HMAC-SHA-256 = 60e43159 1ee0b67f 0d8a26aa cbf5b77f
	//                  8e0bc621 3728c514 0546040f 0ee37f54
	key := make([]byte, 131)
	for i := range key {
		key[i] = 0xaa
	}
	msg := []byte("Test Using Larger Than Block-Size Key - Hash Key First")
	want, _ := hex.DecodeString(
		"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
	got := runtime.JanosHMACSHA256ForTest(key, msg)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("HMAC-SHA256 (long-key path) mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want))
	}
}

// -----------------------------------------------------------------
// HKDF-Expand-SHA256: RFC 5869 test vector 1 (truncated to 32 bytes)
// -----------------------------------------------------------------

func TestHKDFExpand32RFC5869Vector1(t *testing.T) {
	// From RFC 5869 §A.1:
	//   PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
	//   info = f0f1f2f3f4f5f6f7f8f9
	//   L    = 42
	//   OKM  = 3cb25f25faacd57a90434f64d0362f2a
	//          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
	//          34007208d5b887185865
	//
	// We compute only the first 32 bytes (L=32) via HKDFExpand32.
	prk, _ := hex.DecodeString(
		"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString(
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
	got := runtime.JanosHKDFExpand32ForTest(prk, info)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("HKDF-Expand-SHA256 mismatch\n  got:  %s\n  want: %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want))
	}
}

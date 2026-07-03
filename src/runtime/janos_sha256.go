// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// JanOS: minimal SHA-256 implementation for use inside the runtime.
//
// The Go standard library provides SHA-256 in crypto/sha256, but that
// package sits far above the runtime in the import graph and pulls in
// crypto, hash, and internal/fips140 machinery we cannot reach from
// here.  This is a self-contained pure-Go implementation used by the
// self-attestation code path (janos_selfhash.go).  Algorithm and
// constants are per FIPS 180-4.
//
// The rotate operations are written out inline as (x<<k)|(x>>(32-k))
// to avoid depending on math/bits from within package runtime.

package runtime

// janosSHA256Chunk is the SHA-256 block size in bytes.
const janosSHA256Chunk = 64

// SHA-256 round constants (FIPS 180-4, §4.2.2).
var janosSHA256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// janosSHA256 is a streaming SHA-256 digest.  It has no allocations
// and fits on the stack; callers create one as a plain value.
type janosSHA256 struct {
	h   [8]uint32
	x   [janosSHA256Chunk]byte
	nx  int
	len uint64
}

// Reset returns the digest to its initial state.
func (d *janosSHA256) Reset() {
	d.h[0] = 0x6A09E667
	d.h[1] = 0xBB67AE85
	d.h[2] = 0x3C6EF372
	d.h[3] = 0xA54FF53A
	d.h[4] = 0x510E527F
	d.h[5] = 0x9B05688C
	d.h[6] = 0x1F83D9AB
	d.h[7] = 0x5BE0CD19
	d.nx = 0
	d.len = 0
}

// Write absorbs p into the digest.
func (d *janosSHA256) Write(p []byte) {
	d.len += uint64(len(p))
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == janosSHA256Chunk {
			janosSHA256Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if n := len(p) &^ (janosSHA256Chunk - 1); n > 0 {
		janosSHA256Block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
}

// Sum returns the final digest.  It does not modify the receiver, so
// callers may keep writing to d after taking a snapshot.
func (d *janosSHA256) Sum() [32]byte {
	dd := *d
	length := dd.len
	// Pad with 1 bit then zeros until length ≡ 56 mod 64.
	var tmp [janosSHA256Chunk + 8]byte
	tmp[0] = 0x80
	var t uint64
	if length%64 < 56 {
		t = 56 - length%64
	} else {
		t = 64 + 56 - length%64
	}
	// Length in bits, big-endian.
	length <<= 3
	pad := tmp[:t+8]
	pad[t+0] = byte(length >> 56)
	pad[t+1] = byte(length >> 48)
	pad[t+2] = byte(length >> 40)
	pad[t+3] = byte(length >> 32)
	pad[t+4] = byte(length >> 24)
	pad[t+5] = byte(length >> 16)
	pad[t+6] = byte(length >> 8)
	pad[t+7] = byte(length)
	dd.Write(pad)

	var digest [32]byte
	for i, v := range dd.h {
		digest[i*4+0] = byte(v >> 24)
		digest[i*4+1] = byte(v >> 16)
		digest[i*4+2] = byte(v >> 8)
		digest[i*4+3] = byte(v)
	}
	return digest
}

// janosSHA256Block runs the compression function over p, which must be
// a multiple of janosSHA256Chunk bytes.
func janosSHA256Block(d *janosSHA256, p []byte) {
	var w [64]uint32
	h0, h1, h2, h3 := d.h[0], d.h[1], d.h[2], d.h[3]
	h4, h5, h6, h7 := d.h[4], d.h[5], d.h[6], d.h[7]
	for len(p) >= janosSHA256Chunk {
		a, b, c, dd, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		for i := 0; i < 64; i++ {
			if i < 16 {
				j := i * 4
				w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
			} else {
				v1 := w[i-2]
				s1 := ((v1 >> 17) | (v1 << 15)) ^ ((v1 >> 19) | (v1 << 13)) ^ (v1 >> 10)
				v2 := w[i-15]
				s0 := ((v2 >> 7) | (v2 << 25)) ^ ((v2 >> 18) | (v2 << 14)) ^ (v2 >> 3)
				w[i] = s1 + w[i-7] + s0 + w[i-16]
			}
			S1 := ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
			ch := (e & f) ^ (^e & g)
			t1 := h + S1 + ch + janosSHA256K[i] + w[i]
			S0 := ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := S0 + maj

			h = g
			g = f
			f = e
			e = dd + t1
			dd = c
			c = b
			b = a
			a = t1 + t2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += dd
		h4 += e
		h5 += f
		h6 += g
		h7 += h

		p = p[janosSHA256Chunk:]
	}
	d.h[0], d.h[1], d.h[2], d.h[3] = h0, h1, h2, h3
	d.h[4], d.h[5], d.h[6], d.h[7] = h4, h5, h6, h7
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SHA-512 for the janos_hash package.  See sha256.go for the general
// design notes; SHA-512 is the same shape with 128-byte blocks, 80
// rounds, 8x64-bit state.

package janos_hash

// SHA512Chunk is the SHA-512 block size in bytes.
const SHA512Chunk = 128

// SHA-512 round constants (FIPS 180-4, §4.2.3).
var sha512K = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// SHA512 is a streaming SHA-512 digest.  Zero allocations; stack-safe.
type SHA512 struct {
	h   [8]uint64
	x   [SHA512Chunk]byte
	nx  int
	len uint64
}

// Reset returns the digest to its initial state.
func (d *SHA512) Reset() {
	d.h[0] = 0x6a09e667f3bcc908
	d.h[1] = 0xbb67ae8584caa73b
	d.h[2] = 0x3c6ef372fe94f82b
	d.h[3] = 0xa54ff53a5f1d36f1
	d.h[4] = 0x510e527fade682d1
	d.h[5] = 0x9b05688c2b3e6c1f
	d.h[6] = 0x1f83d9abfb41bd6b
	d.h[7] = 0x5be0cd19137e2179
	d.nx = 0
	d.len = 0
}

// Write absorbs p into the digest.
func (d *SHA512) Write(p []byte) {
	d.len += uint64(len(p))
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == SHA512Chunk {
			sha512Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if n := len(p) &^ (SHA512Chunk - 1); n > 0 {
		sha512Block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
}

// Sum returns the 64-byte digest.  Does not modify the receiver.
func (d *SHA512) Sum() [64]byte {
	dd := *d
	length := dd.len
	var tmp [SHA512Chunk + 16]byte
	tmp[0] = 0x80
	var t uint64
	if length%128 < 112 {
		t = 112 - length%128
	} else {
		t = 128 + 112 - length%128
	}
	length <<= 3
	pad := tmp[:t+16]
	pad[t+8+0] = byte(length >> 56)
	pad[t+8+1] = byte(length >> 48)
	pad[t+8+2] = byte(length >> 40)
	pad[t+8+3] = byte(length >> 32)
	pad[t+8+4] = byte(length >> 24)
	pad[t+8+5] = byte(length >> 16)
	pad[t+8+6] = byte(length >> 8)
	pad[t+8+7] = byte(length)
	dd.Write(pad)

	var digest [64]byte
	for i, v := range dd.h {
		digest[i*8+0] = byte(v >> 56)
		digest[i*8+1] = byte(v >> 48)
		digest[i*8+2] = byte(v >> 40)
		digest[i*8+3] = byte(v >> 32)
		digest[i*8+4] = byte(v >> 24)
		digest[i*8+5] = byte(v >> 16)
		digest[i*8+6] = byte(v >> 8)
		digest[i*8+7] = byte(v)
	}
	return digest
}

func sha512Block(d *SHA512, p []byte) {
	var w [80]uint64
	h0, h1, h2, h3 := d.h[0], d.h[1], d.h[2], d.h[3]
	h4, h5, h6, h7 := d.h[4], d.h[5], d.h[6], d.h[7]
	for len(p) >= SHA512Chunk {
		a, b, c, dd, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7
		for i := 0; i < 80; i++ {
			if i < 16 {
				j := i * 8
				w[i] = uint64(p[j])<<56 | uint64(p[j+1])<<48 | uint64(p[j+2])<<40 | uint64(p[j+3])<<32 |
					uint64(p[j+4])<<24 | uint64(p[j+5])<<16 | uint64(p[j+6])<<8 | uint64(p[j+7])
			} else {
				v1 := w[i-2]
				s1 := ((v1 >> 19) | (v1 << 45)) ^ ((v1 >> 61) | (v1 << 3)) ^ (v1 >> 6)
				v2 := w[i-15]
				s0 := ((v2 >> 1) | (v2 << 63)) ^ ((v2 >> 8) | (v2 << 56)) ^ (v2 >> 7)
				w[i] = s1 + w[i-7] + s0 + w[i-16]
			}
			S1 := ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23))
			ch := (e & f) ^ (^e & g)
			t1 := h + S1 + ch + sha512K[i] + w[i]
			S0 := ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25))
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
		p = p[SHA512Chunk:]
	}
	d.h[0], d.h[1], d.h[2], d.h[3] = h0, h1, h2, h3
	d.h[4], d.h[5], d.h[6], d.h[7] = h4, h5, h6, h7
}

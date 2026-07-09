// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm2

import (
	"errors"
	"fmt"
)

// This file adds the TPM key hierarchy JanOS identities need: a P-256
// key created inside the TPM whose private scalar never leaves it,
// with sign and ECDH operations performed in-TPM.  It mirrors the
// internal/secureenclave provider — GenerateKey / PublicPoint / Sign /
// ECDH / Close — so the two hardware roots present the same shape to
// the identity layer.
//
// The key is a CreatePrimary transient in the owner hierarchy: an
// unrestricted ECC P-256 key with sign+decrypt set, so a single key
// serves both TPM2_Sign (ECDSA) and TPM2_ECDH_ZGen.

// Structure tags and handles.
const (
	tagSessions uint16 = 0x8002 // TPM_ST_SESSIONS

	rhOwner   uint32 = 0x40000001 // TPM_RH_OWNER
	rhNull    uint32 = 0x40000007 // TPM_RH_NULL
	rsPW      uint32 = 0x40000009 // TPM_RS_PW (password session)
	stHashChk uint16 = 0x8024     // TPM_ST_HASHCHECK
)

// Command codes.
const (
	ccCreatePrimary uint32 = 0x00000131
	ccSign          uint32 = 0x0000015D
	ccECDHZGen      uint32 = 0x00000154
	ccFlushContext  uint32 = 0x00000165
)

// Algorithm and curve identifiers.
const (
	algECC    uint16 = 0x0023
	algSHA256 uint16 = 0x000B
	algECDSA  uint16 = 0x0018
	algNull   uint16 = 0x0010
	eccP256   uint16 = 0x0003
)

// objectAttrECCKey: fixedTPM | fixedParent | sensitiveDataOrigin |
// userWithAuth | decrypt | sign — an unrestricted key generated in
// the TPM, usable for both ECDSA and ECDH.
const objectAttrECCKey uint32 = 0x00060072

// -- little marshalling helpers --------------------------------------

// tpm2b prefixes b with its 2-byte big-endian length (a TPM2B).
func tpm2b(b []byte) []byte {
	out := make([]byte, 2+len(b))
	putU16(out[0:2], uint16(len(b)))
	copy(out[2:], b)
	return out
}

// pwAuthArea is the 9-byte password authorization area with an empty
// password: TPM_RS_PW, no nonce, no attributes, no HMAC.
func pwAuthArea() []byte {
	b := make([]byte, 0, 9)
	var h [4]byte
	putU32(h[:], rsPW)
	b = append(b, h[:]...) // sessionHandle
	b = append(b, 0, 0)    // nonce size 0
	b = append(b, 0)       // sessionAttributes
	b = append(b, 0, 0)    // hmac size 0
	return b
}

// withAuth wraps a body's parameter bytes with a single authorized
// handle and the empty-password session: handle || authSize || pwAuth
// || params.
func withAuth(handle uint32, params []byte) []byte {
	auth := pwAuthArea()
	out := make([]byte, 0, 4+4+len(auth)+len(params))
	var h, sz [4]byte
	putU32(h[:], handle)
	putU32(sz[:], uint32(len(auth)))
	out = append(out, h[:]...)
	out = append(out, sz[:]...)
	out = append(out, auth...)
	out = append(out, params...)
	return out
}

// cursor is a forward reader over a response byte slice.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) u16() uint16 {
	if c.err != nil || len(c.b) < 2 {
		c.fail()
		return 0
	}
	v := u16(c.b[:2])
	c.b = c.b[2:]
	return v
}

func (c *cursor) u32() uint32 {
	if c.err != nil || len(c.b) < 4 {
		c.fail()
		return 0
	}
	v := u32(c.b[:4])
	c.b = c.b[4:]
	return v
}

func (c *cursor) tpm2b() []byte {
	n := int(c.u16())
	if c.err != nil || len(c.b) < n {
		c.fail()
		return nil
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v
}

func (c *cursor) skip(n int) {
	if c.err != nil || len(c.b) < n {
		c.fail()
		return
	}
	c.b = c.b[n:]
}

func (c *cursor) fail() {
	if c.err == nil {
		c.err = errors.New("tpm2: response truncated or malformed")
	}
}

// -- Key --------------------------------------------------------------

// Key is a TPM-resident P-256 key.  The private scalar lives in the
// TPM; PublicPoint, Sign, and ECDH operate on it without exposing it.
// Close flushes the transient handle.
type Key struct {
	dev    *Device
	handle uint32
	pub    [64]byte
}

// eccKeyTemplate builds the TPM2B_PUBLIC for an unrestricted P-256
// sign+decrypt key with no scheme (caller supplies the scheme at
// sign time), NULL symmetric and KDF.  uniqueSeed is placed in the
// unique.X buffer: CreatePrimary folds the unique field into the key
// derivation, so a random seed makes each primary distinct (an empty
// seed would make CreatePrimary deterministic and every key identical).
func eccKeyTemplate(uniqueSeed []byte) []byte {
	var t []byte
	var u16b [2]byte
	put := func(v uint16) { putU16(u16b[:], v); t = append(t, u16b[:]...) }
	var u32b [4]byte

	put(algECC)    // type
	put(algSHA256) // nameAlg
	putU32(u32b[:], objectAttrECCKey)
	t = append(t, u32b[:]...) // objectAttributes
	t = append(t, tpm2b(nil)...)
	// TPMS_ECC_PARMS: symmetric NULL, scheme NULL, curve P256, kdf NULL
	put(algNull)
	put(algNull)
	put(eccP256)
	put(algNull)
	// unique TPMS_ECC_POINT: seed in X, empty Y
	t = append(t, tpm2b(uniqueSeed)...)
	t = append(t, tpm2b(nil)...)
	return tpm2b(t)
}

// GenerateKey creates a fresh P-256 key inside the TPM (CreatePrimary
// under the owner hierarchy).  The private scalar is generated in the
// TPM and never leaves it.  Close the returned Key to flush it.
func (d *Device) GenerateKey() (*Key, error) {
	// A random unique seed makes each CreatePrimary distinct (the
	// command is otherwise deterministic from the hierarchy seed +
	// template).  Drawn from the TPM's own RNG.
	seed, err := d.GetRandom(32)
	if err != nil {
		return nil, err
	}
	// inSensitive (empty), inPublic (template), outsideInfo (empty),
	// creationPCR (count 0).
	params := make([]byte, 0, 160)
	params = append(params, tpm2b(append(tpm2b(nil), tpm2b(nil)...))...) // TPM2B_SENSITIVE_CREATE
	params = append(params, eccKeyTemplate(seed)...)                     // inPublic
	params = append(params, tpm2b(nil)...)                               // outsideInfo
	params = append(params, 0, 0, 0, 0)                                  // creationPCR count 0

	body := withAuth(rhOwner, params)
	resp, err := d.transact(tagSessions, ccCreatePrimary, body)
	if err != nil {
		return nil, err
	}
	// Response: objectHandle || parameterSize || outPublic || ...
	c := &cursor{b: resp}
	handle := c.u32()
	c.u32() // parameterSize
	outPublic := c.tpm2b()
	if c.err != nil {
		return nil, c.err
	}
	pub, err := parseECCPublic(outPublic)
	if err != nil {
		// Best-effort flush of the handle we can't use.
		d.flush(handle)
		return nil, err
	}
	return &Key{dev: d, handle: handle, pub: pub}, nil
}

// parseECCPublic walks a TPMT_PUBLIC and returns the 64-byte X||Y of
// its unique ECC point.
func parseECCPublic(pub []byte) ([64]byte, error) {
	var out [64]byte
	c := &cursor{b: pub}
	c.skip(2)      // type
	c.skip(2)      // nameAlg
	c.skip(4)      // objectAttributes
	c.tpm2b()      // authPolicy
	c.skip(2)      // symmetric (NULL)
	c.skip(2)      // scheme (NULL)
	c.skip(2)      // curveID
	c.skip(2)      // kdf (NULL)
	x := c.tpm2b() // unique X
	y := c.tpm2b() // unique Y
	if c.err != nil {
		return out, c.err
	}
	if len(x) > 32 || len(y) > 32 {
		return out, fmt.Errorf("tpm2: ECC point coordinate too large (x=%d y=%d)", len(x), len(y))
	}
	// Right-align each coordinate into its 32-byte field (the TPM may
	// drop a leading zero byte).
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out, nil
}

// PublicPoint returns the key's public point as 64 bytes of
// uncompressed X||Y.
func (k *Key) PublicPoint() ([64]byte, error) {
	if k.dev == nil {
		return [64]byte{}, errors.New("tpm2: key is closed")
	}
	return k.pub, nil
}

// Sign produces an ECDSA signature over a 32-byte SHA-256 digest,
// computed in the TPM.  The signature is returned as raw r||s (64
// bytes).
func (k *Key) Sign(digest []byte) ([]byte, error) {
	if k.dev == nil {
		return nil, errors.New("tpm2: key is closed")
	}
	if len(digest) != 32 {
		return nil, errors.New("tpm2: Sign expects a 32-byte SHA-256 digest")
	}
	params := make([]byte, 0, 64)
	params = append(params, tpm2b(digest)...) // digest
	var scheme [4]byte                        // inScheme: ECDSA + SHA256
	putU16(scheme[0:2], algECDSA)
	putU16(scheme[2:4], algSHA256)
	params = append(params, scheme[:]...)
	// validation: TPMT_TK_HASHCHECK with hierarchy NULL, empty digest.
	var vtk [6]byte
	putU16(vtk[0:2], stHashChk)
	putU32(vtk[2:6], rhNull)
	params = append(params, vtk[:]...)
	params = append(params, tpm2b(nil)...)

	resp, err := k.dev.transact(tagSessions, ccSign, withAuth(k.handle, params))
	if err != nil {
		return nil, err
	}
	// Response: parameterSize || TPMT_SIGNATURE || ...
	c := &cursor{b: resp}
	c.u32()   // parameterSize
	c.skip(2) // sigAlg (ECDSA)
	c.skip(2) // hash (SHA256)
	r := c.tpm2b()
	s := c.tpm2b()
	if c.err != nil {
		return nil, c.err
	}
	out := make([]byte, 64)
	copy(out[32-len(r):32], r)
	copy(out[64-len(s):64], s)
	return out, nil
}

// ECDH computes the ECDH shared secret between this key and a peer's
// public point (64-byte uncompressed X||Y), returning the 32-byte
// shared X coordinate.  The scalar multiplication happens in the TPM.
func (k *Key) ECDH(peerPoint [64]byte) ([]byte, error) {
	if k.dev == nil {
		return nil, errors.New("tpm2: key is closed")
	}
	// inPoint: TPM2B_ECC_POINT wrapping X||Y as two TPM2Bs.
	inner := append(tpm2b(peerPoint[:32]), tpm2b(peerPoint[32:])...)
	params := tpm2b(inner)

	resp, err := k.dev.transact(tagSessions, ccECDHZGen, withAuth(k.handle, params))
	if err != nil {
		return nil, err
	}
	// Response: parameterSize || outPoint (TPM2B_ECC_POINT) || ...
	c := &cursor{b: resp}
	c.u32() // parameterSize
	c.u16() // outPoint size
	x := c.tpm2b()
	if c.err != nil {
		return nil, c.err
	}
	out := make([]byte, 32)
	copy(out[32-len(x):32], x)
	return out, nil
}

// Close flushes the TPM's transient handle for this key.  Safe to
// call more than once.
func (k *Key) Close() error {
	if k.dev == nil {
		return nil
	}
	err := k.dev.flush(k.handle)
	k.dev = nil
	return err
}

// flush issues TPM2_FlushContext for a transient handle.
func (d *Device) flush(handle uint32) error {
	var h [4]byte
	putU32(h[:], handle)
	_, err := d.transact(tagNoSessions, ccFlushContext, h[:])
	return err
}

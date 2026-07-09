// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm2

import (
	"errors"
	"fmt"
)

// This file adds the TPM key hierarchy JanOS identities need: P-256
// keys whose private scalar is generated inside the TPM and never
// leaves it, with sign and ECDH performed in-TPM.  It mirrors the
// internal/secureenclave provider — GenerateKey / PublicPoint / Sign /
// ECDH / Close — so the two hardware roots present the same shape to
// the identity layer.
//
// # Scaling: wrapped keys, not resident keys
//
// A TPM has room for only a handful of transient objects (the spec
// floor, TPM_PT_HR_TRANSIENT_MIN, is 3) and little persistent NV, so
// it cannot hold thousands of keys.  Neither can a Secure Enclave or
// Pluton — they all use the same pattern: one hardware master key
// wraps each per-key private blob, and the (encrypted, useless-off-
// hardware) blobs live in ordinary storage.  SE/Pluton hide this
// behind the keychain / CNG; the TPM makes us do it explicitly.
//
// So we keep exactly one storage root key (SRK) — a restricted
// decrypt primary under the owner hierarchy — loaded per Device, and
// every identity key is a TPM2_Create child wrapped under it.  The
// wrapped blob (outPrivate + outPublic) lives in the Key, in ordinary
// memory.  To sign or ECDH, we TPM2_Load the blob (one transient
// slot), operate, and TPM2_FlushContext.  This scales to unlimited
// identities with only the SRK plus one working slot resident at a
// time; the private scalar is never usable outside the TPM.

// Command codes.
const (
	ccCreatePrimary uint32 = 0x00000131
	ccCreate        uint32 = 0x00000153
	ccECDHZGen      uint32 = 0x00000154
	ccLoad          uint32 = 0x00000157
	ccSign          uint32 = 0x0000015D
	ccFlushContext  uint32 = 0x00000165
)

// Structure tags and permanent handles.
const (
	tagSessions uint16 = 0x8002     // TPM_ST_SESSIONS
	rhOwner     uint32 = 0x40000001 // TPM_RH_OWNER
	rhNull      uint32 = 0x40000007 // TPM_RH_NULL
	rsPW        uint32 = 0x40000009 // TPM_RS_PW (password session)
	stHashChk   uint16 = 0x8024     // TPM_ST_HASHCHECK
)

// Algorithms and curve.
const (
	algAES    uint16 = 0x0006
	algSHA256 uint16 = 0x000B
	algNull   uint16 = 0x0010
	algECDSA  uint16 = 0x0018
	algECC    uint16 = 0x0023
	algCFB    uint16 = 0x0043
	eccP256   uint16 = 0x0003
)

// Object attributes.
//
// srkAttr: restricted | decrypt | fixedTPM | fixedParent |
// sensitiveDataOrigin | userWithAuth — a storage parent that wraps
// children.
//
// leafAttr: sign | decrypt | fixedTPM | fixedParent |
// sensitiveDataOrigin | userWithAuth — an unrestricted key usable for
// both TPM2_Sign and TPM2_ECDH_ZGen.
const (
	srkAttr  uint32 = 0x00030072
	leafAttr uint32 = 0x00060072
)

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

// withAuth wraps params with a single authorized handle and the
// empty-password session: handle || authSize || pwAuth || params.
func withAuth(handle uint32, params []byte) []byte {
	auth := pwAuthArea()
	out := make([]byte, 0, 8+len(auth)+len(params))
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

// -- templates --------------------------------------------------------

// srkTemplate is the TPM2B_PUBLIC for the storage root key: a
// restricted ECC P-256 decrypt parent with AES-128-CFB wrapping.  The
// unique field is empty, so CreatePrimary yields the same SRK every
// time on a given TPM — the stable parent under which children wrap.
func srkTemplate() []byte {
	var t []byte
	var u16b [2]byte
	put := func(v uint16) { putU16(u16b[:], v); t = append(t, u16b[:]...) }
	var u32b [4]byte

	put(algECC)
	put(algSHA256)
	putU32(u32b[:], srkAttr)
	t = append(t, u32b[:]...)
	t = append(t, tpm2b(nil)...) // authPolicy
	// TPMS_ECC_PARMS: symmetric AES-128-CFB, scheme NULL, P256, kdf NULL
	put(algAES)
	put(128)
	put(algCFB)
	put(algNull)
	put(eccP256)
	put(algNull)
	// unique: empty X, empty Y
	t = append(t, tpm2b(nil)...)
	t = append(t, tpm2b(nil)...)
	return tpm2b(t)
}

// leafTemplate is the TPM2B_PUBLIC for an identity key: an
// unrestricted ECC P-256 sign+decrypt key with no scheme (the scheme
// is supplied at sign time), NULL symmetric and KDF, empty unique.
// TPM2_Create generates fresh random key material each call, so no
// unique seed is needed for distinctness.
func leafTemplate() []byte {
	var t []byte
	var u16b [2]byte
	put := func(v uint16) { putU16(u16b[:], v); t = append(t, u16b[:]...) }
	var u32b [4]byte

	put(algECC)
	put(algSHA256)
	putU32(u32b[:], leafAttr)
	t = append(t, u32b[:]...)
	t = append(t, tpm2b(nil)...) // authPolicy
	// TPMS_ECC_PARMS: symmetric NULL, scheme NULL, P256, kdf NULL
	put(algNull)
	put(algNull)
	put(eccP256)
	put(algNull)
	// unique: empty X, empty Y
	t = append(t, tpm2b(nil)...)
	t = append(t, tpm2b(nil)...)
	return tpm2b(t)
}

// createParams builds the common CreatePrimary/Create parameter tail:
// empty inSensitive, the given inPublic, empty outsideInfo, empty
// creationPCR.
func createParams(inPublic []byte) []byte {
	p := make([]byte, 0, 16+len(inPublic))
	p = append(p, tpm2b(append(tpm2b(nil), tpm2b(nil)...))...) // TPM2B_SENSITIVE_CREATE
	p = append(p, inPublic...)
	p = append(p, tpm2b(nil)...) // outsideInfo
	p = append(p, 0, 0, 0, 0)    // creationPCR count 0
	return p
}

// -- SRK --------------------------------------------------------------

// ensureSRKLocked creates and caches the storage root key if it is not
// already loaded.  Caller holds d.mu.
func (d *Device) ensureSRKLocked() error {
	if d.srk != 0 {
		return nil
	}
	body := withAuth(rhOwner, createParams(srkTemplate()))
	resp, err := d.transact(tagSessions, ccCreatePrimary, body)
	if err != nil {
		return err
	}
	c := &cursor{b: resp}
	handle := c.u32() // objectHandle
	if c.err != nil {
		return c.err
	}
	d.srk = handle
	return nil
}

// -- Key --------------------------------------------------------------

// Key is a TPM-wrapped P-256 identity key.  It holds only the wrapped
// blob (the private area encrypted under the SRK, plus the public
// area) in ordinary memory — nothing resident in the TPM.  Operations
// load the blob into the TPM transiently.  The private scalar is never
// usable outside the TPM.
type Key struct {
	dev     *Device
	priv    []byte   // outPrivate content (wrapped sensitive area)
	pubArea []byte   // outPublic content (TPMT_PUBLIC), re-wrapped on load
	pub     [64]byte // parsed public point
}

// GenerateKey creates a fresh P-256 key wrapped under the device's
// storage root key.  The private scalar is generated inside the TPM;
// only the wrapped blob and public point come back.  Scales to any
// number of keys — each is just a blob in memory.
func (d *Device) GenerateKey() (*Key, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.ensureSRKLocked(); err != nil {
		return nil, err
	}
	body := withAuth(d.srk, createParams(leafTemplate()))
	resp, err := d.transact(tagSessions, ccCreate, body)
	if err != nil {
		return nil, err
	}
	// Response: parameterSize || outPrivate || outPublic || ...
	c := &cursor{b: resp}
	c.u32() // parameterSize
	priv := c.tpm2b()
	pubArea := c.tpm2b()
	if c.err != nil {
		return nil, c.err
	}
	pub, err := parseECCPublic(pubArea)
	if err != nil {
		return nil, err
	}
	// Copy out of the response buffer, which is reused per transact.
	return &Key{
		dev:     d,
		priv:    append([]byte(nil), priv...),
		pubArea: append([]byte(nil), pubArea...),
		pub:     pub,
	}, nil
}

// loadLocked loads the key's wrapped blob under the SRK and returns
// the transient handle.  Caller holds d.mu and must flush the handle.
func (d *Device) loadLocked(k *Key) (uint32, error) {
	if err := d.ensureSRKLocked(); err != nil {
		return 0, err
	}
	params := append(tpm2b(k.priv), tpm2b(k.pubArea)...)
	resp, err := d.transact(tagSessions, ccLoad, withAuth(d.srk, params))
	if err != nil {
		return 0, err
	}
	c := &cursor{b: resp}
	handle := c.u32() // objectHandle
	if c.err != nil {
		return 0, c.err
	}
	return handle, nil
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
// computed in the TPM.  Returned as raw r||s (64 bytes).
func (k *Key) Sign(digest []byte) ([]byte, error) {
	if k.dev == nil {
		return nil, errors.New("tpm2: key is closed")
	}
	if len(digest) != 32 {
		return nil, errors.New("tpm2: Sign expects a 32-byte SHA-256 digest")
	}
	d := k.dev
	d.mu.Lock()
	defer d.mu.Unlock()
	handle, err := d.loadLocked(k)
	if err != nil {
		return nil, err
	}
	defer d.flushLocked(handle)

	params := make([]byte, 0, 64)
	params = append(params, tpm2b(digest)...)
	var scheme [4]byte // inScheme: ECDSA + SHA256
	putU16(scheme[0:2], algECDSA)
	putU16(scheme[2:4], algSHA256)
	params = append(params, scheme[:]...)
	var vtk [6]byte // validation: TPMT_TK_HASHCHECK, hierarchy NULL
	putU16(vtk[0:2], stHashChk)
	putU32(vtk[2:6], rhNull)
	params = append(params, vtk[:]...)
	params = append(params, tpm2b(nil)...)

	resp, err := d.transact(tagSessions, ccSign, withAuth(handle, params))
	if err != nil {
		return nil, err
	}
	// Response: parameterSize || sigAlg || hash || sigR || sigS || ...
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
	d := k.dev
	d.mu.Lock()
	defer d.mu.Unlock()
	handle, err := d.loadLocked(k)
	if err != nil {
		return nil, err
	}
	defer d.flushLocked(handle)

	inner := append(tpm2b(peerPoint[:32]), tpm2b(peerPoint[32:])...)
	params := tpm2b(inner) // TPM2B_ECC_POINT

	resp, err := d.transact(tagSessions, ccECDHZGen, withAuth(handle, params))
	if err != nil {
		return nil, err
	}
	// Response: parameterSize || outPoint size || X || Y || ...
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

// Close marks the key unusable.  There is no TPM handle to release —
// the key is only ever loaded transiently during an operation — so
// this just drops the device reference.  Safe to call more than once.
func (k *Key) Close() error {
	k.dev = nil
	return nil
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
	// Right-align each coordinate (the TPM may drop a leading zero).
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out, nil
}

// flushLocked issues TPM2_FlushContext for a transient handle.  Caller
// holds d.mu.
func (d *Device) flushLocked(handle uint32) error {
	var h [4]byte
	putU32(h[:], handle)
	_, err := d.transact(tagNoSessions, ccFlushContext, h[:])
	return err
}

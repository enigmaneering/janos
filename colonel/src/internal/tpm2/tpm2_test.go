// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
)

// TestBuildCommandGetRandom checks the exact wire bytes for
// GetRandom(8) against a hand-computed golden vector:
//
//	80 01          tag  = TPM_ST_NO_SESSIONS
//	00 00 00 0C    size = 12
//	00 00 01 7B    code = TPM_CC_GetRandom
//	00 08          bytesRequested = 8
func TestBuildCommandGetRandom(t *testing.T) {
	var params [2]byte
	putU16(params[:], 8)
	got := buildCommand(tagNoSessions, ccGetRandom, params[:])
	want := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x08}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetRandom(8) command\n got %X\nwant %X", got, want)
	}
}

// TestBuildCommandGetCapability checks GetCapability(TPM_PROPERTIES,
// TPM_PT_MANUFACTURER, 1):
//
//	80 01          tag
//	00 00 00 16    size = 22
//	00 00 01 7A    code = TPM_CC_GetCapability
//	00 00 00 06    capability = TPM_CAP_TPM_PROPERTIES
//	00 00 01 05    property   = TPM_PT_MANUFACTURER
//	00 00 00 01    propertyCount = 1
func TestBuildCommandGetCapability(t *testing.T) {
	var params [12]byte
	putU32(params[0:4], capTPMProperties)
	putU32(params[4:8], ptManufacturer)
	putU32(params[8:12], 1)
	got := buildCommand(tagNoSessions, ccGetCapability, params[:])
	want := []byte{
		0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7A,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetCapability command\n got %X\nwant %X", got, want)
	}
}

func TestParseResponseHeader(t *testing.T) {
	// Success: tag, size=10, rc=0, no params.
	ok := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00}
	params, err := parseResponseHeader(ok)
	if err != nil {
		t.Fatalf("success header: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("success header params = %X, want empty", params)
	}

	// Failure: responseCode 0x0000009A (TPM_RC_AUTH_FAIL-ish).
	fail := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x9A}
	if _, err := parseResponseHeader(fail); err == nil {
		t.Error("nonzero responseCode did not error")
	}

	// Size-field mismatch.
	bad := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00}
	if _, err := parseResponseHeader(bad); err == nil {
		t.Error("size mismatch did not error")
	}

	// Short buffer.
	if _, err := parseResponseHeader([]byte{0x80, 0x01}); err == nil {
		t.Error("short buffer did not error")
	}
}

// TestParseGetRandomResponse parses a synthetic GetRandom response
// carrying an 8-byte TPM2B_DIGEST.
func TestParseGetRandomResponse(t *testing.T) {
	digest := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	// Full response = header(10) + size(2) + digest(8) = 20 bytes.
	resp := make([]byte, 0, 20)
	hdr := make([]byte, 10)
	putU16(hdr[0:2], tagNoSessions)
	putU32(hdr[2:6], 20)
	putU32(hdr[6:10], 0) // success
	resp = append(resp, hdr...)
	sz := make([]byte, 2)
	putU16(sz, uint16(len(digest)))
	resp = append(resp, sz...)
	resp = append(resp, digest...)

	params, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	got := params[2 : 2+int(u16(params[0:2]))]
	if !bytes.Equal(got, digest) {
		t.Fatalf("parsed digest %X, want %X", got, digest)
	}
}

// TestParseGetCapabilityProperties parses a synthetic
// TPM_CAP_TPM_PROPERTIES response with two tagged properties.
func TestParseGetCapabilityProperties(t *testing.T) {
	// Body: two properties — manufacturer "IBM\0" and family "2.0\0".
	body := []byte{
		0x00, 0x00, 0x01, 0x05, 0x49, 0x42, 0x4D, 0x00, // manufacturer = 0x49424D00
		0x00, 0x00, 0x01, 0x00, 0x32, 0x2E, 0x30, 0x00, // family = "2.0\0"
	}
	// Param area: moreData(1) || capability(4) || count(4) || body.
	param := make([]byte, 0, 9+len(body))
	param = append(param, 0x00) // moreData
	c := make([]byte, 4)
	putU32(c, capTPMProperties)
	param = append(param, c...)
	pc := make([]byte, 4)
	putU32(pc, 2)
	param = append(param, pc...)
	param = append(param, body...)

	// Wrap in a full response and round-trip through the device's
	// parse path via a fake transport.
	dev := &Device{t: &fakeTransport{param: param}}
	props, err := dev.getProperties(ptFixedPropretyBase, 32)
	if err != nil {
		t.Fatalf("getProperties: %v", err)
	}
	if got := trimASCII(props[ptManufacturer]); got != "IBM" {
		t.Errorf("manufacturer = %q, want IBM", got)
	}
	if got := trimASCII(props[ptFamilyIndicator]); got != "2.0" {
		t.Errorf("family = %q, want 2.0", got)
	}
}

func TestTrimASCII(t *testing.T) {
	cases := map[uint32]string{
		0x49424D00: "IBM",  // "IBM\0"
		0x53544D20: "STM ", // "STM " -> space is printable, kept
		0x322E3000: "2.0",  // "2.0\0"
		0x50524C53: "PRLS", // Parallels
		0x00000000: "",
	}
	for v, want := range cases {
		if got := trimASCII(v); got != want {
			t.Errorf("trimASCII(0x%08X) = %q, want %q", v, got, want)
		}
	}
}

// fakeTransport returns a canned parameter area wrapped in a valid
// response header, letting parse paths be tested without hardware.
type fakeTransport struct {
	param []byte
}

func (f *fakeTransport) submit(cmd []byte) ([]byte, error) {
	resp := make([]byte, 10+len(f.param))
	putU16(resp[0:2], tagNoSessions)
	putU32(resp[2:6], uint32(len(resp)))
	putU32(resp[6:10], 0)
	copy(resp[10:], f.param)
	return resp, nil
}

func (f *fakeTransport) close() error { return nil }

// TestDeviceLive exercises the real transport against an actual TPM.
// It skips when no device is present (host dev machines, CI runners,
// darwin, tamago), so it is safe to run everywhere; it only does work
// on a machine with a reachable TPM (e.g. the Parallels vTPM used for
// JanOS hardware bring-up).
func TestDeviceLive(t *testing.T) {
	dev, err := Open()
	if err == ErrNoDevice {
		t.Skip("no TPM device on this host")
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	// GetRandom: two draws must succeed and differ (a stuck RNG or a
	// broken transport would return zeros or identical buffers).
	a, err := dev.GetRandom(16)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	if len(a) != 16 {
		t.Fatalf("GetRandom returned %d bytes, want 16", len(a))
	}
	b, err := dev.GetRandom(16)
	if err != nil {
		t.Fatalf("GetRandom (2): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Errorf("two GetRandom draws are identical: %X", a)
	}
	allZero := true
	for _, c := range a {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("GetRandom returned all zeros")
	}
	t.Logf("GetRandom(16): %X", a)

	// Info: read the fixed properties and log the device identity.
	info, err := dev.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	t.Logf("TPM identity: manufacturer=%q vendor=%q family=%q firmware=0x%016X revision=%d",
		info.Manufacturer, info.VendorString, info.Family, info.FirmwareVersion, info.SpecRevision)
	if info.Family != "2.0" {
		t.Errorf("family = %q, want 2.0 (is this a TPM 2.0?)", info.Family)
	}
	if info.Manufacturer == "" {
		t.Errorf("manufacturer is empty — GetCapability parse likely broken")
	}
}

// TestKeyLive exercises the TPM key hierarchy against a real device,
// mirroring the internal/secureenclave provider tests.  Skips without
// a TPM.
func TestKeyLive(t *testing.T) {
	dev, err := Open()
	if err == ErrNoDevice {
		t.Skip("no TPM device on this host")
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	k, err := dev.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer k.Close()

	// Public point must be a valid P-256 point.
	pt, err := k.PublicPoint()
	if err != nil {
		t.Fatalf("PublicPoint: %v", err)
	}
	x := new(big.Int).SetBytes(pt[:32])
	y := new(big.Int).SetBytes(pt[32:])
	if !elliptic.P256().IsOnCurve(x, y) {
		t.Fatalf("public point not on P-256: %x", pt)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// A signature from the in-TPM key verifies against its public
	// point — the load-bearing proof it's a real, self-consistent
	// keypair whose private half is in the TPM.
	digest := sha256.Sum256([]byte("janos tpm attestation"))
	sig, err := k.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature = %d bytes, want 64 (r||s)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatalf("TPM signature did not verify against its own public point")
	}
	other := sha256.Sum256([]byte("different message"))
	if ecdsa.Verify(pub, other[:], r, s) {
		t.Fatalf("signature verified for the wrong digest")
	}
	t.Logf("TPM key public X = %x", pt[:32])

	// ECDH between two TPM keys must agree.
	k2, err := dev.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}
	defer k2.Close()
	p1, _ := k.PublicPoint()
	p2, _ := k2.PublicPoint()
	if p1 == p2 {
		t.Fatalf("two TPM keys share a public point")
	}
	ab, err := k.ECDH(p2)
	if err != nil {
		t.Fatalf("k.ECDH(k2): %v", err)
	}
	ba, err := k2.ECDH(p1)
	if err != nil {
		t.Fatalf("k2.ECDH(k): %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("ECDH mismatch:\n  a·B = %x\n  b·A = %x", ab, ba)
	}
	if len(ab) != 32 {
		t.Errorf("ECDH shared secret = %d bytes, want 32", len(ab))
	}
}

// TestKeyScaling proves the wrapped model scales past the TPM's
// transient-slot limit (spec floor is 3).  It generates far more keys
// than could ever be resident, keeps them all "open" (they are just
// blobs in memory), and verifies every one still signs correctly —
// which the CreatePrimary-per-key model could not do.
func TestKeyScaling(t *testing.T) {
	dev, err := Open()
	if err == ErrNoDevice {
		t.Skip("no TPM device on this host")
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	const n = 12 // well past TPM_PT_HR_TRANSIENT_MIN (3)
	keys := make([]*Key, 0, n)
	defer func() {
		for _, k := range keys {
			k.Close()
		}
	}()
	for i := 0; i < n; i++ {
		k, err := dev.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey %d/%d: %v", i+1, n, err)
		}
		keys = append(keys, k)
	}

	// Every key — including ones generated long before the last — must
	// still sign verifiably, proving none were evicted or lost.
	digest := sha256.Sum256([]byte("scaling"))
	for i, k := range keys {
		pt, _ := k.PublicPoint()
		x := new(big.Int).SetBytes(pt[:32])
		y := new(big.Int).SetBytes(pt[32:])
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		sig, err := k.Sign(digest[:])
		if err != nil {
			t.Fatalf("Sign key %d: %v", i, err)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatalf("key %d/%d signature did not verify", i, n)
		}
	}
	t.Logf("%d wrapped keys all signed verifiably (transient slots never exhausted)", n)
}

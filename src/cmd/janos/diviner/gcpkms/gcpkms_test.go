// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcpkms

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// setupFakeKMS spins up an in-process HTTP server that mimics the
// Cloud KMS REST endpoints we use, records the requests, and returns
// canned responses.  Sets endpoint and JANOS_GCP_ACCESS_TOKEN
// appropriately, restoring both on t.Cleanup.
func setupFakeKMS(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	prevEndpoint := endpoint
	endpoint = srv.URL
	prevToken := os.Getenv(EnvAccessToken)
	os.Setenv(EnvAccessToken, "fake-oauth-token-for-test")
	t.Cleanup(func() {
		srv.Close()
		endpoint = prevEndpoint
		if prevToken == "" {
			os.Unsetenv(EnvAccessToken)
		} else {
			os.Setenv(EnvAccessToken, prevToken)
		}
	})
	return srv
}

// p256PubKeyPEM: a well-formed PKIX SubjectPublicKeyInfo for an
// ECDSA P-256 key.  Generated deterministically in the scratchpad
// (see gen_p256_pem.go).  Corresponds to the raw pubkey bytes in
// p256PubKeyRaw below.
const p256PubKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfCPPq2b+5p7R0rsnbwQKkzYxFzBw
Nf1AGIADJVsK7znv95UwSvwFSM9KdMsMnR5AW+G0Y3UUR7x++JtnG8AhRw==
-----END PUBLIC KEY-----
`

var p256PubKeyRaw = [64]byte{
	0x7c, 0x23, 0xcf, 0xab, 0x66, 0xfe, 0xe6, 0x9e,
	0xd1, 0xd2, 0xbb, 0x27, 0x6f, 0x04, 0x0a, 0x93,
	0x36, 0x31, 0x17, 0x30, 0x70, 0x35, 0xfd, 0x40,
	0x18, 0x80, 0x03, 0x25, 0x5b, 0x0a, 0xef, 0x39,
	0xef, 0xf7, 0x95, 0x30, 0x4a, 0xfc, 0x05, 0x48,
	0xcf, 0x4a, 0x74, 0xcb, 0x0c, 0x9d, 0x1e, 0x40,
	0x5b, 0xe1, 0xb4, 0x63, 0x75, 0x14, 0x47, 0xbc,
	0x7e, 0xf8, 0x9b, 0x67, 0x1b, 0xc0, 0x21, 0x47,
}

// p256SigDERBase64: a base64-encoded DER-wrapped ECDSA P-256
// signature over the digest [0x00, 0x01, ..., 0x1f] under the key
// above.  DER = SEQUENCE { INTEGER r, INTEGER s }.
const p256SigDERBase64 = "MEYCIQDUsGi+/QxiXbu1gfMjfbIB8qaxAtz3FkQ3ygof/9nfRAIhANkyjNN/MYH/0Q9KXIeoW5s/x5zsvpUswlAqGSnG5Ct1"

// p256SigRawRS: what decodeECDSASignatureDER should produce when
// fed p256SigDERBase64 — the raw 64-byte r||s the runtime consumes.
var p256SigRawRS = [64]byte{
	0xd4, 0xb0, 0x68, 0xbe, 0xfd, 0x0c, 0x62, 0x5d,
	0xbb, 0xb5, 0x81, 0xf3, 0x23, 0x7d, 0xb2, 0x01,
	0xf2, 0xa6, 0xb1, 0x02, 0xdc, 0xf7, 0x16, 0x44,
	0x37, 0xca, 0x0a, 0x1f, 0xff, 0xd9, 0xdf, 0x44,
	0xd9, 0x32, 0x8c, 0xd3, 0x7f, 0x31, 0x81, 0xff,
	0xd1, 0x0f, 0x4a, 0x5c, 0x87, 0xa8, 0x5b, 0x9b,
	0x3f, 0xc7, 0x9c, 0xec, 0xbe, 0x95, 0x2c, 0xc2,
	0x50, 0x2a, 0x19, 0x29, 0xc6, 0xe4, 0x2b, 0x75,
}

func TestOpenURLValidation(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", ""},
		{"awskms://arn:aws:kms:...", "does not start with"},
		{"gcpkms://", "missing resource path"},
		{"gcpkms://not-projects/x", "must start with projects/"},
	}
	for _, c := range cases {
		_, err := Open(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("Open(%q): unexpected error %v", c.in, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Open(%q): expected error containing %q, got nil", c.in, c.wantErr)
		} else if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("Open(%q): error %q does not contain %q", c.in, err, c.wantErr)
		}
	}
}

func TestParseP256PubKeyPEM(t *testing.T) {
	pk, err := parseP256PubKeyPEM(p256PubKeyPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pk != p256PubKeyRaw {
		t.Errorf("pubkey mismatch\nwant %x\ngot  %x", p256PubKeyRaw, pk)
	}
}

func TestParseP256PubKeyPEMWrongAlgorithm(t *testing.T) {
	// A well-formed 1024-bit RSA SubjectPublicKeyInfo PEM: algorithm
	// OID 1.2.840.113549.1.1.1 (rsaEncryption).  Should be rejected
	// by the id-ecPublicKey OID gate in parseP256PubKeyPEM, not by
	// an ASN.1 syntax error.
	rsaPEM := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1ODOBLh
CPGGdX3ZHYYD0k03YQIDAQAB
-----END PUBLIC KEY-----
`
	_, err := parseP256PubKeyPEM(rsaPEM)
	if err == nil {
		t.Fatal("parseP256PubKeyPEM accepted a non-EC key")
	}
	if !strings.Contains(err.Error(), "id-ecPublicKey") && !strings.Contains(err.Error(), "ASN.1") {
		t.Errorf("error should mention EC pubkey OID or ASN.1 failure: %v", err)
	}
}

func TestDecodeECDSASignatureDER(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(p256SigDERBase64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	got, err := decodeECDSASignatureDER(der)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != p256SigRawRS {
		t.Errorf("sig mismatch\nwant %x\ngot  %x", p256SigRawRS, got)
	}
}

func TestPublicKeyRoundTripThroughFakeKMS(t *testing.T) {
	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/publicKey") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer fake-oauth-token-for-test" {
			t.Errorf("wrong bearer: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"pem": p256PubKeyPEM})
	})

	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := d.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pk != p256PubKeyRaw {
		t.Errorf("pubkey mismatch\nwant %x\ngot  %x", p256PubKeyRaw, pk)
	}
}

func TestSignRoundTripThroughFakeKMS(t *testing.T) {
	// The digest that produced p256SigDERBase64 is [0x00, 0x01, ..., 0x1f].
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	var seenSHA256B64 string

	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":asymmetricSign") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("wrong method %s", r.Method)
		}
		// P-256 keys in Cloud KMS want digest.sha256, not the raw
		// `data` field Ed25519 used.
		var body struct {
			Digest struct {
				SHA256 string `json:"sha256"`
			} `json:"digest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		seenSHA256B64 = body.Digest.SHA256
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"signature": p256SigDERBase64,
		})
	})

	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := d.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig != p256SigRawRS {
		t.Errorf("sig mismatch\nwant %x\ngot  %x", p256SigRawRS, sig)
	}
	wantB64 := base64.StdEncoding.EncodeToString(digest[:])
	if seenSHA256B64 != wantB64 {
		t.Errorf("KMS didn't see the right digest.sha256: got %q want %q", seenSHA256B64, wantB64)
	}
}

func TestMissingAccessTokenErrors(t *testing.T) {
	// Deliberately DO NOT set JANOS_GCP_ACCESS_TOKEN via setupFakeKMS.
	prevEndpoint := endpoint
	endpoint = "http://not-called.invalid"
	t.Cleanup(func() { endpoint = prevEndpoint })
	prevToken := os.Getenv(EnvAccessToken)
	os.Unsetenv(EnvAccessToken)
	t.Cleanup(func() {
		if prevToken != "" {
			os.Setenv(EnvAccessToken, prevToken)
		}
	})

	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.PublicKey()
	if err == nil {
		t.Fatal("PublicKey with no token did not error")
	}
	if !strings.Contains(err.Error(), EnvAccessToken) {
		t.Errorf("error should name the env var %s: %v", EnvAccessToken, err)
	}
}

func TestKMSErrorSurfacedVerbatim(t *testing.T) {
	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": {"code": 403, "message": "insufficient permissions"}}`))
	})
	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.PublicKey()
	if err == nil {
		t.Fatal("PublicKey with 403 didn't error")
	}
	if !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "insufficient permissions") {
		t.Errorf("error should include HTTP status and KMS message: %v", err)
	}
}

// TestRegistrationOnInit: importing the package must have registered
// the gcpkms scheme with diviner.Open.
func TestRegistrationOnInit(t *testing.T) {
	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {})
	_, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
}

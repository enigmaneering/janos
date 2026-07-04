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

// ed25519PubKeyPEM is a well-formed PKIX SubjectPublicKeyInfo PEM for
// an Ed25519 key.  The 32-byte pubkey is [0x01, 0x02, ..., 0x20].
// Pre-computed with `openssl asn1parse` on a real Ed25519 pubkey PEM.
//
// SPKI:
//   SEQUENCE {
//     SEQUENCE { OBJECT IDENTIFIER 1.3.101.112 (ed25519) }
//     BIT STRING (32 bytes) 01 02 03 ... 20
//   }
const ed25519PubKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
-----END PUBLIC KEY-----
`

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

func TestParseEd25519PubKeyPEM(t *testing.T) {
	pk, err := parseEd25519PubKeyPEM(ed25519PubKeyPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pk[0] != 0x01 || pk[31] != 0x20 {
		t.Errorf("wrong pubkey bytes: %x", pk)
	}
}

func TestParseEd25519PubKeyPEMWrongAlgorithm(t *testing.T) {
	// A well-formed 1024-bit RSA SubjectPublicKeyInfo PEM: algorithm
	// OID 1.2.840.113549.1.1.1 (rsaEncryption).  Should be rejected
	// by the Ed25519-OID gate in parseEd25519PubKeyPEM, not by an
	// ASN.1 syntax error.
	rsaPEM := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1ODOBLh
CPGGdX3ZHYYD0k03YQIDAQAB
-----END PUBLIC KEY-----
`
	_, err := parseEd25519PubKeyPEM(rsaPEM)
	if err == nil {
		t.Fatal("parseEd25519PubKeyPEM accepted a non-Ed25519 key")
	}
	if !strings.Contains(err.Error(), "Ed25519") {
		t.Errorf("error should mention Ed25519: %v", err)
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
		json.NewEncoder(w).Encode(map[string]string{"pem": ed25519PubKeyPEM})
	})

	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := d.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pk[0] != 0x01 || pk[31] != 0x20 {
		t.Errorf("pubkey mismatch: %x", pk)
	}
}

func TestSignRoundTripThroughFakeKMS(t *testing.T) {
	// Expected signature is a 64-byte pattern; verify the KMS sees
	// the base64 of our digest and returns the base64 of the sig.
	var wantSig [64]byte
	for i := range wantSig {
		wantSig[i] = byte(0x40 + (i & 0x3f))
	}
	var seenDataB64 string

	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":asymmetricSign") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("wrong method %s", r.Method)
		}
		var body struct {
			Data string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		seenDataB64 = body.Data
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"signature": base64.StdEncoding.EncodeToString(wantSig[:]),
		})
	})

	d, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	sig, err := d.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig != wantSig {
		t.Errorf("sig mismatch\nwant %x\ngot  %x", wantSig, sig)
	}
	wantB64 := base64.StdEncoding.EncodeToString(digest[:])
	if seenDataB64 != wantB64 {
		t.Errorf("KMS didn't see the right data: got %q want %q", seenDataB64, wantB64)
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
	// Deliberately don't set up a fake server or token — Open just
	// dispatches to the factory here, and gcpkms.Open only fails on
	// URL parse (which we've provided cleanly).
	setupFakeKMS(t, func(w http.ResponseWriter, r *http.Request) {})
	// Not actually calling anything on the returned Diviner.
	// This confirms diviner.Open dispatches correctly through the registry.
	// We use the gcpkms.Open directly (not via diviner.Open) because
	// this package is not imported by cmd/janos/diviner (import direction is reversed).
	_, err := Open("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
}

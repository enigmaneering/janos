// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gcpkms implements a diviner backed by Google Cloud KMS.
//
// URL format:
//
//	gcpkms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/N
//
// The path portion after the scheme is the KMS resource name Google
// Cloud APIs expect verbatim.  Authentication is delegated to the
// operator's environment via the JANOS_GCP_ACCESS_TOKEN environment
// variable, which the user populates before invoking `go build`:
//
//	export JANOS_GCP_ACCESS_TOKEN=$(gcloud auth application-default print-access-token)
//
// This avoids linking any Google Cloud Go SDK into cmd/link and keeps
// the auth boundary in the operator's shell, not inside the toolchain.
//
// The backend uses only stdlib: net/http, encoding/json,
// encoding/base64, encoding/pem, encoding/asn1, plus crypto-free
// helpers.  It never touches private key material — the KMS holds
// the key, we pass the digest, KMS returns the signature.
package gcpkms

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cmd/janos/diviner"
)

// EnvAccessToken names the environment variable the backend reads
// its OAuth bearer token from.  Absence at Sign/PublicKey time
// results in a KMS error surfaced to cmd/link, which turns it into
// a hard link failure.
const EnvAccessToken = "JANOS_GCP_ACCESS_TOKEN"

// endpoint is Google Cloud KMS's public REST endpoint.  Exposed as
// a var (not const) so tests can point it at an in-process fake.
var endpoint = "https://cloudkms.googleapis.com"

// httpClient is used for KMS requests.  Exposed as a var so tests
// can substitute a client whose transport is a mock.
var httpClient = &http.Client{Timeout: 30 * time.Second}

type gcpDiviner struct {
	// resource is the KMS resource path — everything after "gcpkms://".
	// Format: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N
	resource string
}

func (d *gcpDiviner) PublicKey() ([32]byte, error) {
	// GET /v1/{resource}/publicKey -> {"pem": "-----BEGIN PUBLIC KEY-----\n..."}
	url := fmt.Sprintf("%s/v1/%s/publicKey", endpoint, d.resource)
	body, err := d.do("GET", url, nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("gcpkms PublicKey: %w", err)
	}
	var resp struct {
		PEM string `json:"pem"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return [32]byte{}, fmt.Errorf("gcpkms PublicKey: decode: %w", err)
	}
	return parseEd25519PubKeyPEM(resp.PEM)
}

func (d *gcpDiviner) Sign(digest [32]byte) ([64]byte, error) {
	// POST /v1/{resource}:asymmetricSign
	// Body: {"data": base64(digest)}
	// Ed25519 keys in KMS take the raw message via the `data` field
	// (RSA/ECDSA keys use `digest.sha256` etc; Ed25519 is different).
	url := fmt.Sprintf("%s/v1/%s:asymmetricSign", endpoint, d.resource)
	req := map[string]any{
		"data": base64.StdEncoding.EncodeToString(digest[:]),
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return [64]byte{}, err
	}
	body, err := d.do("POST", url, reqBody)
	if err != nil {
		return [64]byte{}, fmt.Errorf("gcpkms Sign: %w", err)
	}
	var resp struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return [64]byte{}, fmt.Errorf("gcpkms Sign: decode: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return [64]byte{}, fmt.Errorf("gcpkms Sign: signature not valid base64: %w", err)
	}
	if len(sigBytes) != 64 {
		return [64]byte{}, fmt.Errorf("gcpkms Sign: signature is %d bytes, want 64", len(sigBytes))
	}
	var out [64]byte
	copy(out[:], sigBytes)
	return out, nil
}

// do makes an authenticated HTTP request against Cloud KMS.  method
// is GET or POST; body is nil for GET.  Returns the response body
// or an error explaining the KMS response status and message.
func (d *gcpDiviner) do(method, url string, body []byte) ([]byte, error) {
	token := os.Getenv(EnvAccessToken)
	if token == "" {
		return nil, fmt.Errorf("%s not set — populate with `gcloud auth application-default print-access-token`", EnvAccessToken)
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("KMS %s %s: HTTP %d: %s", method, url, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// parseEd25519PubKeyPEM extracts the raw 32-byte Ed25519 public key
// from a PKIX SubjectPublicKeyInfo PEM blob.  Cloud KMS returns
// public keys in this exact format for Ed25519 keys.
func parseEd25519PubKeyPEM(pemText string) ([32]byte, error) {
	var out [32]byte
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return out, fmt.Errorf("gcpkms: pubkey PEM decode failed")
	}
	// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
	var spki struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return out, fmt.Errorf("gcpkms: pubkey ASN.1 decode: %w", err)
	}
	// Ed25519 OID is 1.3.101.112.
	ed25519OID := asn1.ObjectIdentifier{1, 3, 101, 112}
	if !spki.Algorithm.Algorithm.Equal(ed25519OID) {
		return out, fmt.Errorf("gcpkms: pubkey algorithm is %v, want Ed25519 (1.3.101.112)", spki.Algorithm.Algorithm)
	}
	raw := spki.SubjectPublicKey.Bytes
	if len(raw) != 32 {
		return out, fmt.Errorf("gcpkms: Ed25519 pubkey is %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// Open parses a gcpkms:// URL and returns a Diviner that will talk
// to the Cloud KMS resource it names.  URL validation is minimal at
// this point — the actual PublicKey / Sign call surfaces any resource
// mismatch as a KMS error.
func Open(url string) (diviner.Diviner, error) {
	const prefix = "gcpkms://"
	if !strings.HasPrefix(url, prefix) {
		return nil, fmt.Errorf("gcpkms: URL %q does not start with %q", url, prefix)
	}
	resource := url[len(prefix):]
	if resource == "" {
		return nil, fmt.Errorf("gcpkms: URL missing resource path")
	}
	// Basic shape check: KMS resources are project/location/keyring/key/version.
	// We don't parse each field; KMS itself is the authority on resource format,
	// and we surface KMS's error verbatim.  But an obvious missing prefix is
	// worth catching early.
	if !strings.HasPrefix(resource, "projects/") {
		return nil, fmt.Errorf("gcpkms: resource path %q must start with projects/", resource)
	}
	return &gcpDiviner{resource: resource}, nil
}

func init() {
	diviner.Register("gcpkms", Open)
}

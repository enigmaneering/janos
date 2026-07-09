// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && cgo

package secureenclave

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// sep_err renders a CFErrorRef as a malloc'd UTF-8 C string (caller
// frees) or NULL.
static char* sep_err(CFErrorRef e) {
	if (e == NULL) return NULL;
	CFStringRef desc = CFErrorCopyDescription(e);
	if (desc == NULL) return strdup("secure enclave: unknown error");
	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(desc), kCFStringEncodingUTF8) + 1;
	char* buf = (char*)malloc(max);
	if (buf != NULL) {
		if (!CFStringGetCString(desc, buf, max, kCFStringEncodingUTF8)) {
			buf[0] = '\0';
		}
	}
	CFRelease(desc);
	return buf;
}

// sep_generate creates an ephemeral Secure Enclave P-256 private key.
// Returns the SecKeyRef (as void*) or NULL with *errOut set.
static void* sep_generate(char** errOut) {
	*errOut = NULL;
	CFErrorRef cfErr = NULL;

	SecAccessControlRef access = SecAccessControlCreateWithFlags(
		kCFAllocatorDefault,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		kSecAccessControlPrivateKeyUsage,
		&cfErr);
	if (access == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return NULL; }

	const void* privKeys[] = { kSecAttrIsPermanent, kSecAttrAccessControl };
	const void* privVals[] = { kCFBooleanFalse, access };
	CFDictionaryRef privAttrs = CFDictionaryCreate(kCFAllocatorDefault, privKeys, privVals, 2,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	int bits = 256;
	CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

	const void* keys[] = { kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecPrivateKeyAttrs };
	const void* vals[] = { kSecAttrKeyTypeECSECPrimeRandom, bitsNum, kSecAttrTokenIDSecureEnclave, privAttrs };
	CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	SecKeyRef key = SecKeyCreateRandomKey(attrs, &cfErr);

	CFRelease(attrs);
	CFRelease(bitsNum);
	CFRelease(privAttrs);
	CFRelease(access);

	if (key == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return NULL; }
	return (void*)key;
}

// sep_public_point writes the 64-byte uncompressed X||Y public point
// into out64.  Returns 0 on success.
static int sep_public_point(void* key, uint8_t* out64, char** errOut) {
	*errOut = NULL;
	SecKeyRef pub = SecKeyCopyPublicKey((SecKeyRef)key);
	if (pub == NULL) { *errOut = strdup("secure enclave: no public key"); return -1; }
	CFErrorRef cfErr = NULL;
	CFDataRef data = SecKeyCopyExternalRepresentation(pub, &cfErr);
	CFRelease(pub);
	if (data == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return -1; }
	CFIndex n = CFDataGetLength(data);
	// X9.63 uncompressed: 0x04 || X(32) || Y(32) == 65 for P-256.
	if (n != 65) { CFRelease(data); *errOut = strdup("secure enclave: unexpected public key length"); return -1; }
	memcpy(out64, CFDataGetBytePtr(data) + 1, 64);
	CFRelease(data);
	return 0;
}

// sep_sign signs a 32-byte SHA-256 digest, writing the X9.62 DER
// ECDSA signature into out (capacity *outLen), updating *outLen.
static int sep_sign(void* key, const uint8_t* digest, int digestLen, uint8_t* out, int* outLen, char** errOut) {
	*errOut = NULL;
	CFDataRef d = CFDataCreate(kCFAllocatorDefault, digest, digestLen);
	CFErrorRef cfErr = NULL;
	CFDataRef sig = SecKeyCreateSignature((SecKeyRef)key,
		kSecKeyAlgorithmECDSASignatureDigestX962SHA256, d, &cfErr);
	CFRelease(d);
	if (sig == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return -1; }
	CFIndex n = CFDataGetLength(sig);
	if (n > (CFIndex)*outLen) { CFRelease(sig); *errOut = strdup("secure enclave: signature buffer too small"); return -1; }
	memcpy(out, CFDataGetBytePtr(sig), n);
	*outLen = (int)n;
	CFRelease(sig);
	return 0;
}

// sep_ecdh performs ECDH between this key and a peer given as a
// 65-byte X9.63 uncompressed public point, writing the shared secret
// (the 32-byte X coordinate) into out (capacity *outLen).
static int sep_ecdh(void* key, const uint8_t* peer65, uint8_t* out, int* outLen, char** errOut) {
	*errOut = NULL;
	CFDataRef peerData = CFDataCreate(kCFAllocatorDefault, peer65, 65);
	const void* pkeys[] = { kSecAttrKeyType, kSecAttrKeyClass };
	const void* pvals[] = { kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic };
	CFDictionaryRef pattrs = CFDictionaryCreate(kCFAllocatorDefault, pkeys, pvals, 2,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFErrorRef cfErr = NULL;
	SecKeyRef peer = SecKeyCreateWithData(peerData, pattrs, &cfErr);
	CFRelease(peerData);
	CFRelease(pattrs);
	if (peer == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return -1; }

	CFDictionaryRef params = CFDictionaryCreate(kCFAllocatorDefault, NULL, NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDataRef shared = SecKeyCopyKeyExchangeResult((SecKeyRef)key,
		kSecKeyAlgorithmECDHKeyExchangeStandard, peer, params, &cfErr);
	CFRelease(peer);
	CFRelease(params);
	if (shared == NULL) { *errOut = sep_err(cfErr); if (cfErr) CFRelease(cfErr); return -1; }
	CFIndex n = CFDataGetLength(shared);
	if (n > (CFIndex)*outLen) { CFRelease(shared); *errOut = strdup("secure enclave: ecdh buffer too small"); return -1; }
	memcpy(out, CFDataGetBytePtr(shared), n);
	*outLen = (int)n;
	CFRelease(shared);
	return 0;
}

static void sep_release(void* key) {
	if (key != NULL) CFRelease((SecKeyRef)key);
}
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// takeErr converts a malloc'd C error string to a Go error and frees
// it.  Returns a generic error if the C side gave no message.
func takeErr(what string, cErr *C.char) error {
	if cErr == nil {
		return errors.New("secureenclave: " + what + " failed")
	}
	msg := C.GoString(cErr)
	C.free(unsafe.Pointer(cErr))
	return errors.New("secureenclave: " + what + ": " + msg)
}

// GenerateKey creates a fresh P-256 key inside the Secure Enclave.
// The private scalar is generated in the enclave and never leaves it.
// The returned Key holds a reference that must be released with Close.
func GenerateKey() (*Key, error) {
	var cErr *C.char
	ref := C.sep_generate(&cErr)
	if ref == nil {
		return nil, takeErr("generate", cErr)
	}
	return &Key{ref: ref}, nil
}

// Available reports whether the Secure Enclave can generate a key on
// this host.  It performs the definitive test — an actual ephemeral
// key generation — and releases the key immediately.
func Available() bool {
	k, err := GenerateKey()
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// PublicPoint returns the key's public point as 64 bytes of
// uncompressed X||Y — the same encoding as runtime.Identity.PublicPoint.
func (k *Key) PublicPoint() ([64]byte, error) {
	var out [64]byte
	if k.ref == nil {
		return out, ErrUnavailable
	}
	var cErr *C.char
	rc := C.sep_public_point(k.ref, (*C.uint8_t)(unsafe.Pointer(&out[0])), &cErr)
	runtime.KeepAlive(k)
	if rc != 0 {
		return out, takeErr("public_point", cErr)
	}
	return out, nil
}

// Sign produces an ECDSA signature over a 32-byte SHA-256 digest,
// computed by the Secure Enclave using the in-enclave private key.
// The signature is X9.62 DER-encoded.
func (k *Key) Sign(digest []byte) ([]byte, error) {
	if k.ref == nil {
		return nil, ErrUnavailable
	}
	if len(digest) != 32 {
		return nil, errors.New("secureenclave: Sign expects a 32-byte SHA-256 digest")
	}
	out := make([]byte, 256)
	outLen := C.int(len(out))
	var cErr *C.char
	rc := C.sep_sign(k.ref,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.int(len(digest)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen, &cErr)
	runtime.KeepAlive(k)
	if rc != 0 {
		return nil, takeErr("sign", cErr)
	}
	return out[:int(outLen)], nil
}

// ECDH computes the ECDH shared secret between this key and a peer's
// public point (64-byte uncompressed X||Y), returning the 32-byte
// shared X coordinate.  The scalar multiplication happens inside the
// enclave.
func (k *Key) ECDH(peerPoint [64]byte) ([]byte, error) {
	if k.ref == nil {
		return nil, ErrUnavailable
	}
	// Prepend the 0x04 uncompressed tag to form the 65-byte X9.63
	// representation the Security framework expects.
	var peer65 [65]byte
	peer65[0] = 0x04
	copy(peer65[1:], peerPoint[:])
	out := make([]byte, 32)
	outLen := C.int(len(out))
	var cErr *C.char
	rc := C.sep_ecdh(k.ref,
		(*C.uint8_t)(unsafe.Pointer(&peer65[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), &outLen, &cErr)
	runtime.KeepAlive(k)
	if rc != 0 {
		return nil, takeErr("ecdh", cErr)
	}
	return out[:int(outLen)], nil
}

// Close releases the Secure Enclave key reference.  Safe to call more
// than once.
func (k *Key) Close() error {
	if k.ref != nil {
		C.sep_release(k.ref)
		k.ref = nil
	}
	return nil
}

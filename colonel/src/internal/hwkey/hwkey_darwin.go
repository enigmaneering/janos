// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && cgo

package hwkey

import "internal/secureenclave"

// Compile-time proof that the Secure Enclave key satisfies the common
// Key interface.
var _ Key = (*secureenclave.Key)(nil)

// Open returns the Secure Enclave provider if the enclave is usable.
func Open() (Provider, error) {
	if !secureenclave.Available() {
		return nil, ErrUnavailable
	}
	return seProvider{}, nil
}

// seProvider adapts the package-level secureenclave API to Provider.
type seProvider struct{}

func (seProvider) GenerateKey() (Key, error) {
	k, err := secureenclave.GenerateKey()
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Close is a no-op: the Secure Enclave has no per-process session to
// release.
func (seProvider) Close() error { return nil }

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || windows

package hwkey

import "internal/tpm2"

// Compile-time proof that the TPM key satisfies the common Key
// interface.
var _ Key = (*tpm2.Key)(nil)

// Open returns the TPM provider if a TPM is present and reachable.
func Open() (Provider, error) {
	dev, err := tpm2.Open()
	if err != nil {
		return nil, ErrUnavailable
	}
	return &tpmProvider{dev: dev}, nil
}

// tpmProvider adapts a *tpm2.Device to Provider.
type tpmProvider struct {
	dev *tpm2.Device
}

func (p *tpmProvider) GenerateKey() (Key, error) {
	k, err := p.dev.GenerateKey()
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (p *tpmProvider) Close() error { return p.dev.Close() }

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows

package tpm2

// Platforms without a TPM transport yet (darwin uses the Secure
// Enclave, not a TPM; tamago board support lands later; the BSDs and
// others are unimplemented) report no device so callers degrade
// cleanly and the package still builds everywhere.
func openTransport() (transport, error) {
	return nil, ErrNoDevice
}

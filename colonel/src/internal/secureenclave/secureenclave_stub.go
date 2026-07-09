// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin || !cgo

package secureenclave

// The Secure Enclave is a macOS facility reached through
// Security.framework, which requires cgo.  On every other platform —
// and on darwin with cgo disabled — the package reports unavailable
// so callers degrade cleanly and the package still builds everywhere.

// Available reports whether the Secure Enclave is usable.  Always
// false on this build.
func Available() bool { return false }

// GenerateKey always fails with ErrUnavailable on this build.
func GenerateKey() (*Key, error) { return nil, ErrUnavailable }

// PublicPoint always fails with ErrUnavailable on this build.
func (k *Key) PublicPoint() ([64]byte, error) { return [64]byte{}, ErrUnavailable }

// Sign always fails with ErrUnavailable on this build.
func (k *Key) Sign(digest []byte) ([]byte, error) { return nil, ErrUnavailable }

// ECDH always fails with ErrUnavailable on this build.
func (k *Key) ECDH(peerPoint [64]byte) ([]byte, error) { return nil, ErrUnavailable }

// Close is a no-op on this build.
func (k *Key) Close() error { return nil }

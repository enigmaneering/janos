// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(darwin && cgo) && !linux && !windows

package hwkey

// Platforms with no hardware-key provider yet — darwin with cgo
// disabled, the tamago bare-metal target (board support lands later),
// and the rest — report unavailable so callers degrade cleanly and
// the package builds everywhere.
func Open() (Provider, error) {
	return nil, ErrUnavailable
}

// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test-only exports for JanOS additions.  Lives in package sync so
// the external test package can observe unexported state — the same
// pattern as export_test.go.  An internal test file cannot be used
// for time-based tests because package time imports sync.

package sync

// IdempotentEntryCountForTest reports how many identity slots i
// currently holds.  Used by the eviction test to observe the
// block-finalized hook actually draining entries — fire-count
// assertions alone cannot distinguish "evicted" from "leaked but
// not yet colliding".
func IdempotentEntryCountForTest(i *Idempotent) int {
	i.mu.Lock()
	n := len(i.entries)
	i.mu.Unlock()
	return n
}

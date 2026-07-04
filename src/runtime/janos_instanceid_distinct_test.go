// Copyright The Enigmaneering Guild. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"internal/testenv"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestInstanceIDDistinctAcrossRuns spawns three subprocess copies of
// this same test binary and confirms all three report DIFFERENT
// InstanceID values.  Would have caught the boot-random ordering bug
// where janosInitInstanceID ran before mcommoninit had seeded
// mp.chacha8, producing an identical (nonzero) InstanceID on every
// launch of the same binary.
//
// The subprocess trick uses os.Executable() + the test binary's own
// -test.run flag to re-invoke a small "print my InstanceID" helper
// test in the child.  This avoids needing a separate helper binary.
func TestInstanceIDDistinctAcrossRuns(t *testing.T) {
	if os.Getenv("JANOS_INSTANCE_ID_CHILD") == "1" {
		// Child mode: print InstanceID and exit.  Nothing else this
		// test binary is going to do can be observed by the parent.
		p := runtime.CurrentInstanceIDHexForTest()
		os.Stdout.WriteString(p + "\n")
		os.Exit(0)
	}

	testenv.MustHaveExec(t)

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	seen := map[string]bool{}
	const N = 3
	for i := 0; i < N; i++ {
		cmd := exec.Command(exe, "-test.run=TestInstanceIDDistinctAcrossRuns")
		cmd.Env = append(os.Environ(), "JANOS_INSTANCE_ID_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run %d: %v\noutput: %s", i, err, out)
		}
		id := strings.TrimSpace(string(out))
		if id == "" || id == strings.Repeat("0", 32) {
			t.Fatalf("run %d: got empty or zero InstanceID: %q", i, id)
		}
		if seen[id] {
			t.Errorf("run %d: InstanceID %q was seen in an earlier launch — schedinit random source may be uninitialized when janosInitInstanceID runs (bug fixed in commit 93d88ead8c; re-check that mcommoninit still precedes the janos init calls)", i, id)
		}
		seen[id] = true
	}
}

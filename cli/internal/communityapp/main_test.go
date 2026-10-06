// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"os"
	"testing"
)

// TestMain keeps every test off the real default knowledge store: check and
// scan read it when no knowledge source is named, so the process runs with an
// empty HOME and XDG_DATA_HOME.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "prufyx-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := os.MkdirTemp("", "prufyx-test-data-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("HOME", home)
	os.Setenv("XDG_DATA_HOME", data)
	code := m.Run()
	os.RemoveAll(home)
	os.RemoveAll(data)
	os.Exit(code)
}

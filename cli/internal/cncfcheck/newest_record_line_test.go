// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"testing"
)

// A snapshot that cannot say which lines it names is an error, never "no
// newer line".
func TestNewestRecordLineFailsClosed(t *testing.T) {
	loaded, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	const component = "pkg:github/x/app"
	record := func(line string) json.RawMessage {
		return json.RawMessage(`[{"component":"` + component + `","line":"` + line + `"}]`)
	}
	with := func(served, reviews json.RawMessage) *ScanKnowledge {
		k := *loaded
		k.b.pack.ServedAPIs, k.b.pack.LineAttestations = served, reviews
		return &k
	}
	// Control: the newest of both sections.
	if line, err := with(record("1.9"), record("1.10")).NewestRecordLine(component); err != nil || line != "1.10" {
		t.Fatalf("control: %q %v", line, err)
	}
	bad := map[string]json.RawMessage{
		"undecodable":  json.RawMessage(`{}`),
		"invalid line": record("newest"),
		"no line":      json.RawMessage(`[{"component":"` + component + `"}]`),
	}
	for name, section := range bad {
		for place, k := range map[string]*ScanKnowledge{
			"served lists": with(section, record("1.2")),
			"line reviews": with(record("1.2"), section),
		} {
			if line, err := k.NewestRecordLine(component); !errors.Is(err, ErrIntegrity) || line != "" {
				t.Fatalf("%s in %s: %q %v", name, place, line, err)
			}
		}
	}
	// A store that did not open the component's project cannot answer.
	unopened := *loaded
	unopened.selected = map[string]bundle{}
	if line, err := unopened.NewestRecordLine(component); !errors.Is(err, ErrIntegrity) || line != "" {
		t.Fatalf("unopened component: %q %v", line, err)
	}
}

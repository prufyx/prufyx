// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateQuickstart = flag.Bool("update-quickstart", false, "rewrite the human check transcripts in docs/quickstart.md")

// TestQuickstartTranscriptsMatchTheCommands runs every human `check cncf`
// command in docs/quickstart.md, with the input files the document creates,
// and compares its standard output with the transcript printed under it.
func TestQuickstartTranscriptsMatchTheCommands(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "quickstart.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	dir := t.TempDir()
	checked := 0
	var pending []string // the last shell command's arguments
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "```") {
			continue
		}
		fence := strings.TrimPrefix(lines[i], "```")
		end := i + 1
		for end < len(lines) && lines[end] != "```" {
			end++
		}
		body := lines[i+1 : end]
		if fence == "sh" {
			pending = writeDocFiles(t, dir, body)
		} else if fence == "" && pending != nil {
			var stdout, stderr bytes.Buffer
			Run(context.Background(), pending, &stdout, &stderr, "test")
			// The document types relative file names; the report prints them as given.
			shown := strings.ReplaceAll(stdout.String(), dir+string(filepath.Separator), "")
			got := strings.Split(strings.TrimRight(shown, "\n"), "\n")
			if *updateQuickstart {
				lines = append(lines[:i+1], append(got, lines[end:]...)...)
				end = i + 1 + len(got)
			} else if strings.Join(got, "\n") != strings.Join(body, "\n") {
				t.Errorf("transcript under line %d of quickstart.md differs.\nwant:\n%s\n\ngot:\n%s", i+1, strings.Join(body, "\n"), strings.Join(got, "\n"))
			}
			checked++
			pending = nil
		}
		i = end
	}
	if checked < 4 {
		t.Fatalf("only %d human check transcripts found in quickstart.md", checked)
	}
	if *updateQuickstart {
		if err := os.WriteFile(docPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// writeDocFiles creates the heredoc files of a shell block (mode 0600, inside
// dir) and returns the arguments of its `prufyx check cncf` command, with
// relative file names made absolute; nil when the block holds no such command.
func writeDocFiles(t *testing.T, dir string, body []string) []string {
	t.Helper()
	var command []string
	for i := 0; i < len(body); i++ {
		line := body[i]
		if rest, ok := strings.CutPrefix(line, "cat > "); ok {
			name, tag, _ := strings.Cut(rest, " <<'")
			tag = strings.TrimSuffix(tag, "'")
			var content []string
			for i++; i < len(body) && body[i] != tag; i++ {
				content = append(content, body[i])
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(content, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if strings.HasPrefix(line, "/tmp/prufyx check cncf ") {
			text := line
			for strings.HasSuffix(text, `\`) && i+1 < len(body) {
				i++
				text = strings.TrimSuffix(text, `\`) + " " + strings.TrimSpace(body[i])
			}
			command = strings.Fields(strings.TrimPrefix(text, "/tmp/prufyx "))
		}
	}
	if command == nil || !contains(command, "human") {
		return nil
	}
	for index, arg := range command {
		if index > 0 && command[index-1] == "--native-resource" {
			command[index] = filepath.Join(dir, arg)
		}
	}
	return command
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

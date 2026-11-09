// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const maxInputBytes = 32 << 20

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ParseInput reads the input file strictly: unknown fields, trailing data and
// a wrong schema are errors.
func ParseInput(r io.Reader) (*Input, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(raw) > maxInputBytes {
		return nil, errors.New("input too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in Input
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("parse input: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse input: trailing data")
	}
	if err := validateInput(&in); err != nil {
		return nil, err
	}
	return &in, nil
}

func validateInput(in *Input) error {
	if in.Schema != InputSchema {
		return fmt.Errorf("input schema %q is not %q", in.Schema, InputSchema)
	}
	seen := map[int]bool{}
	for _, pr := range in.PRs {
		if pr.Number <= 0 {
			return fmt.Errorf("input PR number %d is not positive", pr.Number)
		}
		if seen[pr.Number] {
			return fmt.Errorf("input lists PR %d twice", pr.Number)
		}
		seen[pr.Number] = true
		if !sha40.MatchString(pr.Head) {
			return fmt.Errorf("input PR %d head %q is not a 40-hex sha", pr.Number, pr.Head)
		}
		for _, c := range pr.Comments {
			if _, err := time.Parse(time.RFC3339, c.CreatedAt); err != nil {
				return fmt.Errorf("input PR %d comment time %q: %w", pr.Number, c.CreatedAt, err)
			}
			if _, err := time.Parse(time.RFC3339, c.UpdatedAt); err != nil {
				return fmt.Errorf("input PR %d comment updated time %q: %w", pr.Number, c.UpdatedAt, err)
			}
		}
	}
	return nil
}

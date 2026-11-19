// Package sealed exposes the verified-target type to readers outside package
// knowledge. It is an alias: the type can be named and read (Bytes) but not
// constructed here, because the constructors live in knowledge/internal/seal,
// which only package knowledge can import.
package sealed

import "github.com/prufyx/prufyx/cli/internal/knowledge/internal/seal"

// Target is target content authenticated inside package knowledge.
type Target = seal.Target

// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"regexp"
	"strings"
)

// lib names a flag library the scanner understands.
type lib uint8

const (
	libNone    lib = iota
	libStd         // standard library "flag"
	libPflag       // github.com/spf13/pflag
	libCobra       // github.com/spf13/cobra
	libKingpin     // kingpin v2 (both import paths)
	libUrfave      // urfave/cli v1 and v2
)

// flagLibRoots maps an import path, with an optional /vN suffix, to its
// library. Only these paths are treated as the library itself; sub-packages
// (cobra/doc, urfave/cli/v2/altsrc) are allowed but are not the library.
var flagLibRoots = map[string]lib{
	"flag":                           libStd,
	"github.com/spf13/pflag":         libPflag,
	"github.com/spf13/cobra":         libCobra,
	"gopkg.in/alecthomas/kingpin.v2": libKingpin,
	"github.com/alecthomas/kingpin":  libKingpin,
	"github.com/urfave/cli":          libUrfave,
	"gopkg.in/urfave/cli.v1":         libUrfave,
	"gopkg.in/urfave/cli.v2":         libUrfave,
}

// libDefaultName is the package name a flag library declares, which is the
// name a file uses unless it renames the import.
var libDefaultName = map[lib]string{
	libStd: "flag", libPflag: "pflag", libCobra: "cobra", libKingpin: "kingpin", libUrfave: "cli",
}

var (
	majorSuffixRE = regexp.MustCompile(`^(.*)/v[0-9]+$`)
	majorElemRE   = regexp.MustCompile(`^v[0-9]+$`)
)

// libOf returns the flag library an import path names, or libNone.
func libOf(path string) lib {
	if l, ok := flagLibRoots[path]; ok {
		return l
	}
	if m := majorSuffixRE.FindStringSubmatch(path); m != nil {
		return flagLibRoots[m[1]]
	}
	return libNone
}

// allowedExternal is the reviewed list of non-standard-library, non-module
// import path roots whose presence does not withhold a binary. The rule is
// default-deny: an import that is not standard library, not in the module
// and not on this list withholds every binary that reaches it
// (ReasonIdiomUnsupported), because a library nobody reviewed can register
// flags (klog, glog, component-base) or define them from struct tags (kong,
// go-flags, ff) in ways the source of the module does not show.
//
// An entry is a path root: it matches itself and everything below it.
// Adding an entry is a reviewed change to this file, and therefore to the
// code digest.
//
//   - the five flag libraries above: their registration calls are what the
//     scanner reads;
//   - github.com/spf13/viper: binds values to flags that already exist and
//     registers none;
//   - github.com/pkg/errors, golang.org/x/sync, golang.org/x/sys,
//     golang.org/x/term: no command line surface, no init-time registration.
var allowedExternal = []string{
	"github.com/spf13/pflag",
	"github.com/spf13/cobra",
	"gopkg.in/alecthomas/kingpin.v2",
	"github.com/alecthomas/kingpin",
	"github.com/urfave/cli",
	"gopkg.in/urfave/cli.v1",
	"gopkg.in/urfave/cli.v2",
	"github.com/spf13/viper",
	"github.com/pkg/errors",
	"golang.org/x/sync",
	"golang.org/x/sys",
	"golang.org/x/term",
}

func underRoot(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

// importKind classifies an import path against the module.
type importKind uint8

const (
	impStd importKind = iota
	impModule
	impAllowed
	impDenied
)

func isStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func classifyImport(path, module string) importKind {
	if module != "" && underRoot(path, module) {
		return impModule
	}
	if isStdlib(path) {
		return impStd
	}
	for _, root := range allowedExternal {
		if underRoot(path, root) {
			return impAllowed
		}
	}
	return impDenied
}

// defaultImportName is the name a file uses for an import it does not
// rename, for packages whose declared name is not read from source: the last
// path element without a major-version suffix.
func defaultImportName(path string) string {
	if l := libOf(path); l != libNone {
		return libDefaultName[l]
	}
	elems := strings.Split(path, "/")
	n := elems[len(elems)-1]
	if len(elems) > 1 && majorElemRE.MatchString(n) {
		n = elems[len(elems)-2]
	}
	return n
}

// SPDX-License-Identifier: AGPL-3.0-only

// Package k8sversion normalises Kubernetes distribution version strings
// (for example v1.29.3-eks-adc7111 or v1.29.4+k3s1) to the upstream
// Kubernetes version plus a distribution identity.
//
// The vocabulary of accepted formats is closed and compiled in. Any string
// that does not match exactly one format is rejected with a typed error;
// the package never guesses.
//
// Planned wiring (not done here): the scan intake that reads the cluster
// version (cli/internal/projectcheck and the Kubernetes component-config
// route) calls Parse with the user's declared distribution and records both
// Version.Raw and Version.Upstream in the report.
package k8sversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Distribution is a closed identifier of a Kubernetes distribution.
type Distribution string

const (
	OfficialUpstream Distribution = "official_upstream"
	Kubeadm          Distribution = "kubeadm"
	EKS              Distribution = "eks"
	GKE              Distribution = "gke"
	AKS              Distribution = "aks"
	K3s              Distribution = "k3s"
	RKE2             Distribution = "rke2"
	Talos            Distribution = "talos"
	OpenShift        Distribution = "openshift"
)

var known = map[Distribution]bool{
	OfficialUpstream: true, Kubeadm: true, EKS: true, GKE: true, AKS: true,
	K3s: true, RKE2: true, Talos: true, OpenShift: true,
}

// Known reports whether id is one of the closed distribution identifiers
// (case-sensitive).
func Known(id string) bool { return known[Distribution(id)] }

// OpenShiftMap maps an OpenShift 4.x minor to the upstream Kubernetes 1.x
// minor it is based on, for example 16 -> 29 for "OpenShift 4.16 is based on
// Kubernetes 1.29". ParseWith reads it; Parse never does.
type OpenShiftMap map[int]int

// Confidence says how the distribution and upstream version were derived.
type Confidence string

const (
	// ConfidenceExact: the string itself carries a distribution marker (or is a
	// bare upstream version with no declaration) and the upstream version.
	ConfidenceExact Confidence = "exact"
	// ConfidenceDeclared: the format is a bare upstream version and the
	// distribution comes from the user's declaration.
	ConfidenceDeclared Confidence = "declared"
	// ConfidenceMapped: the upstream minor comes from a mapping table; the
	// patch version is not known.
	ConfidenceMapped Confidence = "mapped"
)

// Stage is the pre-release stage of an upstream version, empty for a release.
type Stage string

const (
	StageAlpha Stage = "alpha"
	StageBeta  Stage = "beta"
	StageRC    Stage = "rc"
)

// rank orders the stages as SemVer 2.0 does: identifiers compare in ASCII
// order, and alpha < beta < rc.
func (s Stage) rank() int {
	switch s {
	case StageAlpha:
		return 1
	case StageBeta:
		return 2
	case StageRC:
		return 3
	}
	return 0
}

// Semver is an upstream Kubernetes version. PatchKnown is false when only the
// minor is known (OpenShift mapping). Pre is set for a pre-release
// X.Y.0-(alpha|beta|rc).N, with N in PreN.
type Semver struct {
	Major, Minor, Patch int
	PatchKnown          bool
	Pre                 Stage
	PreN                int
}

// PreRelease reports whether the version is a pre-release.
func (s Semver) PreRelease() bool { return s.Pre != "" }

// Line is the minor release line "X.Y". A pre-release belongs to its own line.
func (s Semver) Line() string { return fmt.Sprintf("%d.%d", s.Major, s.Minor) }

func (s Semver) String() string {
	if !s.PatchKnown {
		return fmt.Sprintf("%d.%d", s.Major, s.Minor)
	}
	if s.Pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s.%d", s.Major, s.Minor, s.Patch, s.Pre, s.PreN)
	}
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
}

// Compare orders two versions as SemVer 2.0 does and returns -1, 0 or 1:
// 1.38.0-alpha.1 < 1.38.0-alpha.2 < 1.38.0-beta.0 < 1.38.0-rc.0 < 1.38.0 <
// 1.38.1. An unknown patch compares as 0.
func Compare(a, b Semver) int {
	for _, d := range [...][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	// A release is above every pre-release of the same X.Y.Z.
	ra, rb := a.Pre.rank(), b.Pre.rank()
	switch {
	case ra == rb && ra == 0:
		return 0
	case ra == 0:
		return 1
	case rb == 0:
		return -1
	case ra != rb:
		if ra < rb {
			return -1
		}
		return 1
	case a.PreN < b.PreN:
		return -1
	case a.PreN > b.PreN:
		return 1
	}
	return 0
}

// ParsePreRelease reads a bare upstream pre-release X.Y.0-(alpha|beta|rc).N:
// no "v" prefix, no distribution marker, no build metadata, N without a
// leading zero. ok is false for anything else, a release included.
func ParsePreRelease(s string) (Semver, bool) {
	core, pre, found := strings.Cut(s, "-")
	if !found {
		return Semver{}, false
	}
	v, err := parseTriple(core, false, "")
	if err != nil {
		return Semver{}, false
	}
	return withPre(v, pre)
}

// withPre attaches the pre-release part "stage.N" to a parsed X.Y.Z. The
// patch must be 0: Kubernetes publishes pre-releases of X.Y.0 only.
func withPre(v Semver, pre string) (Semver, bool) {
	stage, num, found := strings.Cut(pre, ".")
	if !found || v.Patch != 0 {
		return Semver{}, false
	}
	st := Stage(stage)
	if st.rank() == 0 {
		return Semver{}, false
	}
	n, ok := atoi(num)
	if !ok {
		return Semver{}, false
	}
	v.Pre, v.PreN = st, n
	return v, true
}

// Version is the result of a successful Parse.
type Version struct {
	Distribution Distribution
	Raw          string
	Upstream     Semver
	Confidence   Confidence
}

// Typed errors; use errors.Is.
var (
	ErrMalformed            = errors.New("version string is not in an accepted format")
	ErrUnknownDistribution  = errors.New("distribution is not recognised")
	ErrDistributionMismatch = errors.New("version format does not match the declared distribution")
	ErrDeclarationRequired  = errors.New("this version format needs a declared distribution")
	ErrUnknownOpenShift     = errors.New("openshift minor is not in the mapping table")
)

const (
	maxRawLen = 128
	maxNumber = 999999 // per numeric component; bounds all integers
)

// openshiftToKubernetes maps an OpenShift minor (4.N) to the upstream
// Kubernetes (major, minor). It is deliberately empty until entries are
// verified against official OpenShift release notes; see the impl notes.
var openshiftToKubernetes = map[int][2]int{}

// Parse normalises raw. declared may be empty or a known distribution id.
// OpenShift versions are looked up in the compiled-in mapping only.
func Parse(raw, declared string) (Version, error) {
	return parse(raw, declared, nil)
}

// ParseWith is Parse with an injected OpenShift mapping table, for example
// one built from current distribution records. With a nil table it behaves
// exactly as Parse. With a table, an OpenShift version is looked up in that
// table only; a minor the table does not hold is ErrUnknownOpenShift. The
// result carries the Kubernetes minor only (Semver.PatchKnown is false): no
// patch is invented. Every other format is parsed exactly as Parse does.
func ParseWith(raw, declared string, table OpenShiftMap) (Version, error) {
	return parse(raw, declared, table)
}

func parse(raw, declared string, table OpenShiftMap) (Version, error) {
	d := Distribution(declared)
	if declared != "" && !known[d] {
		return Version{}, fmt.Errorf("%w: %q", ErrUnknownDistribution, declared)
	}
	if raw == "" || len(raw) > maxRawLen {
		return Version{}, fmt.Errorf("%w", ErrMalformed)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return Version{}, fmt.Errorf("%w", ErrMalformed)
		}
	}
	if d == OpenShift {
		return parseOpenShift(raw, table)
	}

	core, marker, suffix, err := split(raw)
	if err != nil {
		return Version{}, err
	}
	up, err := parseTriple(core.num, core.v, core.sep)
	if err != nil {
		return Version{}, err
	}
	_ = suffix
	if core.pre != "" {
		// Only the upstream forms carry a pre-release: a distribution
		// marker or a declaration of another distribution stays refused.
		if marker != "" || (d != "" && d != OfficialUpstream) {
			return Version{}, fmt.Errorf("%w", ErrMalformed)
		}
		pv, ok := withPre(up, core.pre)
		if !ok {
			return Version{}, fmt.Errorf("%w", ErrMalformed)
		}
		up = pv
	}
	out := Version{Raw: raw, Upstream: up}
	switch marker {
	case "":
		switch d {
		case "":
			out.Distribution, out.Confidence = OfficialUpstream, ConfidenceExact
		case OfficialUpstream, Kubeadm, AKS, Talos:
			out.Distribution, out.Confidence = d, ConfidenceDeclared
		default:
			return Version{}, fmt.Errorf("%w: bare version with declared %s", ErrDistributionMismatch, d)
		}
	default:
		md := Distribution(marker)
		if d != "" && d != md {
			return Version{}, fmt.Errorf("%w: %s format with declared %s", ErrDistributionMismatch, md, d)
		}
		out.Distribution, out.Confidence = md, ConfidenceExact
	}
	return out, nil
}

type core struct {
	num string
	v   bool // leading "v"
	sep string
	pre string // pre-release part "stage.N", checked by the caller
}

// split recognises the closed format vocabulary and returns the numeric core,
// the distribution marker ("" for a bare version) and validates the suffix.
func split(raw string) (c core, marker, suffix string, err error) {
	bad := fmt.Errorf("%w", ErrMalformed)
	s := raw
	hasV := strings.HasPrefix(s, "v")
	s = strings.TrimPrefix(s, "v")
	switch {
	case strings.Contains(s, "-eks-"):
		i := strings.Index(s, "-eks-")
		h := s[i+5:]
		if !hasV || len(h) != 7 || !isLowerHex(h) {
			return c, "", "", bad
		}
		return core{num: s[:i], v: hasV}, string(EKS), h, nil
	case strings.Contains(s, "-gke."):
		i := strings.Index(s, "-gke.")
		if !isPatchNumber(s[i+5:]) {
			return c, "", "", bad
		}
		return core{num: s[:i], v: hasV}, string(GKE), s[i+5:], nil
	case strings.Contains(s, "+k3s"):
		i := strings.Index(s, "+k3s")
		if !hasV || !isPatchNumber(s[i+4:]) {
			return c, "", "", bad
		}
		return core{num: s[:i], v: hasV}, string(K3s), s[i+4:], nil
	case strings.Contains(s, "+rke2r"):
		i := strings.Index(s, "+rke2r")
		if !hasV || !isPatchNumber(s[i+6:]) {
			return c, "", "", bad
		}
		return core{num: s[:i], v: hasV}, string(RKE2), s[i+6:], nil
	}
	if strings.ContainsAny(s, "+_/ ") || strings.Count(s, "-") > 1 {
		return c, "", "", bad
	}
	if num, pre, found := strings.Cut(s, "-"); found {
		if pre == "" {
			return c, "", "", bad
		}
		return core{num, hasV, "", pre}, "", "", nil
	}
	return core{s, hasV, "", ""}, "", "", nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

// isPatchNumber: positive decimal, no leading zero, bounded.
func isPatchNumber(s string) bool {
	n, ok := atoiN(s, 9)
	return ok && n >= 1
}

// atoi parses a canonical non-negative decimal (no sign, no leading zeros,
// at most 6 digits).
func atoi(s string) (int, bool) {
	n, ok := atoiN(s, 6)
	return n, ok && n <= maxNumber
}

// atoiN is atoi with an explicit digit limit (build numbers are longer).
func atoiN(s string, digits int) (int, bool) {
	if s == "" || len(s) > digits || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func parseTriple(s string, _ bool, _ string) (Semver, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("%w", ErrMalformed)
	}
	var n [3]int
	for i, p := range parts {
		v, ok := atoi(p)
		if !ok {
			return Semver{}, fmt.Errorf("%w", ErrMalformed)
		}
		n[i] = v
	}
	if n[0] != 1 {
		return Semver{}, fmt.Errorf("%w: upstream major must be 1", ErrMalformed)
	}
	return Semver{Major: n[0], Minor: n[1], Patch: n[2], PatchKnown: true}, nil
}

func parseOpenShift(raw string, table OpenShiftMap) (Version, error) {
	s := strings.TrimPrefix(raw, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return Version{}, fmt.Errorf("%w", ErrMalformed)
	}
	maj, ok1 := atoi(parts[0])
	min, ok2 := atoi(parts[1])
	if !ok1 || !ok2 || maj != 4 {
		return Version{}, fmt.Errorf("%w", ErrMalformed)
	}
	if len(parts) == 3 {
		if _, ok := atoi(parts[2]); !ok {
			return Version{}, fmt.Errorf("%w", ErrMalformed)
		}
	}
	k, found := openshiftToKubernetes[min]
	// An injected table, even an empty one, replaces the compiled map
	// entirely: there is never a fallback to it.
	if table != nil {
		minor, ok := table[min]
		k, found = [2]int{1, minor}, ok && minor >= 0 && minor <= maxNumber
	}
	if !found {
		return Version{}, fmt.Errorf("%w: 4.%d", ErrUnknownOpenShift, min)
	}
	return Version{
		Distribution: OpenShift, Raw: raw,
		Upstream:   Semver{Major: k[0], Minor: k[1]},
		Confidence: ConfidenceMapped,
	}, nil
}

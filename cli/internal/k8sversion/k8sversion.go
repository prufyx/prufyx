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

// Semver is an upstream Kubernetes version. PatchKnown is false when only the
// minor is known (OpenShift mapping).
type Semver struct {
	Major, Minor, Patch int
	PatchKnown          bool
}

func (s Semver) String() string {
	if !s.PatchKnown {
		return fmt.Sprintf("%d.%d", s.Major, s.Minor)
	}
	return fmt.Sprintf("%d.%d.%d", s.Major, s.Minor, s.Patch)
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
func Parse(raw, declared string) (Version, error) {
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
		return parseOpenShift(raw)
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
		if d == AKS && strings.HasPrefix(raw, "v") {
			return Version{}, fmt.Errorf("%w", ErrMalformed)
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
		return core{s[:i], hasV, ""}, string(EKS), h, nil
	case strings.Contains(s, "-gke."):
		i := strings.Index(s, "-gke.")
		if hasV || !isPatchNumber(s[i+5:]) {
			return c, "", "", bad
		}
		return core{s[:i], hasV, ""}, string(GKE), s[i+5:], nil
	case strings.Contains(s, "+k3s"):
		i := strings.Index(s, "+k3s")
		if !hasV || !isPatchNumber(s[i+4:]) {
			return c, "", "", bad
		}
		return core{s[:i], hasV, ""}, string(K3s), s[i+4:], nil
	case strings.Contains(s, "+rke2r"):
		i := strings.Index(s, "+rke2r")
		if !hasV || !isPatchNumber(s[i+6:]) {
			return c, "", "", bad
		}
		return core{s[:i], hasV, ""}, string(RKE2), s[i+6:], nil
	}
	if strings.ContainsAny(s, "-+_/ ") {
		return c, "", "", bad
	}
	return core{s, hasV, ""}, "", "", nil
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
	return Semver{n[0], n[1], n[2], true}, nil
}

func parseOpenShift(raw string) (Version, error) {
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
	if !found {
		return Version{}, fmt.Errorf("%w: 4.%d", ErrUnknownOpenShift, min)
	}
	return Version{
		Distribution: OpenShift, Raw: raw,
		Upstream:   Semver{Major: k[0], Minor: k[1]},
		Confidence: ConfidenceMapped,
	}, nil
}

// SPDX-License-Identifier: AGPL-3.0-only

package imageidentity

import (
	"regexp"
	"strings"
	"time"
)

// Kind is the outcome class of a lookup.
type Kind string

const (
	// KindUnknown: the reference is not an image the registry identifies.
	KindUnknown Kind = "unknown"
	// KindMatched: the repository belongs to a project. Version may still
	// be empty; a matched image with no version says "present, version
	// unknown", never a guess.
	KindMatched Kind = "matched"
	// KindDistribution: a provider-built image (for example GKE's own
	// gke-release builds). Its tag is a distribution build number, not an
	// upstream version, and no cited mapping exists, so there is no version.
	KindDistribution Kind = "distribution"
)

// Result is what a lookup concludes about one image reference.
type Result struct {
	Kind      Kind
	Project   string
	Component string
	Role      string
	// Catalog is the record's catalog class (CatalogMember or CatalogNone).
	Catalog string
	Repo    string
	Tag     string
	// Version is the strict X.Y.Z of the project this image installs, or "".
	Version string
	// Scheme is "tag" when Version is set, "digest" when the reference is
	// pinned by digest without a usable tag, and "unknown" otherwise.
	Scheme string
	Reason string
}

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tagRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	refRE    = regexp.MustCompile(`^[A-Za-z0-9._:/@-]+$`)
)

func unknown(reason string) Result {
	return Result{Kind: KindUnknown, Scheme: "unknown", Reason: reason}
}

// canonicalRepo splits an image reference into a canonical repository
// ("host/path"), tag and digest. Anything it cannot read exactly returns ok
// false: there is no best effort.
func canonicalRepo(ref string) (repo, tag, digest string, ok bool) {
	if ref == "" || len(ref) > maxImageBytes || !refRE.MatchString(ref) {
		return "", "", "", false
	}
	name := ref
	if strings.Contains(ref, "@") {
		if strings.Count(ref, "@") != 1 {
			return "", "", "", false
		}
		i := strings.IndexByte(ref, '@')
		name, digest = ref[:i], ref[i+1:]
		if !digestRE.MatchString(digest) {
			return "", "", "", false
		}
	}
	if slash, colon := strings.LastIndexByte(name, '/'), strings.LastIndexByte(name, ':'); colon > slash {
		name, tag = name[:colon], name[colon+1:]
		if !tagRE.MatchString(tag) {
			return "", "", "", false
		}
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if p == "" {
			return "", "", "", false
		}
	}
	host := "docker.io"
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		host, parts = parts[0], parts[1:]
	}
	if host == "index.docker.io" || host == "registry-1.docker.io" {
		host = "docker.io"
	}
	if host == "docker.io" && len(parts) == 1 {
		parts = []string{"library", parts[0]}
	}
	if len(parts) == 0 {
		return "", "", "", false
	}
	return host + "/" + strings.Join(parts, "/"), tag, digest, true
}

func isCanonicalRepo(repo string) bool {
	got, tag, digest, ok := canonicalRepo(repo)
	return ok && got == repo && tag == "" && digest == "" && strings.ContainsAny(strings.SplitN(repo, "/", 2)[0], ".:") &&
		!strings.HasPrefix(repo, "index.docker.io/") && !strings.HasPrefix(repo, "registry-1.docker.io/")
}

func isDistribution(repo string) bool {
	host, path, _ := strings.Cut(repo, "/")
	return host == "gke.gcr.io" || (strings.HasSuffix(host, "gcr.io") && strings.HasPrefix(path, "gke-release/"))
}

// tagVersion extracts the version from a tag under a record's scheme.
func tagVersion(scheme, tag string) (string, bool) {
	switch scheme {
	case SchemeV:
		if !strings.HasPrefix(tag, "v") {
			return "", false
		}
		tag = tag[1:]
	case SchemeAlpine:
		var ok bool
		if tag, ok = strings.CutSuffix(tag, "-alpine"); !ok {
			return "", false
		}
	case SchemePlain:
	default:
		return "", false
	}
	if !versionRE.MatchString(tag) {
		return "", false
	}
	return tag, true
}

// Match identifies one image reference against this table at now.
func (t *Table) Match(ref string, now time.Time) Result {
	repo, tag, digest, ok := canonicalRepo(ref)
	if !ok {
		return unknown("image reference is not a plain repository, tag and sha256 digest")
	}
	if isDistribution(repo) {
		return Result{Kind: KindDistribution, Repo: repo, Tag: tag, Scheme: "unknown", Reason: "provider distribution build; its tag is not an upstream version"}
	}
	for _, r := range t.Records {
		for _, img := range r.Images {
			if img.Repo != repo {
				continue
			}
			if !r.usable(now) {
				return unknown("registry record is withdrawn or past validUntil")
			}
			res := Result{Kind: KindMatched, Project: r.Project, Component: r.Component, Role: img.Role, Catalog: r.Catalog, Repo: repo, Tag: tag, Scheme: "unknown"}
			switch {
			case tag == "" && digest != "":
				res.Scheme, res.Reason = "digest", "digest-only reference has no version"
			case tag == "":
				res.Reason = "untagged reference means latest, which is no version"
			case digest != "" && !r.TagWithDigest:
				res.Scheme, res.Reason = "digest", "tag with a digest is not trusted for this project"
			default:
				if v, ok := tagVersion(r.TagScheme, tag); ok {
					res.Version, res.Scheme = v, "tag"
				} else {
					res.Reason = "tag does not follow the declared scheme " + r.TagScheme
				}
			}
			return res
		}
	}
	return unknown("repository is not in the registry")
}

// Match identifies one image reference against the embedded table. A broken
// embedded table identifies nothing.
func Match(ref string, now time.Time) Result {
	t, err := Load()
	if err != nil {
		return unknown("embedded registry is invalid")
	}
	return t.Match(ref, now)
}

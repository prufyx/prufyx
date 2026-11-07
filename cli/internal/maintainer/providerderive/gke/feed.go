// SPDX-License-Identifier: AGPL-3.0-only

package gke

import (
	"bytes"
	"encoding/xml"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

const (
	srcFeed = "gke-feed"
	// FeedFormat is the first body line of a feed-entry excerpt.
	FeedFormat = "format gke-feed-entry/v1"
	// FeedPath is the path a feed excerpt must cite.
	FeedPath = "/feeds/gke-release-notes.xml"
	// MinFeedEntries is the observed window (30 entries); a shorter feed
	// means the archive would shrink, which is refused.
	MinFeedEntries = 30
	// MaxFeedBytes caps the feed read.
	MaxFeedBytes = 8 << 20
)

// Release is one build named in the feed prose. The feed has no structured
// version field: versions exist only in sentences. A preview build
// ("+preview") is a prerelease and is never a release fact.
type Release struct {
	Day        string // YYYY-MM-DD of the feed entry
	Channel    string // rapid, regular, stable or extended
	Version    string // 1.N.P-gke.B
	Prerelease bool
}

// Entry is one feed day with its releases.
type Entry struct {
	Day      string
	Releases []Release
}

var (
	versionRE = regexp.MustCompile(`\b1\.[0-9]{1,3}\.[0-9]{1,3}-gke\.[0-9]{1,9}(\+[A-Za-z]+)?`)
	sentRE    = regexp.MustCompile(`(?i)the following versions are now available in the ([a-z ]+?) channel:?`)
	tagRE     = regexp.MustCompile(`(?s)<[^>]*>`)
	runRE     = regexp.MustCompile(`^[ \t\r\n,]*(1\.[0-9]{1,3}\.[0-9]{1,3}-gke\.[0-9]{1,9}(?:\+[A-Za-z]+)?)`)
)

type atomFeed struct {
	XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	Entries []struct {
		Title   string `xml:"title"`
		ID      string `xml:"id"`
		Updated string `xml:"updated"`
		Content struct {
			Type string `xml:"type,attr"`
			Body string `xml:",chardata"`
		} `xml:"content"`
	} `xml:"entry"`
}

// ParseFeed reads the Atom feed bytes into per-day entries (newest first, as
// the feed is). Fewer than MinFeedEntries entries, a malformed entry, days
// out of order or a title that disagrees with its timestamp is drift.
func ParseFeed(feed []byte) ([]Entry, error) {
	if len(feed) == 0 {
		return nil, pd.Drift(srcFeed, pd.KindEmpty, "no feed bytes")
	}
	if len(feed) > MaxFeedBytes {
		return nil, pd.Drift(srcFeed, pd.KindSize, "feed over %d bytes", MaxFeedBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(feed))
	dec.Strict = true
	var f atomFeed
	if err := dec.Decode(&f); err != nil {
		return nil, pd.Drift(srcFeed, pd.KindStructure, "not an Atom feed: %v", err)
	}
	if len(f.Entries) < MinFeedEntries {
		return nil, pd.Drift(srcFeed, pd.KindIncomplete, "%d entries, want at least %d", len(f.Entries), MinFeedEntries)
	}
	var out []Entry
	prev := "9999-99-99"
	for i, e := range f.Entries {
		if len(e.Updated) < 10 {
			return nil, pd.Drift(srcFeed, pd.KindRow, "entry %d: no timestamp", i+1)
		}
		day := e.Updated[:10]
		if _, ok := pd.ParseISO(day); !ok {
			return nil, pd.Drift(srcFeed, pd.KindRow, "entry %d: bad timestamp", i+1)
		}
		if tt, err := time.Parse("January 02, 2006", strings.TrimSpace(e.Title)); err != nil || tt.Format("2006-01-02") != day {
			return nil, pd.Drift(srcFeed, pd.KindRow, "entry %d: title disagrees with timestamp", i+1)
		}
		if day >= prev {
			return nil, pd.Drift(srcFeed, pd.KindRow, "entry %d: days are not strictly descending", i+1)
		}
		prev = day
		rel, err := scanContent(day, e.Content.Body)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Day: day, Releases: rel})
	}
	return out, nil
}

// scanContent finds "now available in the X channel" sentences and the run
// of builds that directly follows each (separated only by space or commas).
// Builds named anywhere else in the prose are not mapped to a channel and are
// ignored, never guessed. A sentence naming a channel outside the closed set
// ("no channel") yields no releases.
func scanContent(day, content string) ([]Release, error) {
	txt := tagRE.ReplaceAllString(content, " ")
	txt = strings.ReplaceAll(html.UnescapeString(txt), "\u00a0", " ")
	var out []Release
	for _, m := range sentRE.FindAllStringSubmatchIndex(txt, -1) {
		ch := strings.ToLower(strings.Join(strings.Fields(txt[m[2]:m[3]]), " "))
		if !validChannel(ch) {
			continue
		}
		tail := txt[m[1]:]
		for {
			loc := runRE.FindStringSubmatchIndex(tail)
			if loc == nil {
				break
			}
			v := tail[loc[2]:loc[3]]
			tail = tail[loc[1]:]
			r := Release{Day: day, Channel: ch, Version: v}
			if i := strings.IndexByte(v, '+'); i >= 0 {
				r.Version = v[:i]
				if v[i:] != "+preview" {
					return nil, pd.Drift(srcFeed, pd.KindCell, "unknown build suffix %q on %s", v[i:], day)
				}
				r.Prerelease = true
			}
			dup := false
			for _, o := range out {
				dup = dup || o == r
			}
			if !dup { // the prose repeats builds; one fact per build
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func validChannel(c string) bool {
	for _, v := range Channels {
		if v == c {
			return true
		}
	}
	return false
}

// EntryBody renders one feed day as an excerpt body: "day <date>" then one
// line per channel: "<channel> <version>..." where a preview build keeps its
// "+preview" suffix. A day with no releases still archives (day line only).
func EntryBody(e Entry) string {
	var b strings.Builder
	b.WriteString(FeedFormat + "\nday " + e.Day + "\n")
	for _, ch := range Channels {
		var vs []string
		for _, r := range e.Releases {
			if r.Channel == ch {
				v := r.Version
				if r.Prerelease {
					v += "+preview"
				}
				vs = append(vs, v)
			}
		}
		if len(vs) > 0 {
			b.WriteString(ch + " " + strings.Join(vs, " ") + "\n")
		}
	}
	return b.String()
}

var dayRE = regexp.MustCompile(`^day ([0-9-]{10})$`)

// DeriveFeed reads archived feed-entry excerpts (one or more days, strictly
// ascending by day across the slice) into releases. Preview builds come back
// with Prerelease true; they never map to a lifecycle row. Duplicate builds
// within a day and channel are refused.
func DeriveFeed(xs []pd.Excerpt) ([]Release, error) {
	if len(xs) == 0 {
		return nil, pd.Drift(srcFeed, pd.KindEmpty, "no excerpts")
	}
	var out []Release
	prev := ""
	for _, x := range xs {
		if err := checkSource(x, srcFeed, FeedPath); err != nil {
			return nil, err
		}
		body, err := pd.Body(x)
		if err != nil {
			return nil, err
		}
		if len(body) < 2 || body[0] != FeedFormat {
			return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: not a feed-entry body", x.Entry.ID)
		}
		m := dayRE.FindStringSubmatch(body[1])
		if m == nil {
			return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: no day line", x.Entry.ID)
		}
		if d, ok := pd.ParseISO(m[1]); !ok || d.Precision != distribution.PrecisionDay || m[1] <= prev {
			return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: day missing, invalid or not ascending", x.Entry.ID)
		}
		prev = m[1]
		seenCh := map[string]bool{}
		lastCh := ""
		for _, ln := range body[2:] {
			f := strings.Split(ln, " ")
			if len(f) < 2 || !validChannel(f[0]) || seenCh[f[0]] || f[0] <= lastCh {
				return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: bad channel line", x.Entry.ID)
			}
			seenCh[f[0]], lastCh = true, f[0]
			seenV := map[string]bool{}
			for _, v := range f[1:] {
				if !versionRE.MatchString(v) || versionRE.FindString(v) != v || seenV[v] {
					return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: bad or repeated build", x.Entry.ID)
				}
				seenV[v] = true
				r := Release{Day: m[1], Channel: f[0], Version: v}
				if i := strings.IndexByte(v, '+'); i >= 0 {
					if v[i:] != "+preview" {
						return nil, pd.Drift(srcFeed, pd.KindExcerpt, "%s: unknown build suffix", x.Entry.ID)
					}
					r.Version, r.Prerelease = v[:i], true
				}
				out = append(out, r)
			}
		}
	}
	return out, nil
}

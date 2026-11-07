// SPDX-License-Identifier: AGPL-3.0-only

package distribution

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/k8sversion"
)

// Provider facts on a distribution record: lifecycle dates, release channels
// and provider deprecations. They state what the provider announces, under
// the record's own evidence (same freshness, same sources, same window). They
// are advisory: they can add a finding, never clear one, and nothing in this
// file authorizes a SAFE verdict.

// Limits.
const (
	MaxLifecycle    = 64
	MaxChannels     = 256
	MaxDeprecations = 64
)

// Date precisions. Every date of a row has the row's precision.
const (
	PrecisionDay     = "day"     // YYYY-MM-DD
	PrecisionMonth   = "month"   // YYYY-MM
	PrecisionQuarter = "quarter" // YYYY-Qn
	PrecisionTBD     = "tbd"     // announced without a date: the row holds no date
)

// channelVocabulary is the closed channel set of the distributions that have
// release channels. A distribution absent here takes no channels.
var channelVocabulary = map[string]map[string]bool{
	string(k8sversion.GKE):       {"rapid": true, "regular": true, "stable": true, "extended": true},
	string(k8sversion.OpenShift): {"candidate": true, "fast": true, "stable": true, "eus": true},
}

// ForcedUpgrade is the date the provider upgrades a line for its users. It
// exists only when a source sentence states it; its absence means unknown,
// not none.
type ForcedUpgrade struct {
	Date       string `json:"date"`
	SentenceID string `json:"sentenceId"`
}

// Lifecycle is one provider line's announced support dates.
// ExtendedRequiresOptIn is required next to ExtendedEnd and absent without it.
type Lifecycle struct {
	Line                  string         `json:"line"`
	GA                    string         `json:"ga,omitempty"`
	StandardEnd           string         `json:"standardEnd,omitempty"`
	ExtendedEnd           string         `json:"extendedEnd,omitempty"`
	ExtendedRequiresOptIn *bool          `json:"extendedRequiresOptIn,omitempty"`
	MaintenanceStart      string         `json:"maintenanceStart,omitempty"`
	ForcedUpgrade         *ForcedUpgrade `json:"forcedUpgrade,omitempty"`
	Precision             string         `json:"precision"`
}

// Channel is one line's availability in one release channel.
type Channel struct {
	Line        string `json:"line"`
	Channel     string `json:"channel"`
	Available   string `json:"available,omitempty"`
	AutoUpgrade string `json:"autoUpgrade,omitempty"`
	Precision   string `json:"precision"`
}

// Deprecation is a provider-specific removal or forced change and the first
// line it applies to.
type Deprecation struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	FirstLine string `json:"firstLine"`
}

func (r Record) validateProviderFacts() error {
	if r.Lifecycle != nil {
		if len(r.Lifecycle) == 0 || len(r.Lifecycle) > MaxLifecycle {
			return fmt.Errorf("%w: lifecycle holds 1-%d rows when present", ErrInvalid, MaxLifecycle)
		}
		prev := lineKey{-1, -1}
		for i, l := range r.Lifecycle {
			k, err := r.lineKey(l.Line)
			if err != nil {
				return fmt.Errorf("%w: lifecycle %d: %v", ErrInvalid, i, err)
			}
			if !k.after(prev) {
				return fmt.Errorf("%w: lifecycle lines must be unique and strictly increasing (entry %d, line %s): conflicting rows for one line are refused", ErrInvalid, i, l.Line)
			}
			prev = k
			if err := l.validate(); err != nil {
				return fmt.Errorf("%w: lifecycle %d (%s): %v", ErrInvalid, i, l.Line, err)
			}
		}
	}
	if r.Channels != nil {
		if len(r.Channels) == 0 || len(r.Channels) > MaxChannels {
			return fmt.Errorf("%w: channels holds 1-%d rows when present", ErrInvalid, MaxChannels)
		}
		vocab := channelVocabulary[r.Distribution]
		if vocab == nil {
			return fmt.Errorf("%w: %s has no release channels", ErrInvalid, r.Distribution)
		}
		prev, prevName := lineKey{-1, -1}, ""
		for i, c := range r.Channels {
			k, err := r.lineKey(c.Line)
			if err != nil {
				return fmt.Errorf("%w: channels %d: %v", ErrInvalid, i, err)
			}
			if !vocab[c.Channel] {
				return fmt.Errorf("%w: channels %d: %q is not a %s channel", ErrInvalid, i, c.Channel, r.Distribution)
			}
			if i > 0 && !(k.after(prev) || (k == prev && c.Channel > prevName)) {
				return fmt.Errorf("%w: channels must be unique and ascending by (line, channel): entry %d (%s %s) conflicts or is out of order", ErrInvalid, i, c.Line, c.Channel)
			}
			prev, prevName = k, c.Channel
			if err := validDates(c.Precision, c.Available, c.AutoUpgrade); err != nil {
				return fmt.Errorf("%w: channels %d (%s %s): %v", ErrInvalid, i, c.Line, c.Channel, err)
			}
		}
	}
	if r.Deprecations != nil {
		if len(r.Deprecations) == 0 || len(r.Deprecations) > MaxDeprecations {
			return fmt.Errorf("%w: deprecations holds 1-%d rows when present", ErrInvalid, MaxDeprecations)
		}
		prevID := ""
		for i, d := range r.Deprecations {
			if !validToken(d.ID) {
				return fmt.Errorf("%w: deprecations %d: id %q must be 1-64 of a-z, 0-9, '.', '_', '-' starting with a letter or digit", ErrInvalid, i, d.ID)
			}
			if i > 0 && d.ID <= prevID {
				return fmt.Errorf("%w: deprecation ids must be unique and ascending (entry %d, id %s)", ErrInvalid, i, d.ID)
			}
			prevID = d.ID
			if !publicText(d.Summary) {
				return fmt.Errorf("%w: deprecations %d: summary must be 1-%d bytes of printable UTF-8 text without surrounding space", ErrInvalid, i, MaxText)
			}
			if _, err := r.lineKey(d.FirstLine); err != nil {
				return fmt.Errorf("%w: deprecations %d: firstLine: %v", ErrInvalid, i, err)
			}
		}
	}
	return nil
}

type lineKey struct{ major, minor int }

func (a lineKey) after(b lineKey) bool {
	return a.major > b.major || (a.major == b.major && a.minor > b.minor)
}

// lineKey parses a provider line: OpenShift 4.N, every other distribution 1.N
// (Kubernetes-style minors; a record names no other grammar).
func (r Record) lineKey(line string) (lineKey, error) {
	major, minor, ok := ParseLine(line)
	want := 1
	if r.Distribution == string(k8sversion.OpenShift) {
		want = 4
	}
	if !ok || major != want {
		return lineKey{}, fmt.Errorf("line %q is not a canonical %d.N line for %s", line, want, r.Distribution)
	}
	return lineKey{major, minor}, nil
}

func validToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}

func (l Lifecycle) validate() error {
	if l.ExtendedEnd != "" && l.ExtendedRequiresOptIn == nil {
		return fmt.Errorf("extendedEnd needs extendedRequiresOptIn")
	}
	if l.ExtendedEnd == "" && l.ExtendedRequiresOptIn != nil {
		return fmt.Errorf("extendedRequiresOptIn without extendedEnd")
	}
	forced := ""
	if l.ForcedUpgrade != nil {
		forced = l.ForcedUpgrade.Date
		if forced == "" {
			return fmt.Errorf("forcedUpgrade.date is empty")
		}
		if !publicText(l.ForcedUpgrade.SentenceID) {
			return fmt.Errorf("forcedUpgrade.sentenceId must be 1-%d bytes of printable text", MaxText)
		}
	}
	if err := validDates(l.Precision, l.GA, l.StandardEnd, l.ExtendedEnd, l.MaintenanceStart, forced); err != nil {
		return err
	}
	// A support window cannot end before it starts or before the standard end.
	chain := ""
	for _, d := range []string{l.GA, l.StandardEnd, l.ExtendedEnd} {
		if d == "" {
			continue
		}
		if chain != "" && d < chain {
			return fmt.Errorf("dates conflict: %s is before %s (ga <= standardEnd <= extendedEnd)", d, chain)
		}
		chain = d
	}
	return nil
}

// validDates checks the precision token and that every non-empty date has
// that precision. tbd holds no date; any other precision holds at least one
// (a date without a precision is refused because precision is required).
func validDates(precision string, dates ...string) error {
	n := 0
	for _, d := range dates {
		if d != "" {
			n++
		}
	}
	switch precision {
	case PrecisionDay, PrecisionMonth, PrecisionQuarter:
		if n == 0 {
			return fmt.Errorf("precision %q needs at least one date", precision)
		}
	case PrecisionTBD:
		if n != 0 {
			return fmt.Errorf("precision %q holds no date", precision)
		}
		return nil
	default:
		return fmt.Errorf("precision must be %q, %q, %q or %q", PrecisionDay, PrecisionMonth, PrecisionQuarter, PrecisionTBD)
	}
	for _, d := range dates {
		if d != "" && !validDate(precision, d) {
			return fmt.Errorf("date %q is not a valid %s date", d, precision)
		}
	}
	return nil
}

func validDate(precision, d string) bool {
	switch precision {
	case PrecisionDay:
		if len(d) != 10 || d[4] != '-' || d[7] != '-' {
			return false
		}
		y, m, day := digits(d[0:4]), digits(d[5:7]), digits(d[8:10])
		return y >= 2000 && m >= 1 && m <= 12 && day >= 1 && day <= daysIn(y, m)
	case PrecisionMonth:
		if len(d) != 7 || d[4] != '-' {
			return false
		}
		y, m := digits(d[0:4]), digits(d[5:7])
		return y >= 2000 && m >= 1 && m <= 12
	case PrecisionQuarter:
		if len(d) != 7 || d[4] != '-' || d[5] != 'Q' {
			return false
		}
		return digits(d[0:4]) >= 2000 && d[6] >= '1' && d[6] <= '4'
	}
	return false
}

// digits returns the value of an all-ASCII-digit string, or -1.
func digits(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

func daysIn(y, m int) int {
	switch m {
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

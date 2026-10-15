// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// PairProof is the extractor's account of one pair: what it read at each
// anchor, how it classified every key it considered, and the soft facts it
// recorded without deriving a rule.
type PairProof struct {
	Target       string                    `json:"target"`
	Chart        constraintengine.ChartRef `json:"chart"`
	From         *SideRecord               `json:"from"`
	To           *SideRecord               `json:"to"`
	Lines        *LinesRecord              `json:"lines,omitempty"`
	KubeVersion  *KubeRecord               `json:"kubeVersion,omitempty"`
	Required     *RequiredRecord           `json:"required,omitempty"`
	Removed      *RemovedRecord            `json:"removed,omitempty"`
	Soft         *SoftRecord               `json:"soft,omitempty"`
	Completeness *Completeness             `json:"completeness,omitempty"`
	Rules        []string                  `json:"rules,omitempty"`
}

// SideRecord is one chart release as read.
type SideRecord struct {
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Problem string `json:"problem,omitempty"`
	// The rest is set when the release reads completely.
	Version          string       `json:"version,omitempty"`
	KubeVersion      string       `json:"kubeVersion,omitempty"`
	Subcharts        []string     `json:"subcharts,omitempty"`
	PackagedSubchart bool         `json:"packagedSubchart,omitempty"`
	Schema           bool         `json:"schema"`
	ValuesPaths      []string     `json:"valuesPaths,omitempty"`
	RequiredKeys     []string     `json:"requiredKeys,omitempty"`
	Templates        TemplateRefs `json:"templates"`
}

func sideRecord(s *side) *SideRecord {
	r := &SideRecord{Tag: s.tag, Commit: s.commit, Problem: s.problem, Templates: s.templates}
	if s.problem != "" {
		r.Templates = TemplateRefs{Paths: []string{}, Refused: []string{}}
		return r
	}
	r.Version, r.KubeVersion, r.Subcharts, r.PackagedSubchart = s.meta.Version, s.meta.KubeVersion, s.subcharts, s.opaqueSubcharts
	r.Schema = s.schema != nil
	r.ValuesPaths = []string{}
	for _, p := range helmvaluespath.ValuePaths(s.values) {
		r.ValuesPaths = append(r.ValuesPaths, helmvaluespath.DisplayPath(p))
	}
	r.RequiredKeys = []string{}
	if s.schema != nil {
		for _, p := range walkSchema(s.schema).Required {
			r.RequiredKeys = append(r.RequiredKeys, helmvaluespath.DisplayPath(p))
		}
	}
	return r
}

// LinesRecord lists the final releases of both lines.
type LinesRecord struct {
	From LineRecord `json:"from"`
	To   LineRecord `json:"to"`
}

// LineRecord is one release line.
type LineRecord struct {
	Line     string    `json:"line"`
	Problem  string    `json:"problem,omitempty"`
	Releases []LineTag `json:"releases"`
}

// LineTag is one final release of a line. A release other than the anchor
// is read for the record only; rules are about the anchors.
type LineTag struct {
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	Version string `json:"version"`
	Anchor  bool   `json:"anchor,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// KubeRecord is the kubeVersion of both anchors and the outcome.
type KubeRecord struct {
	From    KubeMinimum `json:"from"`
	To      KubeMinimum `json:"to"`
	Outcome string      `json:"outcome"`
}

// KeyClass is one key and its class.
type KeyClass struct {
	Path   string `json:"path"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
}

// RequiredRecord classifies every key the later schema requires.
type RequiredRecord struct {
	Keys    []KeyClass   `json:"keys"`
	Opaque  []OpaqueNode `json:"opaque"`
	Outcome string       `json:"outcome"`
}

// RemovedRecord classifies every key the earlier chart used. Keys the
// later schema declares or leaves open are counted, not listed.
type RemovedRecord struct {
	Candidates int            `json:"candidates"`
	Counts     map[string]int `json:"counts"`
	Keys       []KeyClass     `json:"keys"`
	Outcome    string         `json:"outcome"`
}

// SoftRecord holds the soft facts: recorded, never a rule.
type SoftRecord struct {
	DefaultsRemoved   []string `json:"defaultsRemoved"`
	DefaultsChanged   []string `json:"defaultsChanged"`
	ReferencesRemoved []string `json:"referencesRemoved"`
	// Unread and Changed classify the keys the two notices considered.
	Unread  *NoticeRecord `json:"unread,omitempty"`
	Changed *NoticeRecord `json:"changed,omitempty"`
}

// Completeness accounts for the derivation: every required key is
// classified, every earlier key has one class, and what was not read is
// counted.
type Completeness struct {
	RequiredKeys          int `json:"requiredKeys"`
	EarlierKeys           int `json:"earlierKeys"`
	EarlierKeysClassified int `json:"earlierKeysClassified"`
	SchemaOpaque          int `json:"schemaOpaque"`
	TemplatesRefused      int `json:"templatesRefused"`
}

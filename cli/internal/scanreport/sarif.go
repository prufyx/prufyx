// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// SARIF 2.1.0 output for code scanning. The log is a pure function of the
// report: it adds no verdict logic and no text beyond the catalog and the
// report's own strings. Findings are the only results, and the only items
// with level "error"; gaps, notices, leads and unsupported combinations are
// tool notifications, and none of them is ever an error.

const (
	sarifSchema     = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion    = "2.1.0"
	sarifToolName   = "prufyx"
	sarifToolURL    = "https://github.com/prufyx/prufyx"
	sarifSrcRoot    = "%SRCROOT%"
	sarifMessageMax = 1024
	// SARIFMaxResults is the number of results code scanning accepts in one
	// run. A scan with more keeps the first ones in report order and says so
	// in a notification.
	SARIFMaxResults = 25000
	// redactedDir holds the digest names that stand in for redacted paths.
	redactedDir = "redacted"
	// fingerprintKey names the partial fingerprint.
	fingerprintKey = "prufyxResult/v1" // gitleaks:allow (a fingerprint name, not a secret)
	// truncatedID is the descriptor of the notification for dropped results.
	truncatedID = "RESULTS_TRUNCATED"
)

// SARIF levels.
const (
	sarifError   = "error"
	sarifWarning = "warning"
	sarifNote    = "note"
)

// Kinds, written to properties.kind.
const (
	kindBlocker     = "blocker"
	kindGap         = "gap"
	kindNotice      = "notice"
	kindLead        = "lead"
	kindUnsupported = "unsupported"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	Properties  sarifRunProps     `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Basis string `json:"basis"`
	Kind  string `json:"kind"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifResultProps struct {
	Component string `json:"component"`
	Hop       string `json:"hop"`
	Basis     string `json:"basis"`
	Match     string `json:"match"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   int                 `json:"exitCode"`
	ExitCodeDescription        string              `json:"exitCodeDescription"`
	StartTimeUTC               string              `json:"startTimeUtc"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Level          string           `json:"level"`
	Message        sarifText        `json:"message"`
	Descriptor     sarifReference   `json:"descriptor"`
	AssociatedRule *sarifRuleRef    `json:"associatedRule,omitempty"`
	Properties     sarifNoticeProps `json:"properties"`
}

type sarifReference struct {
	ID string `json:"id"`
}

type sarifRuleRef struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

type sarifNoticeProps struct {
	Kind      string `json:"kind"`
	Component string `json:"component"`
	Hop       string `json:"hop,omitempty"`
}

type sarifRunProps struct {
	Verdict              string       `json:"verdict"`
	Headline             string       `json:"headline"`
	Summary              Summary      `json:"summary"`
	EvaluatedAt          string       `json:"evaluatedAt"`
	InputDigest          string       `json:"inputDigest"`
	ConfigDigest         string       `json:"configDigest,omitempty"`
	KnowledgeOrigin      string       `json:"knowledgeOrigin"`
	KnowledgeRevision    string       `json:"knowledgeRevision"`
	KnowledgeDigest      string       `json:"knowledgeDigest"`
	EngineContractDigest string       `json:"engineContractDigest"`
	NetworkUsed          bool         `json:"networkUsed"`
	Omissions            []string     `json:"omissions"`
	TrustPolicy          *TrustPolicy `json:"trustPolicy,omitempty"`
	// KnowledgeStore names the knowledge database of a --knowledge-db scan.
	KnowledgeStore *KnowledgeStore `json:"knowledgeStore,omitempty"`
}

// SARIF renders the report as a SARIF 2.1.0 log: one result per finding
// location, rules by id, one tool notification per gap, notice, lead and
// unsupported combination, and the verdict and provenance as run
// properties. The same report always renders to the same bytes.
func SARIF(report Report) ([]byte, error) {
	rules, index := sarifRules(report)
	results, dropped := sarifResults(report, index)
	notifications := sarifNotifications(report, index)
	if dropped > 0 {
		notifications = append(notifications, sarifNotification{
			Level:      sarifWarning,
			Message:    sarifText{Text: Text(labelSarifTruncated, SARIFMaxResults, dropped)},
			Descriptor: sarifReference{ID: truncatedID},
			Properties: sarifNoticeProps{Kind: kindGap},
		})
	}
	omissions := report.Omissions
	if omissions == nil {
		omissions = []string{}
	}
	p := report.Provenance
	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{Name: sarifToolName, Version: p.Build.Version, InformationURI: sarifToolURL, Rules: rules}},
		Invocations: []sarifInvocation{{
			ExecutionSuccessful: true, ExitCode: Exit(report), ExitCodeDescription: report.Headline,
			StartTimeUTC: p.EvaluatedAt, ToolExecutionNotifications: notifications,
		}},
		Results: results,
		Properties: sarifRunProps{
			Verdict: report.Verdict, Headline: report.Headline, Summary: report.Summary, EvaluatedAt: p.EvaluatedAt,
			InputDigest: p.InputDigest, ConfigDigest: p.ConfigDigest, KnowledgeOrigin: p.KnowledgeOrigin,
			KnowledgeRevision: p.KnowledgeRevision, KnowledgeDigest: p.KnowledgeDigest,
			EngineContractDigest: p.EngineContractDigest, NetworkUsed: p.NetworkUsed,
			Omissions: omissions, TrustPolicy: report.TrustPolicy, KnowledgeStore: p.KnowledgeStore,
		},
	}}}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(log); err != nil {
		return nil, err
	}
	return escapeJSON(out.Bytes()), nil
}

// sarifRules lists one rule per distinct rule id of the report, by id, and
// the index of each. A rule id that appears under several kinds keeps the
// first of: findings, unsupported combinations, notices, leads.
func sarifRules(report Report) ([]sarifRule, map[string]int) {
	byID := map[string]sarifRule{}
	add := func(rule sarifRule) {
		if _, found := byID[rule.ID]; !found {
			rule.ShortDescription.Text = cut(rule.ShortDescription.Text, sarifMessageMax)
			rule.Help.Text = cut(rule.Help.Text, sarifMessageMax)
			byID[rule.ID] = rule
		}
	}
	for _, f := range report.Findings {
		add(sarifRule{ID: f.RuleID, ShortDescription: sarifText{f.Title}, Help: sarifText{f.Fix}, HelpURI: firstURL(f.Citations),
			DefaultConfiguration: sarifConfig{sarifError}, Properties: sarifRuleProps{Basis: f.Basis, Kind: kindBlocker}})
	}
	for _, u := range report.Unsupported {
		add(sarifRule{ID: u.RuleID, ShortDescription: sarifText{u.Reason}, Help: sarifText{u.Fix}, HelpURI: firstURL(u.Citations),
			DefaultConfiguration: sarifConfig{sarifWarning}, Properties: sarifRuleProps{Basis: u.Basis, Kind: kindUnsupported}})
	}
	for _, n := range report.Notices {
		add(sarifRule{ID: n.RuleID, ShortDescription: sarifText{n.Text}, Help: sarifText{n.Text}, HelpURI: firstURL(n.Citations),
			DefaultConfiguration: sarifConfig{sarifNote}, Properties: sarifRuleProps{Basis: n.Basis, Kind: kindNotice}})
	}
	for _, l := range report.Leads {
		add(sarifRule{ID: l.RuleID, ShortDescription: sarifText{l.Text}, Help: sarifText{l.Text}, HelpURI: firstURL(l.Citations),
			DefaultConfiguration: sarifConfig{sarifNote}, Properties: sarifRuleProps{Basis: "lead", Kind: kindLead}})
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for _, id := range ids {
		index[id] = len(rules)
		rules = append(rules, byID[id])
	}
	return rules, index
}

type sarifRow struct {
	component string
	hop       int
	file      string
	document  int
	item      int
	result    sarifResult
}

// sarifResults is one result per (finding, location), ordered by
// component, hop, rule id, file, document and item. The second value is how
// many results the size limit dropped.
func sarifResults(report Report, index map[string]int) ([]sarifResult, int) {
	var rows []sarifRow
	for _, f := range report.Findings {
		base := sarifResult{
			RuleID: f.RuleID, RuleIndex: index[f.RuleID], Level: sarifError,
			Message:    sarifText{cut(fmt.Sprintf(labelResultMessage, f.Title, f.Fix), sarifMessageMax)},
			Properties: sarifResultProps{Component: f.Component, Hop: hopLabel(f.Hop), Basis: f.Basis, Match: f.Match},
		}
		if len(f.Locations) == 0 {
			rows = append(rows, sarifRow{component: f.Component, hop: f.Hop.order(), document: -1, item: -1, result: base})
			continue
		}
		for _, l := range f.Locations {
			result := base
			if uri := sarifURI(l.File); uri != "" {
				physical := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri, URIBaseID: sarifSrcRoot}}
				if l.Line >= 1 {
					physical.Region = &sarifRegion{StartLine: l.Line}
				}
				result.Locations = []sarifLocation{{PhysicalLocation: physical, LogicalLocations: []sarifLogical{logicalOf(l)}}}
				result.PartialFingerprints = map[string]string{fingerprintKey: fingerprint(f.RuleID, uri, l.Document, l.Item)}
			}
			rows = append(rows, sarifRow{component: f.Component, hop: f.Hop.order(), file: l.File, document: l.Document, item: l.Item, result: result})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch {
		case a.component != b.component:
			return a.component < b.component
		case a.hop != b.hop:
			return a.hop < b.hop
		case a.result.RuleID != b.result.RuleID:
			return a.result.RuleID < b.result.RuleID
		case a.file != b.file:
			return a.file < b.file
		case a.document != b.document:
			return a.document < b.document
		}
		return a.item < b.item
	})
	dropped := 0
	if len(rows) > SARIFMaxResults {
		dropped = len(rows) - SARIFMaxResults
		rows = rows[:SARIFMaxResults]
	}
	results := make([]sarifResult, 0, len(rows))
	for _, row := range rows {
		results = append(results, row.result)
	}
	return results, dropped
}

func logicalOf(l Location) sarifLogical {
	name := l.Name
	if name == "" {
		name = labelNoName
	}
	qualified := l.Kind + " " + name
	if l.Namespace != "" {
		qualified = l.Kind + " " + l.Namespace + "/" + name
	}
	return sarifLogical{Name: name, FullyQualifiedName: qualified, Kind: "resource"}
}

// fingerprint is stable across runs: it depends on the rule, the artifact
// URI and the position of the object in its input, never on a line.
func fingerprint(ruleID, uri string, document, item int) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + uri + "\x00" + strconv.Itoa(document) + "\x00" + strconv.Itoa(item)))
	return hex.EncodeToString(sum[:])
}

type sarifNoteRow struct {
	component string
	hop       int
	kind      int
	id        string
	note      sarifNotification
}

// sarifNotifications is one notification per gap, unsupported combination,
// notice and lead, ordered by component, hop, kind and id. Gaps and
// unsupported combinations are warnings; notices and leads are notes.
func sarifNotifications(report Report, index map[string]int) []sarifNotification {
	var rows []sarifNoteRow
	for _, g := range report.Gaps {
		props, hop := sarifNoticeProps{Kind: kindGap, Component: g.Component}, -1
		if g.Hop != nil {
			props.Hop, hop = hopLabel(*g.Hop), g.Hop.order()
		}
		rows = append(rows, sarifNoteRow{g.Component, hop, 0, g.Reason, sarifNotification{
			Level: sarifWarning, Message: sarifText{cut(fmt.Sprintf(labelGapLine, g.Detail, g.Action), sarifMessageMax)},
			Descriptor: sarifReference{g.Reason}, Properties: props}})
	}
	for _, u := range report.Unsupported {
		rows = append(rows, sarifNoteRow{u.Component, u.Hop.order(), 1, u.RuleID, sarifNotification{
			Level: sarifWarning, Message: sarifText{cut(fmt.Sprintf(labelUnsupportedMsg, u.Reason, u.Fix), sarifMessageMax)},
			Descriptor: sarifReference{u.RuleID}, AssociatedRule: &sarifRuleRef{u.RuleID, index[u.RuleID]},
			Properties: sarifNoticeProps{Kind: kindUnsupported, Component: u.Component, Hop: hopLabel(u.Hop)}}})
	}
	for _, n := range report.Notices {
		text := fmt.Sprintf(labelNoticeMessage, n.Text)
		if !n.Established {
			text = fmt.Sprintf(labelNoticeNotEstab, n.Reason, n.Text)
		}
		rows = append(rows, sarifNoteRow{n.Component, n.Hop.order(), 2, n.RuleID, sarifNotification{
			Level: sarifNote, Message: sarifText{cut(text, sarifMessageMax)},
			Descriptor: sarifReference{n.RuleID}, AssociatedRule: &sarifRuleRef{n.RuleID, index[n.RuleID]},
			Properties: sarifNoticeProps{Kind: kindNotice, Component: n.Component, Hop: hopLabel(n.Hop)}}})
	}
	for _, l := range report.Leads {
		rows = append(rows, sarifNoteRow{l.Component, l.Hop.order(), 3, l.RuleID, sarifNotification{
			Level: sarifNote, Message: sarifText{cut(fmt.Sprintf(labelLeadMessage, l.Text), sarifMessageMax)},
			Descriptor: sarifReference{l.RuleID}, AssociatedRule: &sarifRuleRef{l.RuleID, index[l.RuleID]},
			Properties: sarifNoticeProps{Kind: kindLead, Component: l.Component, Hop: hopLabel(l.Hop)}}})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch {
		case a.component != b.component:
			return a.component < b.component
		case a.hop != b.hop:
			return a.hop < b.hop
		case a.kind != b.kind:
			return a.kind < b.kind
		case a.id != b.id:
			return a.id < b.id
		}
		return a.note.Message.Text < b.note.Message.Text
	})
	out := make([]sarifNotification, 0, len(rows)+1)
	for _, row := range rows {
		out = append(out, row.note)
	}
	return out
}

func firstURL(citations []constraintengine.SourceEvidence) string {
	for _, c := range citations {
		if c.URL != "" {
			return c.URL
		}
	}
	return ""
}

// sarifURI is the artifact URI of a display path: relative to the
// repository root, forward slashes, percent-encoded, never absolute and
// never containing "..". A path given as absolute or outside the working
// directory keeps its remaining segments. A redacted digest becomes a name
// under "redacted/". An empty result means there is no usable path.
func sarifURI(file string) string {
	if strings.HasPrefix(file, digestPrefix) && len(file) == len(digestPrefix)+64 {
		return redactedDir + "/" + file[len(digestPrefix):len(digestPrefix)+12]
	}
	clean := strings.TrimLeft(path.Clean("/"+strings.ReplaceAll(file, "\\", "/")), "/")
	if clean == "" {
		return ""
	}
	segments := strings.Split(clean, "/")
	for i, segment := range segments {
		segments[i] = strings.ReplaceAll(url.PathEscape(strings.ToValidUTF8(segment, "?")), ":", "%3A")
	}
	return strings.Join(segments, "/")
}

// cut bounds text to n bytes on a character boundary.
func cut(text string, n int) string {
	if len(text) <= n {
		return text
	}
	end := n
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	CRIOComponent    = "pkg:github/cri-o/cri-o"
	CRIOPlannedFact  = "component.crio.artifact_named_reference_resolution_planned"
	CRIOShortFact    = "component.crio.artifact_named_reference_is_short"
	CRIOOperation    = "named-reference-resolution"
	CRIOFrom         = "1.34.0"
	CRIOTo           = "1.35.0"
	crioShortNameMax = 237
	crioQualifiedMax = 255
)

const (
	ReasonCRIOShortReference     Reason = "CRIO_ARTIFACT_SHORT_REFERENCE_WITNESS"
	ReasonCRIOQualifiedReference Reason = "CRIO_ARTIFACT_QUALIFIED_REFERENCE_WITNESS"
	ReasonCRIOInputUnsupported   Reason = "CRIO_IMAGE_STATUS_REQUEST_SHAPE_UNSUPPORTED"
	ReasonCRIOInputAmbiguous     Reason = "CRIO_IMAGE_STATUS_REQUEST_AMBIGUOUS"
)

var (
	crioPathComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	crioTagRE           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	crioDomainLabelRE   = regexp.MustCompile(`^[a-z](?:[a-z0-9-]*[a-z0-9])?$`)
)

// PrepareCRIOArtifactName derives only the caller's named-artifact-resolution
// intent and a conservative short-name classification from a native CRI
// ImageStatusRequest JSON document. It never resolves aliases or contacts CRI-O.
func PrepareCRIOArtifactName(raw []byte, from, to, operation string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	root, ambiguous, err := decodeCRIORequest(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	planned := inputFact{ID: CRIOPlannedFact, State: "unsupported"}
	if operation == CRIOOperation {
		value := true
		planned = inputFact{ID: CRIOPlannedFact, State: "declared", BoolValue: &value}
	}
	short := inputFact{ID: CRIOShortFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonCRIOInputUnsupported
	if ambiguous {
		reason = ReasonCRIOInputAmbiguous
	} else if reference, ok := crioReference(root); ok {
		if value, classified := classifyCRIOReference(reference); classified {
			short = inputFact{ID: CRIOShortFact, State: "declared", BoolValue: &value}
			state = StatePrepared
			if value {
				reason = ReasonCRIOShortReference
			} else {
				reason = ReasonCRIOQualifiedReference
			}
		}
	}
	canonical, err := marshalComponentInput(CRIOComponent, from, to, []inputFact{short, planned})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"ARTIFACT_OPERATION_IS_CALLER_DECLARED_NOT_RUNTIME_OBSERVED",
		"REGISTRIES_CONF_ALIAS_AND_DEFAULT_REGISTRY_NOT_EVALUATED",
		"ARTIFACT_STORE_CONTENTS_AND_SERVER_BRANCH_NOT_EVALUATED",
		"IMAGE_STATUS_REMOVE_PULL_AND_RUNTIME_NOT_EVALUATED",
		OmissionNoLiveObservation,
		OmissionNoWholeUpgrade,
	}}, nil
}

func crioReference(root map[string]any) (string, bool) {
	image, ok := root["image"].(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := image["image"].(string)
	return value, ok && value != ""
}

func classifyCRIOReference(value string) (bool, bool) {
	if value == "" || !isASCII(value) || strings.Contains(value, "@") {
		return false, false
	}
	colon := strings.LastIndexByte(value, ':')
	slash := strings.LastIndexByte(value, '/')
	if colon <= slash || colon == len(value)-1 || !crioTagRE.MatchString(value[colon+1:]) {
		return false, false
	}
	name := value[:colon]
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return false, false
	}
	first := parts[0]
	if !strings.Contains(first, ".") && first != "localhost" {
		for _, part := range parts {
			if !crioPathComponentRE.MatchString(part) {
				return false, false
			}
		}
		return len(name) <= crioShortNameMax, len(name) <= crioShortNameMax
	}
	if len(parts) < 2 || len(name) > crioQualifiedMax || !validCRIODomain(first) {
		return false, false
	}
	for _, part := range parts[1:] {
		if !crioPathComponentRE.MatchString(part) {
			return false, false
		}
	}
	return false, true
}

func validCRIODomain(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	allNumeric := true
	for _, label := range labels {
		if !crioDomainLabelRE.MatchString(label) {
			return false
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				allNumeric = false
				break
			}
		}
	}
	return !allNumeric
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

// decodeCRIORequest preserves unrelated JSON while treating only duplicate or
// case-fold-colliding root image and nested image.image members as ambiguous.
func decodeCRIORequest(raw []byte) (map[string]any, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, ambiguous, err := decodeCRIOValue(decoder, 0, false)
	if err != nil {
		return nil, false, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, false, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false, nil
	}
	return root, ambiguous, nil
}

func decodeCRIOValue(decoder *json.Decoder, depth int, inRootImage bool) (any, bool, error) {
	if depth > maxJSONDepth {
		return nil, false, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, false, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, false, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		seenRelevant := false
		ambiguous := false
		for members := 0; decoder.More(); members++ {
			if members >= maxObjectMembers {
				return nil, false, ErrInvalid
			}
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, false, ErrInvalid
			}
			relevant := (depth == 0 || inRootImage) && strings.EqualFold(key, "image")
			if relevant && seenRelevant {
				ambiguous = true
			}
			if relevant {
				seenRelevant = true
			}
			childInRootImage := depth == 0 && key == "image"
			item, childAmbiguous, err := decodeCRIOValue(decoder, depth+1, childInRootImage)
			if err != nil {
				return nil, false, err
			}
			ambiguous = ambiguous || childAmbiguous
			if _, exists := object[key]; !exists {
				object[key] = item
			}
			if inRootImage && strings.EqualFold(key, "image") && key != "image" {
				ambiguous = true
			}
			if depth == 0 && strings.EqualFold(key, "image") && key != "image" {
				ambiguous = true
			}
		}
		if _, err := decoder.Token(); err != nil {
			return nil, false, err
		}
		return object, ambiguous, nil
	case '[':
		array := []any{}
		ambiguous := false
		for decoder.More() {
			if len(array) >= maxArrayItems {
				return nil, false, ErrInvalid
			}
			item, childAmbiguous, err := decodeCRIOValue(decoder, depth+1, false)
			if err != nil {
				return nil, false, err
			}
			array = append(array, item)
			ambiguous = ambiguous || childAmbiguous
		}
		if _, err := decoder.Token(); err != nil {
			return nil, false, err
		}
		return array, ambiguous, nil
	default:
		return nil, false, ErrInvalid
	}
}

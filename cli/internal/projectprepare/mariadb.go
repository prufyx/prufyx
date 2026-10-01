// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bufio"
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MariaDBProject          = "mariadb"
	MariaDBComponent        = "pkg:github/mariadb/server"
	MariaDBFrom             = "10.11.8"
	MariaDBTo               = "11.4.2"
	MariaDBFact             = "component.mariadb.innodb_defragmentation_required"
	MariaDBDistributionFact = "component.mariadb.upstream_distribution"
)

// PrepareMariaDBEffectiveConfig derives a bounded predicate from one
// caller-selected, complete and precedence-resolved MariaDB option file. The
// upstreamDistribution declaration binds the reviewed upstream source to the
// input. The requirement must be provided explicitly: the option's presence,
// absence, or value does not authorize a behavior-preservation decision.
func PrepareMariaDBEffectiveConfig(raw []byte, from, to string, complete, precedenceResolved, upstreamDistribution, requirementDeclared, requireDefragmentation bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	supported, err := mariaDBOptionFileSupported(raw)
	if err != nil {
		return Prepared{}, err
	}
	requirementFact := inputFact{ID: MariaDBFact, State: "unsupported"}
	distributionFact := inputFact{ID: MariaDBDistributionFact, State: "unsupported"}
	state, reason := "UNKNOWN", "MARIADB_EFFECTIVE_CONFIG_DECLARATIONS_INCOMPLETE"
	if from != MariaDBFrom || to != MariaDBTo {
		reason = "UNSUPPORTED_VERSION_PAIR"
	} else {
		if complete && precedenceResolved && supported && requirementDeclared {
			requirementFact.State = "declared"
			requirementFact.BoolValue = &requireDefragmentation
		}
		if upstreamDistribution {
			upstream := true
			distributionFact.State = "declared"
			distributionFact.BoolValue = &upstream
		}
		if !supported {
			reason = "MARIADB_OPTION_FILE_SHAPE_UNSUPPORTED"
		} else if requirementFact.State == "declared" && distributionFact.State == "declared" {
			state, reason = "PREPARED", "MARIADB_DEFRAGMENTATION_REQUIREMENT_PREPARED"
		}
	}
	canonical, err := marshalInput(MariaDBComponent, from, to, []inputFact{requirementFact, distributionFact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_EFFECTIVE_OPTION_FILE_NOT_LIVE_OBSERVATION",
			"COMPLETENESS_PRECEDENCE_UPSTREAM_DISTRIBUTION_AND_FEATURE_REQUIREMENT_ARE_CALLER_DECLARATIONS",
			"OPTION_PRESENCE_ABSENCE_AND_VALUE_DO_NOT_IMPLY_PRESERVATION_INTENT",
			"TARGET_ACCEPTS_THE_REMOVED_OPTION_AS_A_WARNING_ONLY_COMPATIBILITY_INPUT",
			"OTHER_MARIADB_CONFIGURATION_DATA_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// mariaDBOptionFileSupported admits only the reviewed literal option spelling in
// exact upstream server groups. Includes, group suffixes, case variants, and
// option aliases can change which setting is effective, so they remain
// UNKNOWN. Exact client groups are ignored because they are not server groups.
func mariaDBOptionFileSupported(raw []byte) (supported bool, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxInputBytes)
	serverGroupSeen, inServerGroup := false, false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if !utf8.ValidString(line) || mariaDBControlOrUnicodeSpace(line) {
			return false, nil
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "!") {
			return false, nil
		}
		if strings.HasPrefix(trimmed, "[") {
			closing := strings.IndexByte(trimmed, ']')
			if closing < 0 {
				return false, ErrInvalid
			}
			if closing != len(trimmed)-1 || len(trimmed) < 3 || strings.Count(trimmed, "[") != 1 || strings.Count(trimmed, "]") != 1 {
				return false, nil
			}
			group := trimmed[1 : len(trimmed)-1]
			switch group {
			case "mariadb", "mariadbd", "mysqld", "server":
				serverGroupSeen, inServerGroup = true, true
			case "client":
				inServerGroup = false
			default:
				// Without the target option parser and caller's group-suffix
				// invocation, other groups cannot prove effective absence.
				return false, nil
			}
			continue
		}
		if !inServerGroup {
			continue
		}
		key := trimmed
		if before, _, ok := strings.Cut(trimmed, "="); ok {
			key = strings.TrimSpace(before)
		} else if strings.ContainsAny(trimmed, " \t") {
			return false, nil
		}
		if key == mariaDBOptionName {
			if _, value, hasValue := strings.Cut(trimmed, "="); hasValue {
				switch strings.TrimSpace(value) {
				case "ON", "OFF", "1", "0":
				default:
					return false, nil
				}
			}
			continue
		}
		if mariaDBDefragmentAlias(key) {
			return false, nil
		}
	}
	if scanner.Err() != nil {
		return false, ErrInvalid
	}
	return serverGroupSeen, nil
}

const mariaDBOptionName = "innodb_defragment"

func mariaDBDefragmentAlias(key string) bool {
	if strings.EqualFold(key, mariaDBOptionName) && key != mariaDBOptionName {
		return true
	}
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	return normalized == mariaDBOptionName || strings.HasSuffix(normalized, "_"+mariaDBOptionName)
}

func mariaDBControlOrUnicodeSpace(s string) bool {
	for _, r := range s {
		if r == '\t' || unicode.IsControl(r) || unicode.IsSpace(r) && r != ' ' {
			return true
		}
	}
	return false
}

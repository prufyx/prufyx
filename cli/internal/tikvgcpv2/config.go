// SPDX-License-Identifier: AGPL-3.0-only

// Package tikvgcpv2 prepares a bounded TiKV planned-backup observation from
// one native TOML configuration supplied by the operator.
package tikvgcpv2

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/BurntSushi/toml"
)

const (
	ObservationSchema = "prufyx.io/tikv-gcp-v2-wif-backup-observation/v1"
	Component         = "pkg:github/tikv/tikv"
	CoveredTarget     = "tikv_8_5_8"
	UnsupportedTarget = "unsupported"
	ReviewedOperation = "gcs-full-backup-wif"
)

var (
	ErrInput    = errors.New("TiKV configuration input failed admission")
	versionRE   = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$`)
	operationRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

type Observation struct {
	Schema                      string `json:"schema"`
	Component                   string `json:"component"`
	TargetVersionClass          string `json:"targetVersionClass"`
	PlannedGCSFullBackupWithWIF bool   `json:"plannedGCSFullBackupWithWIF"`
	BackupGCPV2Enable           *bool  `json:"backupGCPV2Enable,omitempty"`
}

func MarshalObservation(observation Observation) ([]byte, error) {
	if observation.Schema != ObservationSchema || observation.Component != Component || (observation.TargetVersionClass != CoveredTarget && observation.TargetVersionClass != UnsupportedTarget) {
		return nil, ErrInput
	}
	return json.Marshal(observation)
}

func ClassifyTargetVersion(value string) (string, error) {
	if len(value) == 0 || len(value) > 20 || !versionRE.MatchString(value) {
		return "", ErrInput
	}
	if value == "8.5.8" {
		return CoveredTarget, nil
	}
	return UnsupportedTarget, nil
}

func ClassifyOperation(value string) (bool, error) {
	if !operationRE.MatchString(value) {
		return false, ErrInput
	}
	return value == ReviewedOperation, nil
}

func Prepare(raw []byte, targetVersion, operation string) (Observation, error) {
	class, err := ClassifyTargetVersion(targetVersion)
	if err != nil {
		return Observation{}, err
	}
	planned, err := ClassifyOperation(operation)
	if err != nil {
		return Observation{}, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return Observation{}, ErrInput
	}
	var document map[string]any
	if _, err = toml.Decode(string(raw), &document); err != nil {
		return Observation{}, ErrInput
	}
	o := Observation{Schema: ObservationSchema, Component: Component, TargetVersionClass: class, PlannedGCSFullBackupWithWIF: planned}
	backupValue, ok := document["backup"]
	if !ok {
		return o, nil
	}
	backup, ok := backupValue.(map[string]any)
	if !ok {
		return o, nil
	}
	kebab, hasKebab := backup["gcp-v2-enable"]
	underscore, hasUnderscore := backup["gcp_v2_enable"]
	if hasKebab == hasUnderscore {
		return o, nil
	}
	selected := kebab
	if hasUnderscore {
		selected = underscore
	}
	value, ok := selected.(bool)
	if !ok {
		return o, nil
	}
	o.BackupGCPV2Enable = &value
	return o, nil
}

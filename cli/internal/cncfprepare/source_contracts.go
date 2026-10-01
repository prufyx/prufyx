// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// These contracts bind the latest routes to reviewed official source bytes.
// They are metadata gates; they do not imply package execution or runtime proof.
//
//go:embed cloudcustodian_latest_source_contract.json
var cloudCustodianLatestSourceContract []byte

//go:embed opencost_latest_source_contract.json
var openCostLatestSourceContract []byte

const (
	CloudCustodianLatestSourceContractDigest = "sha256:8cf8827208bf83cb4e54020aa526a1f560bb88ac64fb11c75f28a6b843113fe7"
	OpenCostLatestSourceContractDigest       = "sha256:b97c9ab65cdcb4a4273ac19366110e9458c781198f436c03901753ae748994be"
)

func sourceContractDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package localcollector

import "errors"

func readKubeconfigForSnapshot(string) ([]byte, error) {
	return nil, errors.New("unsupported platform")
}

func createKubeconfigSnapshot([]byte) (string, func() error, error) {
	return "", nil, errors.New("unsupported platform")
}

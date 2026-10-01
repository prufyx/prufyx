// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package sourcecorpus

import "os"

func openRootDirectory() (*os.File, error)                     { return nil, errUnsupportedPlatform }
func openRelative(*os.File, string, int) (*os.File, error)     { return nil, errUnsupportedPlatform }
func openRelativeDirectory(*os.File, string) (*os.File, error) { return nil, errUnsupportedPlatform }
func duplicateFD(int) (int, error)                             { return -1, errUnsupportedPlatform }
func mkdirRelative(*os.File, string, uint32) error             { return errUnsupportedPlatform }
func createRelativeExclusive(*os.File, string, uint32) (*os.File, error) {
	return nil, errUnsupportedPlatform
}
func removeRelative(*os.File, string) error            { return errUnsupportedPlatform }
func removeDirRelative(*os.File, string) error         { return errUnsupportedPlatform }
func syncFile(*os.File) error                          { return errUnsupportedPlatform }
func platformFileState(os.FileInfo) (fileState, error) { return fileState{}, errUnsupportedPlatform }

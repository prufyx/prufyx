// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

// EmbeddedRulePack returns a copy of the rule pack bytes this build ships.
// It is a read-only accessor for reporting tools; it admits nothing and does
// not evaluate any rule.
func EmbeddedRulePack() ([]byte, error) {
	raw, err := packagedRulePack()
	if err != nil {
		return nil, ErrIntegrity
	}
	return append([]byte(nil), raw...), nil
}

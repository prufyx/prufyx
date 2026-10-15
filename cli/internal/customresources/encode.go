// SPDX-License-Identifier: AGPL-3.0-only

package customresources

// CanonicalTable returns the one spelling of table.json for a table: the
// spelling TestTableFileIsCanonical holds the embedded table to. A reader of
// a proposed table compares the file with it.
func CanonicalTable(projects []Project, reserved []ReservedGroup) ([]byte, error) {
	return encodeTable(projects, reserved)
}

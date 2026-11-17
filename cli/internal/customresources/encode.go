// SPDX-License-Identifier: AGPL-3.0-only

package customresources

// CanonicalTable returns the one spelling of table.json for a table: the
// spelling TestTableFileIsCanonical holds the embedded table to. A reader of
// a proposed table compares the file with it.
func CanonicalTable(projects []Project, reserved []ReservedGroup, unowned []UnownedGroup) ([]byte, error) {
	return encodeTable(projects, reserved, unowned)
}

// CanonicalLegacyTable is the canonical spelling of a table that has no
// unowned records, in the older form that omits the unowned member. A reader
// of an older base accepts it as an equal of the empty list; a table that
// is to be admitted is held to CanonicalTable.
func CanonicalLegacyTable(projects []Project, reserved []ReservedGroup) ([]byte, error) {
	return encodeLegacyTable(projects, reserved)
}

# Cited change-list suffixes across a major upgrade

`scan` and `plan` can explain a known minor change-list suffix even when the
preceding major transition is unreviewed. For example, an in-toto
`2.3.0` to `3.1.0` request can show an unresolved `2.3.0` to `3.0.0` prefix
followed by the cited `3.0.0` to `3.1.0` entry. The prefix remains
`UNDECIDED`; the cited entry is `ATTENTION`. The aggregate remains `UNKNOWN`
(exit 11 with the default scan exit policy).

This is a **partial listed-entry explanation**. It does not establish the
complete set of release lines, the last line of the old major, required
upgrade stops, compatibility, or runtime behavior. Both `LINES_NOT_LISTED`
and `MAJOR_HOP_NOT_COVERED` identify missing evidence and the next actions:
review each missing release line and read the upstream major-upgrade guide.
The plan does not turn the cited boundary identity into a required stop.

The first suffix anchor requires one current, fully validated, admitted
change-list record with one exact final From release and one exact final To
release, each pinned to a commit inside the request window. It covers only
the first minor line after the adjacent major boundary. Ambiguous identities,
conflicting commits, stale or malformed records, excluded evidence bases,
and explicit incompatible path policies do not authorize expansion. Calendar
and published-line version schemes and requests crossing multiple majors
retain the existing fallback. Later intermediate releases still require
matching release and commit identities in both adjacent line reviews.

Scan and plan human, Markdown and JSON output retain the cited suffix and
partial scope. Scan CSV and SARIF retain the partial scope and both missing
evidence actions in their existing gap output; they do not add a compatibility
decision or a new result category. No new input or collection is involved.

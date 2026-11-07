// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgepacket assembles the daily signing packet: for the range
// between the source commit of the last published knowledge revision and a
// candidate commit it lists every merged pull request, classifies it as data,
// non-data or trust-path, checks the exact-head gate and data-review markers
// the caller supplies, and computes the rule, attestation, project and README
// number deltas with git. It reads one local git repository and one input
// file. It performs no network operation, holds no token or key, signs
// nothing and changes nothing. Any input it cannot parse is an error and no
// packet is produced; a marker it cannot verify is listed as UNVERIFIED and is
// never omitted.
package knowledgepacket

// Schema identifiers.
const (
	PacketSchema = "prufyx.io/knowledge-packet/v1"
	InputSchema  = "prufyx.io/knowledge-packet-input/v2"
)

// Classes of a merged pull request.
const (
	ClassData      = "DATA"
	ClassNonData   = "NON-DATA"
	ClassTrustPath = "TRUST-PATH"
)

// Marker states.
const (
	Verified   = "VERIFIED"
	Unverified = "UNVERIFIED"
	NotChecked = "NOT-CHECKED"
)

// Input is the file the caller supplies: what a thin wrapper read from the
// code host. It is data only; this package never fetches it.
type Input struct {
	Schema string    `json:"schema"`
	PRs    []PRInput `json:"prs"`
}

// PRInput is one pull request as read from the code host.
type PRInput struct {
	Number   int       `json:"number"`
	Head     string    `json:"head"`
	Author   string    `json:"author"`
	Ref      string    `json:"ref"`
	Title    string    `json:"title"`
	Comments []Comment `json:"comments"`
	Statuses []Status  `json:"statuses"`
	Checks   []Check   `json:"checks"`
}

// Comment is one pull request comment. AuthorID is the numeric user id of
// the author (user.id), the only identity a marker is matched on; Author is
// the login, shown for humans and never trusted. CreatedAt and UpdatedAt are
// RFC 3339; a comment whose UpdatedAt differs from CreatedAt was edited.
type Comment struct {
	Author    string `json:"author"`
	AuthorID  int64  `json:"authorId"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	Body      string `json:"body"`
}

// Status is one commit status of the head commit.
type Status struct {
	ID      int64  `json:"id"`
	Context string `json:"context"`
	State   string `json:"state"`
	Creator string `json:"creator"`
	// CreatorID is the numeric user id of the creator; the login is never trusted.
	CreatorID int64 `json:"creatorId"`
}

// Check is one check run of the head commit, listed for information only.
type Check struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
}

// Options select the range and carry the input.
type Options struct {
	Repo             string
	Base             string
	Head             string
	PreviousRevision int
	Input            Input
	// TrustedUserIDs is the allow-list of numeric user ids whose markers
	// count. It must not be empty.
	TrustedUserIDs []int64
}

// Marker is the result of one marker check.
type Marker struct {
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
	Line   string `json:"line,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Entry is one merge commit of the range, in first-parent order.
type Entry struct {
	Number      int      `json:"number"`
	MergeCommit string   `json:"mergeCommit"`
	Head        string   `json:"head"`
	Author      string   `json:"author"`
	Ref         string   `json:"ref"`
	Title       string   `json:"title"`
	Class       string   `json:"class"`
	ClassReason string   `json:"classReason"`
	Files       []string `json:"files"`
	Gate        Marker   `json:"gate"`
	Review      Marker   `json:"review"`
	CI          []Check  `json:"ci"`
	Flags       []string `json:"flags"`
}

// PreviousRevision names the last published revision and its source commit.
type PreviousRevision struct {
	Revision     int    `json:"revision"`
	SourceCommit string `json:"sourceCommit"`
}

// RuleDelta is the change of one rule or attestation file.
type RuleDelta struct {
	Path    string   `json:"path"`
	Before  int      `json:"before"`
	After   int      `json:"after"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

// PathChange is one added, deleted or modified file under a data tree.
type PathChange struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

// ProjectDelta is the change of the project sets.
type ProjectDelta struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// ReadmeDelta is one README coverage-table row that differs.
type ReadmeDelta struct {
	Label    string `json:"label"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Decrease bool   `json:"decrease"`
}

// Deltas are the range-wide differences between base and head.
type Deltas struct {
	Rules     []RuleDelta   `json:"rules"`
	DataFiles []PathChange  `json:"dataFiles"`
	Projects  ProjectDelta  `json:"projects"`
	Readme    []ReadmeDelta `json:"readme"`
}

// Summary counts what an approver needs to see first.
type Summary struct {
	DataPRs       int `json:"dataPRs"`
	Verified      int `json:"verified"`
	Unverified    int `json:"unverified"`
	NonData       int `json:"nonData"`
	TrustPath     int `json:"trustPath"`
	DirectCommits int `json:"directCommits"`
	Decreases     int `json:"decreases"`
}

// Packet is the artifact. ContentDigest is the sha256 of the compact JSON of
// Entries; PacketDigest is the sha256 of the compact JSON of the packet with
// PacketDigest empty.
type Packet struct {
	Schema           string           `json:"schema"`
	SourceCommit     string           `json:"sourceCommit"`
	PreviousRevision PreviousRevision `json:"previousRevision"`
	Entries          []Entry          `json:"entries"`
	DirectCommits    []string         `json:"directCommits"`
	Deltas           Deltas           `json:"deltas"`
	Summary          Summary          `json:"summary"`
	ContentDigest    string           `json:"contentDigest"`
	PacketDigest     string           `json:"packetDigest,omitempty"`
}

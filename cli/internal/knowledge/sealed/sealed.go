// Package sealed holds the one type through which package target bytes reach
// a reader. Target has an unexported field, so no code outside this package
// can build one except through the constructors below, and each constructor
// performs the verification itself:
//
//   - Download asks the TUF updater to fetch the target, which checks signed
//     metadata, length and digest before returning bytes.
//   - Pinned re-checks stored bytes against a digest that was bound to the
//     selection when the package was verified and admitted.
//
// Admission functions, the minimum-client check and the index parser accept
// only Target, so reading unverified bytes fails to compile. This is a
// compile-time guarantee; there is no runtime test for "does not compile".
package sealed

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// ErrDigest reports that pinned bytes do not match their digest.
var ErrDigest = errors.New("sealed target digest mismatch")

// Target is target content authenticated by one of the constructors.
type Target struct{ raw []byte }

// Download fetches info through the TUF updater. The updater verifies the
// signed metadata, length and digest; on any failure no Target is returned.
func Download(u *updater.Updater, info *metadata.TargetFiles, filePath, baseURL string) (Target, error) {
	_, raw, err := u.DownloadTarget(info, filePath, baseURL)
	if err != nil {
		return Target{}, err
	}
	return Target{raw: append([]byte(nil), raw...)}, nil
}

// Pinned seals raw only when its sha256 equals digest ("sha256:<hex>").
func Pinned(raw []byte, digest string) (Target, error) {
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if !strings.HasPrefix(digest, "sha256:") || subtle.ConstantTimeCompare([]byte(want), []byte(digest)) != 1 {
		return Target{}, ErrDigest
	}
	return Target{raw: append([]byte(nil), raw...)}, nil
}

// Bytes returns a copy of the verified content.
func (t Target) Bytes() []byte { return append([]byte(nil), t.raw...) }

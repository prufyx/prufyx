// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// crdSetNoticeRule is a test-only set notice on a Strimzi chart hop over the
// custom-resource set. It is never published.
func crdSetNoticeRule(operator string) string {
	return `{"id":"strimzi.synthetic-set-notice.` + strings.ReplaceAll(operator, "_", "-") + `.0-51-0-to-1-0-0","operator":"` + operator + `",` +
		`"subject":{"component":"` + crdComponent + `","chart":{"source":"https://strimzi.io/charts","name":"strimzi-kafka-operator"},"from":"0.51.0","to":"1.0.0"},` +
		`"setCondition":{"side":"proposed","component":"` + crdComponent + `","factId":"` + crdSetFact + `","members":["kafka.strimzi.io/v1beta2/KafkaTopic"]},` +
		`"evidence":{"state":"active","reviewedAt":"` + currentReviewed + `","validUntil":"` + currentUntil + `","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRevision + `/install/cluster-operator/043-Crd-kafkatopic.yaml","revision":"` + crdRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"SYNTHETIC_SET_NOTICE","nextAction":"review KafkaTopic objects"}`
}

// A set notice in a project's rules is verdict-neutral in a scan: the scan
// does not fail, and exit, gaps, findings, passes and notices are those of
// the scan without it.
func TestScanSetNoticeIsNeutral(t *testing.T) {
	t.Parallel()
	for _, operator := range []string{constraintengine.OperatorNoticeSetMemberPresent, constraintengine.OperatorNoticeSetMemberAbsent} {
		rule, err := cncfcheck.NewScanRule("strimzi", "Synthetic set notice. Test only.", []byte(crdSetNoticeRule(operator)))
		if err != nil || !rule.Notice || !rule.SetNotice {
			t.Fatalf("%s: scan rule %+v %v", operator, rule, err)
		}
		for _, docs := range [][]string{{kafkaV1Doc, topicV1beta2Doc}, {kafkaV1beta2Doc, topicV1beta2Doc}} {
			for _, basis := range [][]string{nil, {"--require-basis", "mechanical"}, {"--require-basis", "reviewed,mechanical"}} {
				extra := append([]string{"--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete"}, basis...)
				plain := crdScan(t, newCRDKnowledge(t), docs, extra...)
				notice := crdScan(t, newCRDKnowledge(t, crdRule, crdSetNoticeRule(operator)), docs, extra...)
				if plain.Exit != notice.Exit || plain.Report.Verdict != notice.Report.Verdict ||
					strings.Join(gapReasons(plain.Report), ",") != strings.Join(gapReasons(notice.Report), ",") ||
					len(plain.Report.Findings) != len(notice.Report.Findings) || len(plain.Report.Passes) != len(notice.Report.Passes) ||
					len(plain.Report.Notices) != len(notice.Report.Notices) {
					t.Fatalf("%s changed the answer: exit %d/%d gaps %v / %v notices %+v", operator, plain.Exit, notice.Exit, gapReasons(plain.Report), gapReasons(notice.Report), notice.Report.Notices)
				}
			}
		}
	}
}

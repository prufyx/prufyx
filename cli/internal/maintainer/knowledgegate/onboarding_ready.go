// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

const onboardingReadySchema = "prufyx.io/onboarding-admission-ready/v1"
const maxOnboardingReadyBytes = maxOnboardingBytes + 4096

// OnboardingReadiness is preparation, not a signature or signing permission.
// It travels only on the dedicated supervisor pipe, never human stdout/stderr.
type OnboardingReadiness struct {
	Schema        string             `json:"schema"`
	KeyID         string             `json:"keyId"`
	Request       OnboardingRecordV2 `json:"request"`
	RequestDigest string             `json:"requestDigest"`
}

// OnboardingReadinessExpected names the supervisor's immutable request. The
// caller must authenticate the pipe's producer and refresh its existing live
// controls after decoding, before opening/feeding any private key.
type OnboardingReadinessExpected struct {
	BatchID     string
	CandidateID string
	KeyID       string
	Binding     OnboardingAdmissionBinding
	Projects    []OnboardingProject
	NotBefore   time.Time
	NotAfter    time.Time
}

func writeOnboardingReadiness(pipe *os.File, e OnboardingEnvelope) error {
	if pipe == nil || e.binding == nil {
		return errors.New("dedicated admission readiness pipe missing")
	}
	msg, err := signedOnboardingEnvelopeBytes(e)
	if err != nil {
		return err
	}
	frame := OnboardingReadiness{Schema: onboardingReadySchema, KeyID: e.KeyID, Request: OnboardingRecordV2{AdmissionBinding: *e.binding, OnboardingRecord: e.Record}, RequestDigest: CandidateDigest(msg)}
	raw, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > maxOnboardingReadyBytes {
		return errors.New("admission readiness frame too large")
	}
	if err := pipe.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	for len(raw) > 0 {
		n, err := pipe.Write(raw)
		if err != nil {
			return err
		}
		raw = raw[n:]
	}
	// EOF is part of the protocol: a supervisor refuses duplicate frames and
	// must finish parsing before it feeds the separate key-stdin pipe.
	return pipe.Close()
}

// ReadOnboardingReadiness accepts exactly one canonical JSON line followed by
// EOF, bounded by the batch limit. The supervisor owns the read deadline. This
// parser authenticates neither its writer nor live remote control values.
func ReadOnboardingReadiness(r io.Reader, want OnboardingReadinessExpected) (OnboardingReadiness, error) {
	var frame OnboardingReadiness
	raw, err := io.ReadAll(io.LimitReader(r, maxOnboardingReadyBytes+1))
	if err != nil || len(raw) > maxOnboardingReadyBytes || !bytes.HasSuffix(raw, []byte{'\n'}) {
		return frame, errors.New("incomplete or oversized admission readiness frame")
	}
	if err := strictDecode(raw[:len(raw)-1], &frame); err != nil {
		return frame, err
	}
	canonical, err := json.Marshal(frame)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return frame, errors.New("noncanonical or duplicate admission readiness framing")
	}
	if frame.Schema != onboardingReadySchema {
		return frame, errors.New("wrong admission readiness schema")
	}
	msg, err := SignedOnboardingV2Bytes(frame.Request)
	if err != nil {
		return frame, err
	}
	b := frame.Request.AdmissionBinding
	at, err := time.Parse(time.RFC3339, b.ObservedAt)
	if err != nil || want.NotBefore.IsZero() || want.NotAfter.Before(want.NotBefore) || at.Before(want.NotBefore) || at.After(want.NotAfter) {
		return frame, errors.New("admission readiness outside supervisor invocation window")
	}
	// Only decision time is generated during this invocation; all remaining
	// binding fields must match the supervisor's frozen request.
	b.ObservedAt = ""
	expected := want.Binding
	expected.ObservedAt = ""
	if frame.RequestDigest != CandidateDigest(msg) || frame.KeyID != want.KeyID || b.Profile.KeyID != want.KeyID ||
		frame.Request.BatchID != want.BatchID || frame.Request.CandidateID != want.CandidateID || !canonicalEqual(b, expected) ||
		want.Projects == nil || !canonicalEqual(frame.Request.Projects, want.Projects) {
		return frame, errors.New("admission readiness differs from immutable request")
	}
	return frame, nil
}

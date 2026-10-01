// SPDX-License-Identifier: AGPL-3.0-only

package spiffex509svid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestEmbeddedProfileAndClaims(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	one := "one"
	yes := true
	no := false
	cases := []struct {
		name           string
		o              Observation
		status, reason string
	}{
		{"ca", Observation{Schema: ObservationSchema, IsCA: true}, "UNKNOWN", "CERTIFICATE_NOT_PUBLIC_LEAF"},
		{"missing", Observation{Schema: ObservationSchema, URISANCardinality: strptr("zero")}, "FAIL", "SPIFFE_URI_SAN_MISSING"},
		{"multiple", Observation{Schema: ObservationSchema, URISANCardinality: strptr("multiple")}, "FAIL", "SPIFFE_URI_SAN_MULTIPLE"},
		{"other scheme", Observation{Schema: ObservationSchema, URISANCardinality: &one, URISANSchemeIsSPIFFE: &no}, "FAIL", "SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE"},
		{"root", Observation{Schema: ObservationSchema, URISANCardinality: &one, URISANSchemeIsSPIFFE: &yes, URISANPathIsNonRoot: &no}, "FAIL", "SPIFFE_ID_ROOT_PATH"},
		{"pass", Observation{Schema: ObservationSchema, URISANCardinality: &one, URISANSchemeIsSPIFFE: &yes, URISANPathIsNonRoot: &yes}, "PASS", "SPIFFE_PUBLIC_LEAF_URI_SAN_PROFILE_SATISFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Evaluate(p, tc.o, at)
			if c.Status != tc.status || c.ReasonCode != tc.reason {
				t.Fatalf("claim=%+v", c)
			}
		})
	}
}

func TestCertificateAdmissionAndURIShape(t *testing.T) {
	der := certificateDER(t, "spiffe://example.org/workload", false)
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	o := Observe(cert)
	if o.URISANPathIsNonRoot == nil || !*o.URISANPathIsNonRoot {
		t.Fatalf("observation=%+v", o)
	}
	pemRaw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemRaw = append(pemRaw, '\n', ' ', '\t')
	if _, err := ParseCertificate(pemRaw); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"der trailing":              append(append([]byte{}, der...), 0),
		"pem leading whitespace":    append([]byte(" \n"), pemRaw...),
		"two pem":                   append(append([]byte{}, pemRaw...), pemRaw...),
		"wrong block":               pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		"malformed block then cert": append([]byte("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"), pemRaw...),
	} {
		if _, err := ParseCertificate(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for name, u := range map[string]*url.URL{"query": {Scheme: "spiffe", Host: "example.org", Path: "/x", RawQuery: "a=b"}, "force query": {Scheme: "spiffe", Host: "example.org", Path: "/x", ForceQuery: true}, "fragment": {Scheme: "spiffe", Host: "example.org", Path: "/x", Fragment: "x"}, "userinfo": {Scheme: "spiffe", Host: "example.org", Path: "/x", User: url.User("x")}, "opaque": {Scheme: "spiffe", Opaque: "example.org/x"}, "raw path": {Scheme: "spiffe", Host: "example.org", Path: "/x", RawPath: "/%78"}} {
		t.Run(name, func(t *testing.T) {
			o := Observe(&x509.Certificate{URIs: []*url.URL{u}})
			if o.URISANCardinality == nil || *o.URISANCardinality != "one" || o.URISANSchemeIsSPIFFE != nil || o.URISANPathIsNonRoot != nil {
				t.Fatalf("observation=%+v", o)
			}
		})
	}
}

func TestEvidenceExpiryIsUnknown(t *testing.T) {
	p, err := ParseProfile(EmbeddedProfile())
	if err != nil {
		t.Fatal(err)
	}
	one := "one"
	yes := true
	claim := Evaluate(p, Observation{Schema: ObservationSchema, URISANCardinality: &one, URISANSchemeIsSPIFFE: &yes, URISANPathIsNonRoot: &yes}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if claim.Status != "UNKNOWN" || claim.ReasonCode != "PROFILE_EVIDENCE_EXPIRED" {
		t.Fatalf("claim=%+v", claim)
	}
}

func TestProfileRejectsAmbiguityAndBadSource(t *testing.T) {
	raw := EmbeddedProfile()
	for name, bad := range map[string][]byte{"duplicate": bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"1","revision":"1"`), 1), "case alias": bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"1","Revision":"1"`), 1), "wrong repo": bytes.Replace(raw, []byte(NormativeRepository), []byte("https://github.com/example/spiffe"), 1), "wrong digest": bytes.Replace(raw, []byte("sha256:a7dc"), []byte("sha256:b7dc"), 1), "trailing invalid token": append(append([]byte{}, raw...), 'x'), "trailing partial string": append(append([]byte{}, raw...), '"')} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProfile(bad); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func certificateDER(t *testing.T, uri string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private-canary.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func strptr(v string) *string { return &v }

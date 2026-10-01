// SPDX-License-Identifier: AGPL-3.0-only

package spiffex509svid

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
)

var ErrCertificateInput = errors.New("certificate input failed admission")

const ObservationSchema = "prufyx.io/spiffe-x509-svid-observation/v1"

var certificatePEMBegin = []byte("-----BEGIN CERTIFICATE-----")

type Observation struct {
	Schema               string  `json:"schema"`
	IsCA                 bool    `json:"component.spiffe.x509_svid.is_ca"`
	URISANCardinality    *string `json:"component.spiffe.x509_svid.uri_san_cardinality,omitempty"`
	URISANSchemeIsSPIFFE *bool   `json:"component.spiffe.x509_svid.uri_san_scheme_is_spiffe,omitempty"`
	URISANPathIsNonRoot  *bool   `json:"component.spiffe.x509_svid.uri_san_path_is_non_root,omitempty"`
}

func ParseCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrCertificateInput
	}
	der := raw
	if bytes.HasPrefix(raw, []byte("-----BEGIN")) {
		if !bytes.HasPrefix(raw, certificatePEMBegin) || bytes.Count(raw, []byte("-----BEGIN")) != 1 {
			return nil, ErrCertificateInput
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrCertificateInput
		}
		der = block.Bytes
	} else {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(raw, &value)
		if err != nil || len(rest) != 0 || !bytes.Equal(value.FullBytes, raw) {
			return nil, ErrCertificateInput
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrCertificateInput
	}
	return cert, nil
}

func Observe(cert *x509.Certificate) Observation {
	o := Observation{Schema: ObservationSchema}
	if cert == nil {
		return o
	}
	o.IsCA = cert.IsCA
	if cert.IsCA {
		return o
	}
	cardinality := "multiple"
	if len(cert.URIs) == 0 {
		cardinality = "zero"
	}
	if len(cert.URIs) == 1 {
		cardinality = "one"
	}
	o.URISANCardinality = &cardinality
	if len(cert.URIs) != 1 {
		return o
	}
	u := cert.URIs[0]
	if !limitedURI(u) {
		return o
	}
	scheme := u.Scheme == "spiffe"
	o.URISANSchemeIsSPIFFE = &scheme
	if scheme {
		nonRoot := u.Path != "" && u.Path != "/"
		o.URISANPathIsNonRoot = &nonRoot
	}
	return o
}

func limitedURI(u *url.URL) bool {
	if u == nil || u.Scheme == "" || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "" && u.Path[0] != '/' {
		return false
	}
	for i, c := range []byte(u.Scheme) {
		if !(c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' || i > 0 && (c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return true
}

func MarshalObservation(o Observation) ([]byte, error) {
	if o.Schema != ObservationSchema {
		return nil, ErrIntegrity
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func ObservationDigest(o Observation) (string, error) {
	raw, err := MarshalObservation(o)
	if err != nil {
		return "", err
	}
	return digestBytes(raw), nil
}

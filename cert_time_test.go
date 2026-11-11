// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestSelfSignedRSACertificate(t *testing.T) {
	key, err := GenerateRSAKeyWithExponent(2048, 65537)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Truncate(time.Second)
	after := before.Add(24 * time.Hour)
	cert, err := NewCertificateTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SetVersion(X509_V3); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetSerial(big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(before, after); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetPubKey(key); err != nil {
		t.Fatal(err)
	}
	name, err := cert.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SetIssuerName(name); err != nil {
		t.Fatal(err)
	}
	if err := cert.AddExtension(NID_basic_constraints, "critical,CA:FALSE"); err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(key, EVP_SHA256); err != nil {
		t.Fatal(err)
	}
	b, a, err := cert.Validity()
	if err != nil || !b.Equal(before) || !a.Equal(after) {
		t.Fatalf("validity: %v %v %v", b, a, err)
	}
	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 3 || parsed.SerialNumber.Int64() != 1 ||
		parsed.IsCA || !parsed.BasicConstraintsValid ||
		parsed.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("unexpected certificate fields: %+v", parsed)
	}
	public, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 2048 || public.E != 65537 {
		t.Fatal("unexpected RSA public key")
	}
	if err := parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature); err != nil {
		t.Fatal(err)
	}
	if err := cert.SetValidity(after, before); err == nil {
		t.Fatal("invalid validity accepted")
	}
	var nilCert *Certificate
	if err := nilCert.SetValidity(before, after); err == nil {
		t.Fatal("nil certificate accepted")
	}
}

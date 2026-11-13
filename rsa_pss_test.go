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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestRSAPSSSHA256Interoperability(t *testing.T) {
	goKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, err := LoadPrivateKeyFromDER(x509.MarshalPKCS1PrivateKey(goKey))
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&goKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := LoadPublicKeyFromDER(publicDER)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("RSA-PSS SHA-256 interoperability")
	signature, err := SignRSAPSSSHA256(private, message)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(&goKey.PublicKey, crypto.SHA256, digest[:], signature, opts); err != nil {
		t.Fatalf("Go verification of OpenSSL signature: %v", err)
	}
	if err := VerifyRSAPSSSHA256(public, message, signature); err != nil {
		t.Fatalf("OpenSSL verification of OpenSSL signature: %v", err)
	}

	goSignature, err := rsa.SignPSS(rand.Reader, goKey, crypto.SHA256, digest[:], opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRSAPSSSHA256(public, message, goSignature); err != nil {
		t.Fatalf("OpenSSL verification of Go signature: %v", err)
	}
}

func TestRSAPSSSHA256RejectsInvalidInputs(t *testing.T) {
	goKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, err := LoadPrivateKeyFromDER(x509.MarshalPKCS1PrivateKey(goKey))
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&goKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := LoadPublicKeyFromDER(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublicDER, err := x509.MarshalPKIXPublicKey(&wrongKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic, err := LoadPublicKeyFromDER(wrongPublicDER)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("RSA-PSS rejection test")
	signature, err := SignRSAPSSSHA256(private, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRSAPSSSHA256(public, []byte("different message"), signature); err == nil {
		t.Fatal("signature verified for a different message")
	}
	if err := VerifyRSAPSSSHA256(wrongPublic, message, signature); err == nil {
		t.Fatal("signature verified with a different key")
	}

	digest := sha256.Sum256(message)
	wrongSaltSignature, err := rsa.SignPSS(rand.Reader, goKey, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRSAPSSSHA256(public, message, wrongSaltSignature); err == nil {
		t.Fatal("signature with a non-SHA256 salt length was accepted")
	}

	pkcs1Signature, err := rsa.SignPKCS1v15(rand.Reader, goKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRSAPSSSHA256(public, message, pkcs1Signature); err == nil {
		t.Fatal("PKCS#1 v1.5 signature was accepted")
	}
	if err := VerifyRSAPSSSHA256(public, message, signature[:len(signature)-1]); err == nil {
		t.Fatal("malformed signature was accepted")
	}
	if err := VerifyRSAPSSSHA256(public, message, nil); err == nil {
		t.Fatal("nil signature was accepted")
	}
	if _, err := SignRSAPSSSHA256(nil, message); err == nil {
		t.Fatal("nil signing key was accepted")
	}
	if err := VerifyRSAPSSSHA256(nil, message, signature); err == nil {
		t.Fatal("nil verification key was accepted")
	}

	emptySignature, err := SignRSAPSSSHA256(private, nil)
	if err != nil {
		t.Fatalf("sign empty message: %v", err)
	}
	if err := VerifyRSAPSSSHA256(public, nil, emptySignature); err != nil {
		t.Fatalf("verify empty message: %v", err)
	}
}

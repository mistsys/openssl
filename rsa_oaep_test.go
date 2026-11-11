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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestRSAOAEPSHA256Interoperability(t *testing.T) {
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
	for _, plaintext := range [][]byte{nil, []byte("RSA-OAEP interoperability test")} {
		ciphertext, err := EncryptRSAOAEPSHA256(public, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, goKey, ciphertext, nil)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("Go decrypt: got %x, err %v", got, err)
		}

		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &goKey.PublicKey, plaintext, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err = DecryptRSAOAEPSHA256(private, ciphertext)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("OpenSSL decrypt: got %x, err %v", got, err)
		}
		ciphertext[len(ciphertext)-1] ^= 1
		if _, err := DecryptRSAOAEPSHA256(private, ciphertext); err == nil {
			t.Fatal("tampered ciphertext accepted")
		}
	}
	if _, err := EncryptRSAOAEPSHA256(nil, []byte("test")); err == nil {
		t.Fatal("nil key accepted")
	}
	if _, err := DecryptRSAOAEPSHA256(private, nil); err == nil {
		t.Fatal("empty ciphertext accepted")
	}
	if _, err := EncryptRSAOAEPSHA256(public, make([]byte, 191)); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
	wrongLabel, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &goKey.PublicKey, []byte("test"), []byte("label"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptRSAOAEPSHA256(private, wrongLabel); err == nil {
		t.Fatal("non-empty OAEP label accepted")
	}
	wrongKey, err := GenerateRSAKeyWithExponent(2048, 65537)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := EncryptRSAOAEPSHA256(public, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptRSAOAEPSHA256(wrongKey, ciphertext); err == nil {
		t.Fatal("wrong private key accepted")
	}
}

func TestRS256Interoperability(t *testing.T) {
	goKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, err := LoadPrivateKeyFromDER(x509.MarshalPKCS1PrivateKey(goKey))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GetDigestByName("SHA256", false)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("base64url-header.base64url-payload")
	hash := sha256.Sum256(message)
	sig, err := private.SignPKCS1v15(digest, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&goKey.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatal(err)
	}
	sig, err = rsa.SignPKCS1v15(rand.Reader, goKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := private.VerifyPKCS1v15(digest, message, sig); err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	if err := private.VerifyPKCS1v15(digest, message, sig); err == nil {
		t.Fatal("tampered RS256 signature accepted")
	}
}

func TestRandomBytes(t *testing.T) {
	var first, second [32]byte
	if err := RandomBytes(first[:]); err != nil {
		t.Fatal(err)
	}
	if err := RandomBytes(second[:]); err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two random outputs match")
	}
	if err := RandomBytes(nil); err != nil {
		t.Fatal(err)
	}
}

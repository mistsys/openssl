package openssl

import (
	"bytes"
	"testing"
)

func TestLoadCertificateFromDER(t *testing.T) {
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := cert.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCertificateFromDER(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, der) {
		t.Fatal("DER did not round trip")
	}
	for _, invalid := range [][]byte{
		nil, {}, {0}, []byte("not a certificate"), der[:len(der)-1],
		append(append([]byte{}, der...), 0),
		append(append([]byte{}, der...), der...),
	} {
		if cert, err := LoadCertificateFromDER(invalid); err == nil || cert != nil {
			t.Fatalf("accepted invalid DER (%d bytes): cert=%v err=%v", len(invalid), cert, err)
		}
		if _, err := LoadCertificateFromDER(der); err != nil {
			t.Fatalf("loading valid DER after rejection: %v", err)
		}
	}
}

package openssl

import (
	"errors"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCertificateVerify(t *testing.T) {
	// Certificate construction uses several thread-local error queue operations.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	serial := int64(0)
	makeCert := func(name string, ca bool, issuer *Certificate, key, signer PrivateKey, eku, san string, expires time.Duration) *Certificate {
		t.Helper()
		serial++
		cert, err := NewCertificate(&CertificateInfo{
			Serial: big.NewInt(serial), Issued: -time.Hour, Expires: expires,
			Country: "US", Organization: "Verify test", CommonName: name,
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.SetVersion(X509_V3); err != nil {
			t.Fatal(err)
		}
		if issuer != nil {
			if err := cert.SetIssuer(issuer); err != nil {
				t.Fatal(err)
			}
		}
		extensions := map[NID]string{
			NID_basic_constraints: "critical,CA:FALSE",
			NID_key_usage:         "critical,digitalSignature,keyEncipherment",
		}
		if ca {
			extensions[NID_basic_constraints] = "critical,CA:TRUE"
			extensions[NID_key_usage] = "critical,keyCertSign,cRLSign"
		}
		if eku != "" {
			extensions[NID_ext_key_usage] = eku
		}
		if san != "" {
			extensions[NID_subject_alt_name] = san
		}
		if err := cert.AddExtensions(extensions); err != nil {
			t.Fatal(err)
		}
		if err := cert.Sign(signer, EVP_SHA256); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	root := makeCert("Root", true, nil, caKey, caKey, "", "", 96*time.Hour)
	otherRoot := makeCert("Other root", true, nil, leafKey, leafKey, "", "", 96*time.Hour)
	intermediate := makeCert("Intermediate", true, root, caKey, caKey, "", "", 48*time.Hour)
	san := "DNS:service.example.test,DNS:*.example.test,IP:192.0.2.10,IP:2001:db8::10"
	server := makeCert("ignored.other.test", false, intermediate, leafKey, caKey, "serverAuth", san, 24*time.Hour)
	client := makeCert("Client", false, intermediate, leafKey, caKey, "clientAuth", "", 24*time.Hour)
	both := makeCert("Both", false, intermediate, leafKey, caKey, "clientAuth,serverAuth", san, 24*time.Hour)
	cnOnly := makeCert("service.example.test", false, intermediate, leafKey, caKey, "serverAuth", "", 24*time.Hour)
	badSignature := makeCert("Bad signature", false, intermediate, leafKey, leafKey, "serverAuth", san, 24*time.Hour)
	notCA := makeCert("Not a CA", false, root, caKey, caKey, "", "", 48*time.Hour)
	invalidChain := makeCert("Invalid CA chain", false, notCA, leafKey, caKey, "serverAuth", san, 24*time.Hour)

	base := CertificateVerifyOptions{
		Roots: []*Certificate{root}, Intermediates: []*Certificate{intermediate},
		CurrentTime: now, Purpose: CertificatePurposeSSLServer,
	}
	tests := []struct {
		name   string
		cert   *Certificate
		change func(*CertificateVerifyOptions)
		code   VerifyResult
	}{
		{name: "trusted server", cert: server},
		{name: "unrestricted purpose", cert: client, change: func(o *CertificateVerifyOptions) { o.Purpose = CertificatePurposeAny }},
		{name: "trusted client", cert: client, change: func(o *CertificateVerifyOptions) { o.Purpose = CertificatePurposeSSLClient }},
		{name: "server cannot authenticate client", cert: server, change: func(o *CertificateVerifyOptions) { o.Purpose = CertificatePurposeSSLClient }, code: InvalidPurpose},
		{name: "client cannot authenticate server", cert: client, code: InvalidPurpose},
		{name: "both purposes server", cert: both},
		{name: "both purposes client", cert: both, change: func(o *CertificateVerifyOptions) { o.Purpose = CertificatePurposeSSLClient }},
		{name: "no implicit system roots", cert: server, change: func(o *CertificateVerifyOptions) { o.Roots = nil }, code: UnableToGetIssuerCertLocally},
		{name: "unrelated trust", cert: server, change: func(o *CertificateVerifyOptions) { o.Roots = []*Certificate{otherRoot} }, code: UnableToGetIssuerCertLocally},
		{name: "missing intermediate", cert: server, change: func(o *CertificateVerifyOptions) { o.Intermediates = nil }, code: UnableToGetIssuerCertLocally},
		{name: "intermediates are not trusted", cert: server, change: func(o *CertificateVerifyOptions) {
			o.Roots = nil
			o.Intermediates = []*Certificate{intermediate, root}
		}, code: SelfSignedCertInChain},
		{name: "expired at explicit time", cert: server, change: func(o *CertificateVerifyOptions) { o.CurrentTime = now.Add(25 * time.Hour) }, code: CertHasExpired},
		{name: "not yet valid at explicit time", cert: server, change: func(o *CertificateVerifyOptions) { o.CurrentTime = now.Add(-2 * time.Hour) }, code: CertNotYetValid},
		{name: "invalid signature", cert: badSignature, code: CertSignatureFailure},
		{name: "issuer is not a CA", cert: invalidChain, change: func(o *CertificateVerifyOptions) { o.Intermediates = []*Certificate{notCA} }, code: InvalidCa},
		{name: "DNS SAN", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "service.example.test" }},
		{name: "wildcard DNS SAN", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "other.example.test" }},
		{name: "DNS mismatch", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "outside.invalid" }, code: HostnameMismatch},
		{name: "wildcard cannot span labels", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "a.b.example.test" }, code: HostnameMismatch},
		{name: "CN does not override SAN", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "ignored.other.test" }, code: HostnameMismatch},
		{name: "CN fallback disabled", cert: cnOnly, change: func(o *CertificateVerifyOptions) { o.DNSName = "service.example.test" }, code: HostnameMismatch},
		{name: "IPv4 SAN", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "192.0.2.10" }},
		{name: "IPv6 SAN", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "2001:db8::10" }},
		{name: "IPv4 mismatch", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "192.0.2.11" }, code: IPAddressMismatch},
		{name: "IPv6 mismatch", cert: server, change: func(o *CertificateVerifyOptions) { o.DNSName = "2001:db8::11" }, code: IPAddressMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := base
			if tt.change != nil {
				tt.change(&opts)
			}
			err := tt.cert.Verify(opts)
			if tt.code == Ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var verificationErr *CertificateVerificationError
			if !errors.As(err, &verificationErr) {
				t.Fatalf("expected verification error %d, got %v", tt.code, err)
			}
			if verificationErr.Code != tt.code || verificationErr.Depth < 0 || verificationErr.Reason == "" {
				t.Fatalf("unexpected verification error: %+v", verificationErr)
			}
			if !strings.Contains(err.Error(), verificationErr.Reason) {
				t.Fatalf("error omits OpenSSL reason: %v", err)
			}
			if tt.code == CertHasExpired && verificationErr.Depth != 0 {
				t.Fatalf("expected expired leaf depth 0, got %d", verificationErr.Depth)
			}
			// A rejection must not poison the thread's next OpenSSL operation.
			if err := server.Verify(base); err != nil {
				t.Fatalf("verification after rejection: %v", err)
			}
		})
	}
	t.Run("DER-loaded chain", func(t *testing.T) {
		loadDER := func(cert *Certificate) *Certificate {
			t.Helper()
			der, err := cert.MarshalDER()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadCertificateFromDER(der)
			if err != nil {
				t.Fatal(err)
			}
			return loaded
		}
		opts := base
		opts.Roots = []*Certificate{loadDER(root)}
		opts.Intermediates = []*Certificate{loadDER(intermediate)}
		opts.DNSName = "service.example.test"
		if err := loadDER(server).Verify(opts); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid options", func(t *testing.T) {
		cases := []struct {
			cert *Certificate
			opts CertificateVerifyOptions
		}{
			{nil, base}, {&Certificate{}, base},
		}
		for _, change := range []func(*CertificateVerifyOptions){
			func(o *CertificateVerifyOptions) { o.CurrentTime = time.Time{} },
			func(o *CertificateVerifyOptions) { o.Purpose = 0 },
			func(o *CertificateVerifyOptions) { o.Purpose = -1 },
			func(o *CertificateVerifyOptions) { o.DNSName = "service.example.test\x00.invalid" },
			func(o *CertificateVerifyOptions) { o.Roots = []*Certificate{nil} },
			func(o *CertificateVerifyOptions) { o.Intermediates = []*Certificate{{}} },
		} {
			opts := base
			change(&opts)
			cases = append(cases, struct {
				cert *Certificate
				opts CertificateVerifyOptions
			}{server, opts})
		}
		for i, tc := range cases {
			err := tc.cert.Verify(tc.opts)
			var verificationErr *CertificateVerificationError
			if err == nil || errors.As(err, &verificationErr) {
				t.Fatalf("case %d: expected option error, got %v", i, err)
			}
		}
	})
	t.Run("concurrent independent contexts", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					if err := server.Verify(base); err != nil {
						t.Error(err)
					}
				}
			}()
		}
		wg.Wait()
	})
}

# Offline X.509 chain verification

`(*Certificate).Verify(CertificateVerifyOptions) error` runs OpenSSL's
`X509_verify_cert`, without a TLS handshake or Go's certificate verifier.

```go
err := leaf.Verify(openssl.CertificateVerifyOptions{
    Roots:         []*openssl.Certificate{root},
    Intermediates: []*openssl.Certificate{intermediate},
    CurrentTime:   time.Now(),
    Purpose:       openssl.CertificatePurposeSSLServer,
    DNSName:       "router.example.com",
})
var rejected *openssl.CertificateVerificationError
if errors.As(err, &rejected) {
    // Code is an openssl.VerifyResult; Depth 0 means the leaf.
    log.Printf("verification: code=%d depth=%d reason=%s",
        rejected.Code, rejected.Depth, rejected.Reason)
}
```

Certificates can be loaded with `LoadCertificateFromPEM` or the new
`LoadCertificateFromDER` API. DER loading requires exactly one certificate and
rejects trailing data, including concatenated certificates.
Roots are the **only** trust anchors; an empty root set fails closed.
Intermediates are untrusted candidates. The call creates a fresh store and
context; it does not change existing certificate stores or TLS contexts.
`PartialChain` may be enabled to terminate a chain at an explicitly trusted
non-self-signed certificate. TLS stores provide the same opt-in through
`CertificateStore.SetPartialChain`.

`CurrentTime` and `Purpose` are required. Time is checked at whole Unix-second
precision. Select `CertificatePurposeSSLClient` for client authentication,
`CertificatePurposeSSLServer` for server authentication, or explicitly select
`CertificatePurposeAny` to omit the TLS extended-key-usage check.

`DNSName` is optional and accepts DNS names or unbracketed IPv4/IPv6 literals
(not URLs, ports, or IPv6 zone identifiers). DNS verification requires a SAN;
there is no common-name fallback. OpenSSL wildcard matching is used, with
partial-label wildcards disabled. IP literals must match an IP SAN.
`HostnameMismatch` and `IPAddressMismatch` are verification result codes.

Validation failures return `*CertificateVerificationError`; invalid options
and internal failures return other errors. Verification does not load system
trust, fetch missing intermediates, perform CRL/OCSP revocation checks, or return
the constructed chain. OpenSSL's installed providers and security policy apply.
Certificates and option slices must not be mutated concurrently with verification.

Run the focused tests with:

```sh
go test -run '^(TestCertificateVerify|TestLoadCertificateFromDER)$' .
go test -race -run '^(TestCertificateVerify|TestLoadCertificateFromDER)$' .
```

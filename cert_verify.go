package openssl

/*
#include "shim.h"

static STACK_OF(X509) *verify_chain_new(void) {
	return sk_X509_new_null();
}

static int verify_chain_push(STACK_OF(X509) *chain, X509 *cert) {
	return sk_X509_push(chain, cert);
}

static void verify_chain_free(STACK_OF(X509) *chain) {
	sk_X509_free(chain);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// CertificatePurpose selects the intended use checked by OpenSSL.
type CertificatePurpose int

const (
	// CertificatePurposeAny performs chain validation without a TLS EKU check.
	CertificatePurposeAny CertificatePurpose = C.X509_PURPOSE_ANY
	// CertificatePurposeSSLClient checks suitability for TLS client authentication.
	CertificatePurposeSSLClient CertificatePurpose = C.X509_PURPOSE_SSL_CLIENT
	// CertificatePurposeSSLServer checks suitability for TLS server authentication.
	CertificatePurposeSSLServer CertificatePurpose = C.X509_PURPOSE_SSL_SERVER
)

// Identity failures returned in CertificateVerificationError.Code.
const (
	HostnameMismatch  VerifyResult = C.X509_V_ERR_HOSTNAME_MISMATCH
	IPAddressMismatch VerifyResult = C.X509_V_ERR_IP_ADDRESS_MISMATCH
)

// CertificateVerifyOptions configures offline OpenSSL certificate verification.
// Roots are the only trust anchors; system trust is never loaded. Intermediates
// are untrusted chain-building candidates and are not promoted to trust anchors.
// Certificates and slices must not be mutated concurrently with Verify.
type CertificateVerifyOptions struct {
	Roots         []*Certificate
	Intermediates []*Certificate
	// PartialChain permits an explicitly trusted non-self-signed certificate
	// to terminate the chain.
	PartialChain bool
	// CurrentTime is required, is evaluated to whole Unix seconds, and applies
	// to every certificate in the chain. A zero time is rejected.
	CurrentTime time.Time
	// Purpose is required; choose CertificatePurposeAny to omit TLS EKU checks.
	Purpose CertificatePurpose
	// DNSName optionally checks a DNS name or literal IPv4/IPv6 address.
	// DNS identities require a subjectAltName; common-name fallback is disabled.
	// Wildcards follow OpenSSL's rules, with partial-label wildcards disabled.
	DNSName string
}

// CertificateVerificationError reports an OpenSSL X509_V_ERR_* validation
// failure. Code uses the existing VerifyResult constants; Depth is zero for
// the leaf. Reason is OpenSSL's human-readable description.
type CertificateVerificationError struct {
	Code   VerifyResult
	Depth  int
	Reason string
}

func (e *CertificateVerificationError) Error() string {
	return fmt.Sprintf("openssl: certificate verification failed at depth %d: %s (code %d)",
		e.Depth, e.Reason, e.Code)
}

// Verify verifies c using X509_verify_cert, independently of any TLS context.
// It returns nil on success, *CertificateVerificationError for a rejected
// certificate chain or identity, and another error for invalid options or
// internal failures. It does not fetch intermediates, CRLs, or OCSP responses.
func (c *Certificate) Verify(opts CertificateVerifyOptions) error {
	if c == nil || c.x == nil {
		return errors.New("openssl: missing leaf certificate")
	}
	if opts.CurrentTime.IsZero() {
		return errors.New("openssl: verification time is required")
	}
	switch opts.Purpose {
	case CertificatePurposeAny, CertificatePurposeSSLClient, CertificatePurposeSSLServer:
	default:
		return errors.New("openssl: unsupported certificate verification purpose")
	}
	if strings.IndexByte(opts.DNSName, 0) >= 0 {
		return errors.New("openssl: certificate identity contains NUL")
	}
	when := C.time_t(opts.CurrentTime.Unix())
	if int64(when) != opts.CurrentTime.Unix() {
		return errors.New("openssl: verification time is outside time_t range")
	}
	for _, certs := range [][]*Certificate{opts.Roots, opts.Intermediates} {
		for _, cert := range certs {
			if cert == nil || cert.x == nil {
				return errors.New("openssl: nil certificate in roots or intermediates")
			}
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("openssl: verifying certificate: %w", err)
	}
	defer C.ERR_clear_error()
	defer runtime.KeepAlive(c)
	defer runtime.KeepAlive(opts)

	store := C.X509_STORE_new()
	if store == nil {
		return fmt.Errorf("openssl: creating verification store: %w", errorFromErrorQueue())
	}
	defer C.X509_STORE_free(store)
	for _, root := range opts.Roots {
		if C.X509_STORE_add_cert(store, root.x) != 1 {
			return fmt.Errorf("openssl: adding trust anchor: %w", errorFromErrorQueue())
		}
	}

	chain := C.verify_chain_new()
	if chain == nil {
		return fmt.Errorf("openssl: creating intermediate stack: %w", errorFromErrorQueue())
	}
	defer C.verify_chain_free(chain)
	for _, intermediate := range opts.Intermediates {
		if C.verify_chain_push(chain, intermediate.x) <= 0 {
			return fmt.Errorf("openssl: adding intermediate: %w", errorFromErrorQueue())
		}
	}

	ctx := C.X509_STORE_CTX_new()
	if ctx == nil {
		return fmt.Errorf("openssl: creating verification context: %w", errorFromErrorQueue())
	}
	defer C.X509_STORE_CTX_free(ctx)
	if C.X509_STORE_CTX_init(ctx, store, c.x, chain) != 1 {
		return fmt.Errorf("openssl: initializing verification context: %w", errorFromErrorQueue())
	}
	if C.X509_STORE_CTX_set_purpose(ctx, C.int(opts.Purpose)) != 1 {
		return fmt.Errorf("openssl: setting verification purpose: %w", errorFromErrorQueue())
	}
	param := C.X509_STORE_CTX_get0_param(ctx)
	C.X509_VERIFY_PARAM_set_time(param, when)
	if opts.PartialChain && C.X509_VERIFY_PARAM_set_flags(param, C.X509_V_FLAG_PARTIAL_CHAIN) != 1 {
		return fmt.Errorf("openssl: setting partial-chain verification: %w", errorFromErrorQueue())
	}
	if opts.DNSName != "" {
		identity := C.CString(opts.DNSName)
		defer C.free(unsafe.Pointer(identity))
		var ok C.int
		if net.ParseIP(opts.DNSName) != nil {
			ok = C.X509_VERIFY_PARAM_set1_ip_asc(param, identity)
		} else {
			C.X509_VERIFY_PARAM_set_hostflags(param,
				C.X509_CHECK_FLAG_NEVER_CHECK_SUBJECT|C.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS)
			ok = C.X509_VERIFY_PARAM_set1_host(param, identity, C.size_t(len(opts.DNSName)))
		}
		if ok != 1 {
			return fmt.Errorf("openssl: setting verification identity: %w", errorFromErrorQueue())
		}
	}
	result := C.X509_verify_cert(ctx)
	if result == 1 {
		return nil
	}
	if result < 0 {
		return fmt.Errorf("openssl: certificate verification internal failure: %w", errorFromErrorQueue())
	}
	code := C.X509_STORE_CTX_get_error(ctx)
	return &CertificateVerificationError{
		Code:   VerifyResult(code),
		Depth:  int(C.X509_STORE_CTX_get_error_depth(ctx)),
		Reason: C.GoString(C.X509_verify_cert_error_string(C.long(code))),
	}
}

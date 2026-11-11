package openssl

/*
#include "shim.h"

static X509 *decode_certificate_der(const unsigned char *data, long len) {
	const unsigned char *next = data;
	X509 *cert = d2i_X509(NULL, &next, len);
	if (cert != NULL && next != data + len) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
)

// LoadCertificateFromDER loads exactly one DER-encoded X.509 certificate.
// Empty, malformed, truncated, and trailing data are rejected.
func LoadCertificateFromDER(der []byte) (*Certificate, error) {
	if len(der) == 0 {
		return nil, errors.New("openssl: empty certificate DER")
	}
	length := C.long(len(der))
	if int64(length) != int64(len(der)) {
		return nil, errors.New("openssl: certificate DER is too large")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("openssl: loading certificate DER: %w", err)
	}
	defer C.ERR_clear_error()
	data := C.CBytes(der)
	defer C.free(data)
	x := C.decode_certificate_der((*C.uchar)(data), length)
	if x == nil {
		return nil, fmt.Errorf("openssl: invalid certificate DER: %w", errorFromErrorQueue())
	}
	cert := &Certificate{x: x}
	runtime.SetFinalizer(cert, func(cert *Certificate) {
		C.X509_free(cert.x)
	})
	return cert, nil
}

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

/*
#include <openssl/x509.h>
#include <time.h>

static int cert_validity_parts(const ASN1_TIME *value, struct tm *result) {
	return value != NULL && ASN1_TIME_to_tm(value, result);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

// NewCertificateTemplate creates an empty, unsigned certificate. Callers must
// set its fields and sign it before using it.
func NewCertificateTemplate() (*Certificate, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("certificate template: %w", err)
	}
	x := C.X509_new()
	if x == nil {
		return nil, fmt.Errorf("certificate template: create: %w", errorFromErrorQueue())
	}
	cert := &Certificate{x: x}
	runtime.SetFinalizer(cert, func(c *Certificate) { C.X509_free(c.x) })
	return cert, nil
}

// SetValidity sets the certificate's absolute validity interval, to the
// nearest whole second. Times are encoded in UTC.
func (c *Certificate) SetValidity(notBefore, notAfter time.Time) error {
	if c == nil || c.x == nil {
		return errors.New("certificate validity: certificate is nil")
	}
	if notAfter.Unix() <= notBefore.Unix() ||
		int64(C.time_t(notBefore.Unix())) != notBefore.Unix() ||
		int64(C.time_t(notAfter.Unix())) != notAfter.Unix() {
		return errors.New("certificate validity: invalid interval")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer runtime.KeepAlive(c)
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("certificate validity: %w", err)
	}
	if C.ASN1_TIME_set(C.X509_getm_notBefore(c.x), C.time_t(notBefore.Unix())) == nil ||
		C.ASN1_TIME_set(C.X509_getm_notAfter(c.x), C.time_t(notAfter.Unix())) == nil {
		return fmt.Errorf("certificate validity: set: %w", errorFromErrorQueue())
	}
	return nil
}

// Validity returns the certificate's inclusive not-before and not-after times.
func (c *Certificate) Validity() (time.Time, time.Time, error) {
	if c == nil || c.x == nil {
		return time.Time{}, time.Time{}, errors.New("certificate validity: certificate is nil")
	}
	var before, after C.struct_tm
	if C.cert_validity_parts(C.X509_get0_notBefore(c.x), &before) != 1 ||
		C.cert_validity_parts(C.X509_get0_notAfter(c.x), &after) != 1 {
		runtime.KeepAlive(c)
		return time.Time{}, time.Time{}, errors.New("certificate validity: invalid ASN.1 time")
	}
	runtime.KeepAlive(c)
	toTime := func(t C.struct_tm) time.Time {
		return time.Date(int(t.tm_year)+1900, time.Month(int(t.tm_mon)+1), int(t.tm_mday),
			int(t.tm_hour), int(t.tm_min), int(t.tm_sec), 0, time.UTC)
	}
	return toTime(before), toTime(after), nil
}

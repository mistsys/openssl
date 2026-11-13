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
#include <openssl/evp.h>
#include <openssl/rsa.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// SignRSAPSSSHA256 signs message with RSA-PSS, SHA-256, MGF1-SHA-256 and a
// salt whose length is exactly the SHA-256 digest size.
func SignRSAPSSSHA256(key PrivateKey, message []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("RSA-PSS: key is nil")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer runtime.KeepAlive(key)
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("RSA-PSS: %w", err)
	}
	if key.KeyType() != KeyTypeRSA && key.KeyType() != KeyTypeRSAPSS {
		return nil, errors.New("RSA-PSS: key is not RSA")
	}

	digestName := C.CString("SHA256")
	defer C.free(unsafe.Pointer(digestName))
	digest := C.EVP_MD_fetch(nil, digestName, nil)
	if digest == nil {
		return nil, fmt.Errorf("RSA-PSS: fetch SHA256 digest: %w", errorFromErrorQueue())
	}
	defer C.EVP_MD_free(digest)
	if C.EVP_MD_get_size(digest) != 32 {
		return nil, errors.New("RSA-PSS: unexpected SHA256 digest size")
	}

	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("RSA-PSS: create context: %w", errorFromErrorQueue())
	}
	defer C.EVP_MD_CTX_free(ctx)

	var pkeyCtx *C.EVP_PKEY_CTX
	if C.EVP_DigestSignInit(ctx, &pkeyCtx, digest, nil, key.evpPKey()) != 1 {
		return nil, fmt.Errorf("RSA-PSS: initialize signing: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, C.RSA_PKCS1_PSS_PADDING) != 1 {
		return nil, fmt.Errorf("RSA-PSS: set padding: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_mgf1_md_name(pkeyCtx, digestName, nil) != 1 {
		return nil, fmt.Errorf("RSA-PSS: set MGF1 digest: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, 32) != 1 {
		return nil, fmt.Errorf("RSA-PSS: set salt length: %w", errorFromErrorQueue())
	}

	var data *C.uchar
	if len(message) != 0 {
		data = (*C.uchar)(unsafe.Pointer(&message[0]))
	}
	if C.EVP_DigestSignUpdate(ctx, unsafe.Pointer(data), C.size_t(len(message))) != 1 {
		return nil, fmt.Errorf("RSA-PSS: hash message: %w", errorFromErrorQueue())
	}

	var signatureLen C.size_t
	if C.EVP_DigestSignFinal(ctx, nil, &signatureLen) != 1 {
		return nil, fmt.Errorf("RSA-PSS: size signature: %w", errorFromErrorQueue())
	}
	if signatureLen == 0 || uint64(signatureLen) > uint64(^uint(0)>>1) {
		return nil, errors.New("RSA-PSS: invalid signature size")
	}
	signature := make([]byte, int(signatureLen))
	if C.EVP_DigestSignFinal(ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), &signatureLen) != 1 {
		return nil, fmt.Errorf("RSA-PSS: sign message: %w", errorFromErrorQueue())
	}
	return signature[:int(signatureLen)], nil
}

// VerifyRSAPSSSHA256 verifies a SHA-256 RSA-PSS signature with MGF1-SHA-256
// and a salt whose length is exactly the SHA-256 digest size.
func VerifyRSAPSSSHA256(key PublicKey, message, signature []byte) error {
	if key == nil {
		return errors.New("RSA-PSS: key is nil")
	}
	if len(signature) == 0 {
		return errors.New("RSA-PSS: signature is empty")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer runtime.KeepAlive(key)
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("RSA-PSS: %w", err)
	}
	if key.KeyType() != KeyTypeRSA && key.KeyType() != KeyTypeRSAPSS {
		return errors.New("RSA-PSS: key is not RSA")
	}
	if len(signature) != key.Size() {
		return errors.New("RSA-PSS: signature has invalid size")
	}

	digestName := C.CString("SHA256")
	defer C.free(unsafe.Pointer(digestName))
	digest := C.EVP_MD_fetch(nil, digestName, nil)
	if digest == nil {
		return fmt.Errorf("RSA-PSS: fetch SHA256 digest: %w", errorFromErrorQueue())
	}
	defer C.EVP_MD_free(digest)
	if C.EVP_MD_get_size(digest) != 32 {
		return errors.New("RSA-PSS: unexpected SHA256 digest size")
	}

	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		return fmt.Errorf("RSA-PSS: create context: %w", errorFromErrorQueue())
	}
	defer C.EVP_MD_CTX_free(ctx)

	var pkeyCtx *C.EVP_PKEY_CTX
	if C.EVP_DigestVerifyInit(ctx, &pkeyCtx, digest, nil, key.evpPKey()) != 1 {
		return fmt.Errorf("RSA-PSS: initialize verification: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, C.RSA_PKCS1_PSS_PADDING) != 1 {
		return fmt.Errorf("RSA-PSS: set padding: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_mgf1_md_name(pkeyCtx, digestName, nil) != 1 {
		return fmt.Errorf("RSA-PSS: set MGF1 digest: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, 32) != 1 {
		return fmt.Errorf("RSA-PSS: set salt length: %w", errorFromErrorQueue())
	}

	var data *C.uchar
	if len(message) != 0 {
		data = (*C.uchar)(unsafe.Pointer(&message[0]))
	}
	if C.EVP_DigestVerifyUpdate(ctx, unsafe.Pointer(data), C.size_t(len(message))) != 1 {
		return fmt.Errorf("RSA-PSS: hash message: %w", errorFromErrorQueue())
	}
	if C.EVP_DigestVerifyFinal(
		ctx,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
	) != 1 {
		return fmt.Errorf("RSA-PSS: verify signature: %w", errorFromErrorQueue())
	}
	return nil
}

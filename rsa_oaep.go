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

// EncryptRSAOAEPSHA256 encrypts plaintext with RSA-OAEP, SHA-256,
// MGF1-SHA-256 and an empty label.
func EncryptRSAOAEPSHA256(key PublicKey, plaintext []byte) ([]byte, error) {
	return rsaOAEPSHA256(key, plaintext, true)
}

// DecryptRSAOAEPSHA256 decrypts ciphertext using RSA-OAEP with SHA-256,
// MGF1-SHA-256 and an empty label. The private key must support decryption.
func DecryptRSAOAEPSHA256(key PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsaOAEPSHA256(key, ciphertext, false)
}

func rsaOAEPSHA256(key PublicKey, input []byte, encrypt bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("RSA-OAEP: key is nil")
	}
	if key.KeyType() != KeyTypeRSA {
		return nil, errors.New("RSA-OAEP: key is not RSA")
	}
	if !encrypt && len(input) == 0 {
		return nil, errors.New("RSA-OAEP: ciphertext is empty")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("RSA-OAEP: %w", err)
	}
	ctx := C.EVP_PKEY_CTX_new_from_pkey(nil, key.evpPKey(), nil)
	if ctx == nil {
		return nil, fmt.Errorf("RSA-OAEP: create context: %w", errorFromErrorQueue())
	}
	defer C.EVP_PKEY_CTX_free(ctx)
	defer runtime.KeepAlive(key)

	var rc C.int
	if encrypt {
		rc = C.EVP_PKEY_encrypt_init(ctx)
	} else {
		rc = C.EVP_PKEY_decrypt_init(ctx)
	}
	if rc != 1 {
		return nil, fmt.Errorf("RSA-OAEP: initialize: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING) != 1 {
		return nil, fmt.Errorf("RSA-OAEP: set padding: %w", errorFromErrorQueue())
	}
	digest := C.CString("SHA256")
	defer C.free(unsafe.Pointer(digest))
	if C.EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, digest, nil) != 1 {
		return nil, fmt.Errorf("RSA-OAEP: set digest: %w", errorFromErrorQueue())
	}
	if C.EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, digest, nil) != 1 {
		return nil, fmt.Errorf("RSA-OAEP: set MGF1 digest: %w", errorFromErrorQueue())
	}

	var in *C.uchar
	if len(input) != 0 {
		in = (*C.uchar)(unsafe.Pointer(&input[0]))
	}
	var outLen C.size_t
	if encrypt {
		rc = C.EVP_PKEY_encrypt(ctx, nil, &outLen, in, C.size_t(len(input)))
	} else {
		rc = C.EVP_PKEY_decrypt(ctx, nil, &outLen, in, C.size_t(len(input)))
	}
	if rc != 1 {
		return nil, fmt.Errorf("RSA-OAEP: size output: %w", errorFromErrorQueue())
	}
	if outLen == 0 || uint64(outLen) > uint64(^uint(0)>>1) {
		return nil, errors.New("RSA-OAEP: invalid output size")
	}
	out := make([]byte, int(outLen))
	if encrypt {
		rc = C.EVP_PKEY_encrypt(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen, in, C.size_t(len(input)))
	} else {
		rc = C.EVP_PKEY_decrypt(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen, in, C.size_t(len(input)))
	}
	if rc != 1 {
		return nil, fmt.Errorf("RSA-OAEP: operation failed: %w", errorFromErrorQueue())
	}
	return out[:int(outLen)], nil
}

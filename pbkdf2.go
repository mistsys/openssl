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

// #include "shim.h"
import "C"
import (
	"errors"
	"unsafe"
)

func KeySHA1(password, salt []byte, iter, keyLen int) ([]byte, error) {
	result := make([]byte, keyLen)
	if 1 != C.X_PKCS5_PBKDF2_HMAC_SHA1(
		(*C.char)(unsafe.Pointer(&password[0])), C.int(len(password)),
		(*C.uchar)(unsafe.Pointer(&salt[0])), C.int(len(salt)), C.int(iter),
		C.int(keyLen), (*C.uchar)(unsafe.Pointer(&result[0]))) {
		return nil, errors.New("openssl: pbkdf2 sha1: cannot create key")
	}
	return result, nil
}

func KeySHA256(password, salt []byte, iter, keyLen int) ([]byte, error) {
	result := make([]byte, keyLen)
	if 1 != C.X_PKCS5_PBKDF2_HMAC(
		(*C.char)(unsafe.Pointer(&password[0])), C.int(len(password)),
		(*C.uchar)(unsafe.Pointer(&salt[0])), C.int(len(salt)), C.int(iter),
		C.X_EVP_sha256(), C.int(keyLen), (*C.uchar)(unsafe.Pointer(&result[0]))) {
		return nil, errors.New("openssl: pbkdf2 sha256: cannot create key")
	}
	return result, nil
}

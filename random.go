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

// #include <openssl/rand.h>
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// RandomBytes fills dst using the OpenSSL default library context's DRBG.
// Its provider and properties are controlled by the process configuration.
func RandomBytes(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("random bytes: %w", err)
	}
	if C.RAND_bytes_ex(nil, (*C.uchar)(unsafe.Pointer(&dst[0])), C.size_t(len(dst)), 0) != 1 {
		return fmt.Errorf("random bytes: %w", errorFromErrorQueue())
	}
	return nil
}

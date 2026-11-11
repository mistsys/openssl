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

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestHMACEmptyKeyAndReset(t *testing.T) {
	h, err := NewHMAC("sha256", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	want := hmac.New(sha256.New, nil)
	if _, err := want.Write([]byte("message")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := h.Write([]byte("message")); err != nil {
			t.Fatal(err)
		}
		got, err := h.Final()
		if err != nil {
			t.Fatal(err)
		}
		if !hmac.Equal(got, want.Sum(nil)) {
			t.Fatalf("HMAC mismatch: got %x, want %x", got, want.Sum(nil))
		}
		if err := h.Reset(); err != nil {
			t.Fatal(err)
		}
	}
}

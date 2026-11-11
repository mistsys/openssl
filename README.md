# OpenSSL bindings for Go

Forked from https://github.com/libp2p/openssl (archived)

---

Please see http://godoc.org/github.com/pexip/go-openssl for more info

---

### Cryptographic operations

The package provides OpenSSL-backed SHA-256 (`SHA256`), HMAC (`NewHMAC`),
RS256 primitives (`SignPKCS1v15` and `VerifyPKCS1v15` with a SHA-256 digest),
RSA key generation (`GenerateRSAKeyWithExponent`), and TLS connections.
`RandomBytes` fills a caller-provided buffer using OpenSSL's
default-context DRBG. `EncryptRSAOAEPSHA256` and `DecryptRSAOAEPSHA256` use
RSA-OAEP with SHA-256, MGF1-SHA-256 and an empty label. The latter is for
software-accessible private keys; TPM-resident decryption remains a TPM
operation unless an appropriate provider is configured.

`NewCertificateTemplate` creates an unsigned certificate for callers to
configure and sign. `Certificate.SetValidity` and `Certificate.Validity` set
and read its absolute validity interval.

These APIs use the OpenSSL default library context and its configured
providers and properties. Their availability alone does not establish FIPS
validation or approved operation. Applications must configure and enforce the
appropriate provider policy and must verify the certificate chain and peer
identity before trusting a TLS connection. These APIs do not themselves
enforce FIPS mode.

### License

Copyright (C) 2017. See AUTHORS.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### Using on macOS
1. Install [homebrew](http://brew.sh/)
2. `$ brew install openssl` or `$ brew install openssl@3`

### Using on Windows
1. Install [mingw-w64](http://mingw-w64.sourceforge.net/)
2. Install [pkg-config-lite](http://sourceforge.net/projects/pkgconfiglite)
3. Build (or install precompiled) openssl for mingw32-w64
4. Set __PKG\_CONFIG\_PATH__ to the directory containing openssl.pc
   (i.e. c:\mingw64\mingw64\lib\pkgconfig)

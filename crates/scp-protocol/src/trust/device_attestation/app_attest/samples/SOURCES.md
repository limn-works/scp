# App Attest sample attestation objects

Each file holds the raw attestation object, the CBOR bytes Apple's
`DCAppAttestService.attestKey` returned, decoded from base64 and otherwise
unchanged. The tests in `../tests.rs` read them with `include_bytes!`.

| File | iOS | AAGUID | Source |
|---|---|---|---|
| `ios-14.4.cbor` | 14.4 | `appattestdevelop` | `src/test/resources/ios-14.4.yaml` of https://github.com/veehaitch/devicecheck-appattest at commit `cb26211f63c1e2e7949deafe2efdf352daca27fa` |
| `go-dev.cbor` | 17.6.1 | `appattestdevelop` | the attestation in `TestAppAttestDev` in `appattest/appattest_impl_test.go` of https://github.com/splitsecure/go-app-attest at commit `b4cf46a249f27449ce53a83b3967da56f46b5fba` |
| `go-prod.cbor` | 18.0 | `appattest` and seven zero bytes | the attestation in `TestAppAttest` in the same file and commit |

## App IDs and client data

`recorded_samples_run_every_check` runs checks 1 through 12 on each object
with the App ID and the client data its upstream test passed to Apple. Each
pair reproduces the object's `rpIdHash` and its 8.2 nonce,
`SHA-256(authData ‖ clientData)`.

| File | App ID | Client data | Upstream source |
|---|---|---|---|
| `ios-14.4.cbor` | `6MURL8TA57.de.vincent-haupert.apple-appattest-poc` | the 32 bytes whose base64 is `i+ZcylFa0JfJU5Z9GNY12G3XihQu09B3UmvtEca+xns=` | the `clientDataHash` and App ID fields of `src/test/resources/ios-14.4.yaml` |
| `go-dev.cbor` | `NFVU6DQWLM.com.turtlecrypt.appattestfun` | SHA-256 of the ASCII string `server_challenge` | the challenge and App ID in `TestAppAttestDev` |
| `go-prod.cbor` | `0352187391.com.apple.example_app_attest` | the 21 ASCII bytes `test_server_challenge`, unhashed | the challenge and App ID in `TestAppAttest` |

SHA-256 of each file:

- `ios-14.4.cbor`: `9472e19c33e28e8cca9b1bc3a0417f6690ac0425d23b36be0a3f1d115ddda9d1`
- `go-dev.cbor`: `3ae99a09a46624070657a45ae9e86e2b64b0f769c093859a47edcaa55c4e4a0d`
- `go-prod.cbor`: `5ebd274c27bf9b3a88345e73db13afc2d643bcc6e1bc02648483ff2c45354034`

## Licences

`ios-14.4.cbor` comes from veehaitch/devicecheck-appattest, which is licensed
under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). The file is decoded from the
base64 in the YAML resource and is not otherwise modified.

`go-dev.cbor` and `go-prod.cbor` come from splitsecure/go-app-attest, which
carries this licence:

```
MIT License

Copyright (c) 2025 SplitSecure

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

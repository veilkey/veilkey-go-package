# veilkey-go-package

Shared Go packages for VeilKey services.

## packages

- `refs` — typed ref scope/status constants and helpers
- `crypto` — AES-GCM encryption and envelope encryption helpers
- `tlsutil` — HTTP clients for inter-service TLS

## Toolchain

Build and test with Go 1.26.10 (`GOTOOLCHAIN=go1.26.10`).

## Cryptography

`crypto.Encrypt` and `crypto.Decrypt` accept 16-, 24-, or 32-byte AES keys.
Encryption generates a fresh 12-byte nonce. Decryption requires a 12-byte nonce
and ciphertext containing at least the 16-byte authentication tag. Invalid inputs
return errors rather than panicking; empty plaintext is supported.

The existing KEK derivation remains PBKDF2-HMAC-SHA256 with 600,000 iterations
and a 32-byte output. This update does not change the KDF or stored format.

## TLS configuration

`tlsutil.NewHTTPClient("", false)` and `tlsutil.InitHTTPClientFromEnv()` verify
certificates using system trust roots by default and require TLS 1.2 or later.
Set `VEILKEY_TLS_CA` to a PEM CA file to use custom trust roots. The constructor
returns an error for an unreadable or invalid CA file; the environment helper
falls back to system trust roots with certificate verification still enabled.

Certificate verification can be disabled only by explicitly passing `true` to
`NewHTTPClient` or setting `VEILKEY_TLS_INSECURE=1`. Other values, including an
unset variable or `0`, keep verification enabled. This opt-in is retained for
isolated development environments; do not use it for multi-host deployments.
Use a trusted certificate or configure `VEILKEY_TLS_CA` instead.

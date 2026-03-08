## 1.0.1

* Fix constant-time comparison to use max length of both strings.
* Fix URI label encoding to use literal colon per Google Authenticator spec.
* Add constructor validation for `OTPUri` type, `HOTP`/`TOTP` digits range, and `TOTP` period.
* Clamp `HOTP.verify` window to avoid negative counter values.

## 1.0.0

* HOTP generation and verification (RFC 4226).
* TOTP generation and verification (RFC 6238).
* SHA-1, SHA-256, SHA-512 algorithm support.
* Base32 encoding and decoding (RFC 4648).
* `otpauth://` URI parsing and building.
* Constant-time code comparison.

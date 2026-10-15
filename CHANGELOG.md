## 1.0.3

* fix: HOTP/TOTP generation and verification threw on web because of ByteData.setInt64.
  The counter is now written as two 32-bit halves, giving the same bytes on the VM.
  On the web, counters outside -(2^53 - 1) to 2^53 - 1 throw a `RangeError`.

## 1.0.2

* Declare the real minimum Dart SDK (3.4, required by `crypto` 3.0.7).
* Update dev dependencies to `lints` 6 and `test` 1.33.
* Tidy the example's lint suppressions.

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

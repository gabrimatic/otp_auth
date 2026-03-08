# otp_auth

A Dart package for generating and verifying HOTP and TOTP one-time passwords using RFC 4226 and RFC 6238.

[![pub package](https://img.shields.io/pub/v/otp_auth.svg)](https://pub.dev/packages/otp_auth) [![likes](https://img.shields.io/pub/likes/otp_auth)](https://pub.dev/packages/otp_auth/score) [![popularity](https://img.shields.io/pub/popularity/otp_auth)](https://pub.dev/packages/otp_auth/score) [![pub points](https://img.shields.io/pub/points/otp_auth)](https://pub.dev/packages/otp_auth/score)

## Quick start

```yaml
dependencies:
  otp_auth: ^1.0.0
```

```dart
import 'package:otp_auth/otp_auth.dart';

final totp = TOTP(secret: 'JBSWY3DPEHPK3PXP');
print(totp.now());              // e.g. '492039'
print(TOTP.format(totp.now())); // e.g. '492 039'
print(totp.remaining);          // seconds until expiry
print(totp.verify('492039'));    // true if current code matches
```

## API

| Class | Description |
|---|---|
| `TOTP` | Time-based one-time password (RFC 6238). `now()`, `at(DateTime)`, `verify()`, `remaining`, `format()`. |
| `HOTP` | Counter-based one-time password (RFC 4226). `at(int)`, `verify()`. |
| `OTPUri` | Parses and builds `otpauth://` URIs. `parse()`, `extractSecret()`, `toTOTP()`, `toHOTP()`. |
| `Base32` | RFC 4648 Base32 codec. `encode()`, `decode()`. |
| `OTPAlgorithm` | `sha1`, `sha256`, `sha512`. |

## Parameters

### TOTP

| Parameter | Type | Default | Description |
|---|---|---|---|
| `secret` | `String` | required | Base32-encoded shared secret |
| `digits` | `int` | `6` | Number of digits in the output code |
| `algorithm` | `OTPAlgorithm` | `sha1` | Hash algorithm |
| `period` | `int` | `30` | Time step in seconds |

### HOTP

| Parameter | Type | Default | Description |
|---|---|---|---|
| `secret` | `String` | required | Base32-encoded shared secret |
| `digits` | `int` | `6` | Number of digits in the output code |
| `algorithm` | `OTPAlgorithm` | `sha1` | Hash algorithm |

Both `TOTP` and `HOTP` accept raw bytes via `.fromBytes(secret: Uint8List)`.

## URI parsing

```dart
final uri = OTPUri.parse(
  'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
);
print(uri.issuer);  // 'GitHub'
print(uri.account); // 'user@example.com'

final totp = uri.toTOTP();
print(totp.now());

// Extract just the secret from any otpauth:// URI
final secret = OTPUri.extractSecret('otpauth://totp/...?secret=ABC123');
```

## RFC compliance

| Standard | Title |
|---|---|
| [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) | HOTP: An HMAC-Based One-Time Password Algorithm |
| [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) | TOTP: Time-Based One-Time Password Algorithm |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base16, Base32, and Base64 Data Encodings |

Validated against official test vectors from RFC 4226 Appendix D and RFC 6238 Appendix B.

## Requirements

Dart SDK: >=3.0.0

## Author

[Soroush Yousefpour](https://gabrimatic.info)

<a href="https://www.buymeacoffee.com/gabrimatic" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="200"></a>

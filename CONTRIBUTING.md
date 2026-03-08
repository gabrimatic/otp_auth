# Contributing

Bug fixes, better docs, new features. Here's how to get involved.

## Dev setup

```bash
git clone https://github.com/gabrimatic/otp_auth.git
cd otp_auth
dart pub get
```

Run the tests:

```bash
dart test
```

## Architecture

```
lib/
├── otp_auth.dart        # public barrel export
└── src/
    ├── algorithm.dart   # OTPAlgorithm enum (SHA-1, SHA-256, SHA-512)
    ├── base32.dart      # RFC 4648 Base32 codec
    ├── hotp.dart        # RFC 4226 HOTP implementation
    ├── totp.dart        # RFC 6238 TOTP implementation
    └── uri.dart         # otpauth:// URI parser and builder
```

## PR checklist

- One feature or fix per PR. Keep scope tight.
- `dart analyze` must pass with no issues.
- `dart test` must pass with no failures.
- Update `CHANGELOG.md` if the change is user-facing.
- Do not bump version numbers — that is handled during release.
- Match existing code style. No reformatting unrelated files.

## Reporting issues

Use the [issue tracker](https://github.com/gabrimatic/otp_auth/issues). Include your Dart/Flutter version and steps to reproduce.

## Vulnerability reporting

See [SECURITY.md](SECURITY.md). Do **not** open public issues for security vulnerabilities.

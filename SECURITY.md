# Security Policy

## Vulnerability reporting

Report vulnerabilities responsibly:

1. **Do not open a public issue.** Vulnerabilities stay private until a fix ships.
2. Use [GitHub's private vulnerability reporting](https://github.com/gabrimatic/otp_auth/security/advisories/new) to submit.
3. Include:
   - Steps to reproduce
   - Demonstrated impact
   - Suggested fix (if any)

Reports without reproduction steps or demonstrated impact are deprioritized.

Expect acknowledgment within 48 hours.

## Scope

This package generates and verifies HOTP/TOTP one-time passwords using HMAC-based algorithms. It handles shared secrets in memory during code generation.

Reports related to timing attacks, secret exposure, or cryptographic weaknesses are taken seriously.

## Out of scope

- Issues requiring a compromised device or physical access
- Issues in third-party dependencies unrelated to this package's API surface

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

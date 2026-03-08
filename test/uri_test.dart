import 'package:otp_auth/otp_auth.dart';
import 'package:test/test.dart';

void main() {
  group('OTPUri parse', () {
    test('parses full TOTP URI', () {
      const uriStr =
          'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60';
      final uri = OTPUri.parse(uriStr);

      expect(uri.type, equals('totp'));
      expect(uri.account, equals('user@example.com'));
      expect(uri.issuer, equals('Example'));
      expect(uri.secret, equals('JBSWY3DPEHPK3PXP'));
      expect(uri.algorithm, equals(OTPAlgorithm.sha256));
      expect(uri.digits, equals(8));
      expect(uri.period, equals(60));
    });

    test('parses HOTP URI with counter', () {
      const uriStr =
          'otpauth://hotp/account?secret=JBSWY3DPEHPK3PXP&counter=42';
      final uri = OTPUri.parse(uriStr);

      expect(uri.type, equals('hotp'));
      expect(uri.account, equals('account'));
      expect(uri.secret, equals('JBSWY3DPEHPK3PXP'));
      expect(uri.counter, equals(42));
    });

    test('parses URI with only secret', () {
      const uriStr = 'otpauth://totp/?secret=JBSWY3DPEHPK3PXP';
      final uri = OTPUri.parse(uriStr);

      expect(uri.secret, equals('JBSWY3DPEHPK3PXP'));
      expect(uri.type, equals('totp'));
    });

    test('uses defaults for missing params', () {
      const uriStr = 'otpauth://totp/account?secret=JBSWY3DPEHPK3PXP';
      final uri = OTPUri.parse(uriStr);

      expect(uri.algorithm, equals(OTPAlgorithm.sha1));
      expect(uri.digits, equals(6));
      expect(uri.period, equals(30));
    });

    test('throws on invalid scheme', () {
      expect(
        () => OTPUri.parse('https://example.com?secret=ABC'),
        throwsFormatException,
      );
    });

    test('throws on missing secret', () {
      expect(
        () => OTPUri.parse('otpauth://totp/account'),
        throwsFormatException,
      );
    });

    test('throws on unknown OTP type', () {
      expect(
        () => OTPUri.parse('otpauth://motp/account?secret=ABC'),
        throwsFormatException,
      );
    });
  });

  group('OTPUri extractSecret', () {
    test('extracts secret from URI', () {
      const uriStr =
          'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
      expect(OTPUri.extractSecret(uriStr), equals('JBSWY3DPEHPK3PXP'));
    });
  });

  group('OTPUri toString roundtrip', () {
    test('TOTP roundtrip preserves key fields', () {
      const uriStr =
          'otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60';
      final uri = OTPUri.parse(uriStr);
      final reparsed = OTPUri.parse(uri.toString());

      expect(reparsed.type, equals(uri.type));
      expect(reparsed.account, equals(uri.account));
      expect(reparsed.issuer, equals(uri.issuer));
      expect(reparsed.secret, equals(uri.secret));
      expect(reparsed.algorithm, equals(uri.algorithm));
      expect(reparsed.digits, equals(uri.digits));
      expect(reparsed.period, equals(uri.period));
    });

    test('HOTP roundtrip preserves counter', () {
      const uriStr =
          'otpauth://hotp/account?secret=JBSWY3DPEHPK3PXP&counter=42';
      final uri = OTPUri.parse(uriStr);
      final reparsed = OTPUri.parse(uri.toString());

      expect(reparsed.counter, equals(42));
    });
  });

  group('OTPUri toTOTP / toHOTP', () {
    test('toTOTP returns TOTP instance', () {
      final uri =
          OTPUri.parse('otpauth://totp/account?secret=JBSWY3DPEHPK3PXP');
      final totp = uri.toTOTP();
      expect(totp, isA<TOTP>());
      expect(totp.now().length, equals(6));
    });

    test('toHOTP returns HOTP instance', () {
      final uri = OTPUri.parse(
          'otpauth://hotp/account?secret=JBSWY3DPEHPK3PXP&counter=0');
      final hotp = uri.toHOTP();
      expect(hotp, isA<HOTP>());
      expect(hotp.at(0).length, equals(6));
    });

    test('toTOTP throws on hotp URI', () {
      final uri = OTPUri.parse(
          'otpauth://hotp/account?secret=JBSWY3DPEHPK3PXP&counter=0');
      expect(() => uri.toTOTP(), throwsStateError);
    });

    test('toHOTP throws on totp URI', () {
      final uri =
          OTPUri.parse('otpauth://totp/account?secret=JBSWY3DPEHPK3PXP');
      expect(() => uri.toHOTP(), throwsStateError);
    });
  });
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:otp_auth/otp_auth.dart';
import 'package:test/test.dart';

void main() {
  DateTime epoch(int seconds) =>
      DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

  group('TOTP RFC 6238 SHA-1 test vectors', () {
    // Secret: ASCII '12345678901234567890' (20 bytes)
    final secret = Uint8List.fromList(utf8.encode('12345678901234567890'));

    late TOTP totp;

    setUp(() {
      totp = TOTP.fromBytes(secret: secret);
    });

    const vectors = <int, String>{
      59: '287082',
      1111111109: '081804',
      1111111111: '050471',
      1234567890: '005924',
      2000000000: '279037',
    };

    for (final entry in vectors.entries) {
      test('time=${entry.key} → ${entry.value}', () {
        expect(totp.at(epoch(entry.key)), equals(entry.value));
      });
    }

    test('time=20000000000 → 65353130 (8-digit, RFC 6238 Appendix B)', () {
      final totp8 = TOTP.fromBytes(secret: secret, digits: 8);
      expect(totp8.at(epoch(20000000000)), equals('65353130'));
    });

    test('verify correct code', () {
      final code = totp.at(epoch(59));
      expect(
        totp.verify(code, time: epoch(59), window: 0),
        isTrue,
      );
    });

    test('verify with window allows adjacent step', () {
      final code = totp.at(epoch(59));
      // Verify at time=89 (next step), window=1 should accept
      expect(
        totp.verify(code, time: epoch(89), window: 1),
        isTrue,
      );
    });

    test('verify wrong code', () {
      expect(totp.verify('000000', time: epoch(59), window: 0), isFalse);
    });
  });

  group('TOTP RFC 6238 SHA-256 test vectors', () {
    // Secret: ASCII '12345678901234567890123456789012' (32 bytes)
    final secret =
        Uint8List.fromList(utf8.encode('12345678901234567890123456789012'));

    late TOTP totp;

    setUp(() {
      totp = TOTP.fromBytes(
        secret: secret,
        algorithm: OTPAlgorithm.sha256,
      );
    });

    const vectors = <int, String>{
      59: '119246',
      1111111109: '084774',
      1111111111: '062674',
      1234567890: '819424',
      2000000000: '698825',
    };

    for (final entry in vectors.entries) {
      test('time=${entry.key} → ${entry.value}', () {
        expect(totp.at(epoch(entry.key)), equals(entry.value));
      });
    }

    test('time=20000000000 → 77737706 (8-digit, RFC 6238 Appendix B)', () {
      final totp8 = TOTP.fromBytes(
        secret: secret,
        algorithm: OTPAlgorithm.sha256,
        digits: 8,
      );
      expect(totp8.at(epoch(20000000000)), equals('77737706'));
    });
  });

  group('TOTP RFC 6238 SHA-512 test vectors', () {
    // Secret: ASCII 64-byte string
    final secret = Uint8List.fromList(utf8.encode(
        '1234567890123456789012345678901234567890123456789012345678901234'));

    late TOTP totp;

    setUp(() {
      totp = TOTP.fromBytes(
        secret: secret,
        algorithm: OTPAlgorithm.sha512,
      );
    });

    const vectors = <int, String>{
      59: '693936',
      1111111109: '091201',
      1111111111: '943326',
      1234567890: '441116',
      2000000000: '618901',
    };

    for (final entry in vectors.entries) {
      test('time=${entry.key} → ${entry.value}', () {
        expect(totp.at(epoch(entry.key)), equals(entry.value));
      });
    }

    test('time=20000000000 → 47863826 (8-digit, RFC 6238 Appendix B)', () {
      final totp8 = TOTP.fromBytes(
        secret: secret,
        algorithm: OTPAlgorithm.sha512,
        digits: 8,
      );
      expect(totp8.at(epoch(20000000000)), equals('47863826'));
    });
  });

  group('TOTP utilities', () {
    final secret = Uint8List.fromList(utf8.encode('12345678901234567890'));
    late TOTP totp;

    setUp(() {
      totp = TOTP.fromBytes(secret: secret);
    });

    test('remaining is between 1 and 30 inclusive', () {
      expect(totp.remaining, inInclusiveRange(1, 30));
    });

    test('format splits 6-digit code', () {
      expect(TOTP.format('492039'), equals('492 039'));
    });

    test('format splits 8-digit code', () {
      expect(TOTP.format('49203900'), equals('4920 3900'));
    });

    test('format returns short codes unchanged', () {
      expect(TOTP.format('123'), equals('123'));
    });

    test('now() returns 6-digit code', () {
      expect(totp.now().length, equals(6));
    });
  });

  group('TOTP Base32 constructor', () {
    test('produces same output as fromBytes', () {
      final secret = Uint8List.fromList(utf8.encode('12345678901234567890'));
      final fromBytes = TOTP.fromBytes(secret: secret);
      final fromBase32 = TOTP(secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      final time = DateTime.fromMillisecondsSinceEpoch(59000, isUtc: true);
      expect(fromBase32.at(time), equals(fromBytes.at(time)));
    });
  });

  group('TOTP validation', () {
    test('throws on period <= 0', () {
      expect(
        () => TOTP(secret: 'JBSWY3DPEHPK3PXP', period: 0),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws on negative period', () {
      expect(
        () => TOTP(secret: 'JBSWY3DPEHPK3PXP', period: -1),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws on digits out of range', () {
      expect(
        () => TOTP(secret: 'JBSWY3DPEHPK3PXP', digits: 0),
        throwsA(isA<RangeError>()),
      );
    });
  });
}

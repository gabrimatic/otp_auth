import 'dart:convert';
import 'dart:typed_data';

import 'package:otp_auth/otp_auth.dart';
import 'package:test/test.dart';

void main() {
  // RFC 4226 Appendix D test vectors
  // Secret: ASCII string '12345678901234567890'
  final secret = Uint8List.fromList(utf8.encode('12345678901234567890'));

  group('HOTP RFC 4226 test vectors', () {
    late HOTP hotp;

    setUp(() {
      hotp = HOTP.fromBytes(secret: secret);
    });

    const vectors = <int, String>{
      0: '755224',
      1: '287082',
      2: '359152',
      3: '969429',
      4: '338314',
      5: '254676',
      6: '287922',
      7: '162583',
      8: '399871',
      9: '520489',
    };

    for (final entry in vectors.entries) {
      test('counter ${entry.key} → ${entry.value}', () {
        expect(hotp.at(entry.key), equals(entry.value));
      });
    }
  });

  group('HOTP verify', () {
    late HOTP hotp;

    setUp(() {
      hotp = HOTP.fromBytes(secret: secret);
    });

    test('verify with window=0 exact match', () {
      expect(hotp.verify('755224', 0, window: 0), isTrue);
    });

    test('verify with window=0 wrong counter', () {
      expect(hotp.verify('287082', 0, window: 0), isFalse);
    });

    test('verify with window=1 adjacent counter', () {
      // code for counter=1 is '287082', verifying at counter=0 with window=1
      expect(hotp.verify('287082', 0, window: 1), isTrue);
    });

    test('verify with window=1 too far', () {
      // code for counter=2 is '359152', verifying at counter=0 with window=1
      expect(hotp.verify('359152', 0, window: 1), isFalse);
    });

    test('verify wrong code', () {
      expect(hotp.verify('000000', 0, window: 0), isFalse);
    });
  });

  group('HOTP 8 digits', () {
    test('generates 8-digit code', () {
      final hotp = HOTP.fromBytes(secret: secret, digits: 8);
      final code = hotp.at(0);
      expect(code.length, equals(8));
    });
  });

  group('HOTP Base32 constructor', () {
    test('produces same output as fromBytes', () {
      final fromBytes = HOTP.fromBytes(secret: secret);
      // Base32 of '12345678901234567890' is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
      final fromBase32 = HOTP(secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      expect(fromBase32.at(0), equals(fromBytes.at(0)));
      expect(fromBase32.at(7), equals(fromBytes.at(7)));
    });
  });

  group('HOTP validation', () {
    test('throws on digits < 1', () {
      expect(
        () => HOTP.fromBytes(secret: secret, digits: 0),
        throwsA(isA<RangeError>()),
      );
    });

    test('throws on digits > 8', () {
      expect(
        () => HOTP.fromBytes(secret: secret, digits: 9),
        throwsA(isA<RangeError>()),
      );
    });

    test('verify clamps negative counter window to 0', () {
      final hotp = HOTP.fromBytes(secret: secret);
      // counter=0, window=3 should not go negative
      expect(hotp.verify('755224', 0, window: 3), isTrue);
    });
  });

  group('HOTP large and negative counters', () {
    late HOTP hotp;

    setUp(() {
      hotp = HOTP.fromBytes(secret: secret);
    });

    // Expected values: HMAC-SHA1 over the 8-byte big-endian counter
    // (two's complement for negative counters), RFC 4226 truncation.
    const vectors = <int, String>{
      4294967295: '117190', // 2^32 - 1, low half only
      4294967296: '999456', // 2^32, first counter using the high half
      4294967297: '108930', // 2^32 + 1
      9007199254740991: '891307', // 2^53 - 1, largest exact integer on web
      -1: '094451',
      -9007199254740991: '452964', // -(2^53 - 1)
    };

    for (final entry in vectors.entries) {
      test('counter ${entry.key} → ${entry.value}', () {
        expect(hotp.at(entry.key), equals(entry.value));
      });
    }

    test('8-digit code at 2^53 - 1', () {
      final hotp8 = HOTP.fromBytes(secret: secret, digits: 8);
      expect(hotp8.at(9007199254740991), equals('41891307'));
    });

    test('verify across the 2^32 boundary', () {
      expect(hotp.verify('999456', 4294967295, window: 1), isTrue);
    });

    test(
      'rejects counters beyond 2^53 - 1 on the web',
      () {
        expect(() => hotp.at(9007199254740992), throwsA(isA<RangeError>()));
        expect(() => hotp.at(-9007199254740992), throwsA(isA<RangeError>()));
      },
      testOn: 'browser',
    );
  });
}

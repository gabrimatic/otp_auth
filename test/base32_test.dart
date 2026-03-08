import 'dart:convert';
import 'dart:typed_data';

import 'package:otp_auth/otp_auth.dart';
import 'package:test/test.dart';

void main() {
  group('Base32', () {
    test('decodes known value', () {
      // 'Hello!' encoded in Base32 is JBSWY3DPEE
      final bytes = Base32.decode('JBSWY3DPEE');
      expect(utf8.decode(bytes), equals('Hello!'));
    });

    test('decodes JBSWY3DPEHPK3PXP to known bytes', () {
      final bytes = Base32.decode('JBSWY3DPEHPK3PXP');
      expect(bytes, isNotEmpty);
      expect(bytes.length, equals(10));
      // First 6 bytes are 'Hello!'
      expect(bytes.sublist(0, 6), equals([72, 101, 108, 108, 111, 33]));
    });

    test('is case-insensitive', () {
      final upper = Base32.decode('JBSWY3DPEHPK3PXP');
      final lower = Base32.decode('jbswy3dpehpk3pxp');
      expect(upper, equals(lower));
    });

    test('strips spaces', () {
      final clean = Base32.decode('JBSWY3DPEHPK3PXP');
      final spaced = Base32.decode('JBSWY 3DPE HPK3 PXP');
      expect(clean, equals(spaced));
    });

    test('strips hyphens', () {
      final clean = Base32.decode('JBSWY3DPEHPK3PXP');
      final hyphenated = Base32.decode('JBSWY-3DPE-HPK3-PXP');
      expect(clean, equals(hyphenated));
    });

    test('strips padding', () {
      final withPadding = Base32.decode('JBSWY3DPEB3W64TMMQ======');
      final withoutPadding = Base32.decode('JBSWY3DPEB3W64TMMQ');
      expect(withPadding, equals(withoutPadding));
    });

    test('encode/decode roundtrip', () {
      // JBSWY3DPEE encodes 'Hello!' — clean 8-char input, no trailing bits
      const input = 'JBSWY3DPEE';
      final decoded = Base32.decode(input);
      final encoded = Base32.encode(decoded);
      expect(encoded, equals(input));
    });

    test('encodes empty bytes to empty string', () {
      expect(Base32.encode(Uint8List(0)), equals(''));
    });

    test('decodes empty string to empty bytes', () {
      expect(Base32.decode(''), equals(Uint8List(0)));
    });

    test('throws FormatException on invalid character', () {
      expect(() => Base32.decode('JBSWY1DP'), throwsFormatException);
    });

    test('throws FormatException on digit 8', () {
      expect(() => Base32.decode('8BSWY3DP'), throwsFormatException);
    });
  });
}

import 'dart:typed_data';

/// RFC 4648 Base32 codec.
class Base32 {
  static const _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /// Decodes a Base32-encoded [input] to bytes.
  ///
  /// Strips whitespace, hyphens, and padding before decoding.
  /// Case-insensitive.
  static Uint8List decode(String input) {
    final cleaned = input.toUpperCase().replaceAll(RegExp(r'[\s\-=]'), '');
    final out = <int>[];
    var buffer = 0;
    var bitsLeft = 0;

    for (final char in cleaned.codeUnits) {
      final value = _alphabet.indexOf(String.fromCharCode(char));
      if (value < 0) {
        throw FormatException(
            'Invalid Base32 character: ${String.fromCharCode(char)}');
      }
      buffer = (buffer << 5) | value;
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        bitsLeft -= 8;
        out.add((buffer >> bitsLeft) & 0xff);
      }
    }
    return Uint8List.fromList(out);
  }

  /// Encodes [bytes] to a Base32 string without padding.
  static String encode(Uint8List bytes) {
    final out = StringBuffer();
    var buffer = 0;
    var bitsLeft = 0;

    for (final byte in bytes) {
      buffer = (buffer << 8) | byte;
      bitsLeft += 8;
      while (bitsLeft >= 5) {
        bitsLeft -= 5;
        out.write(_alphabet[(buffer >> bitsLeft) & 0x1f]);
      }
    }
    if (bitsLeft > 0) {
      out.write(_alphabet[(buffer << (5 - bitsLeft)) & 0x1f]);
    }
    return out.toString();
  }
}

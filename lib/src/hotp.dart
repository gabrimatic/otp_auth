import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:otp_auth/src/algorithm.dart';
import 'package:otp_auth/src/base32.dart';

/// HMAC-based One-Time Password (RFC 4226).
class HOTP {
  final Uint8List _secret;

  /// Number of digits in the generated code.
  final int digits;

  /// Hash algorithm used.
  final OTPAlgorithm algorithm;

  /// Creates an HOTP instance from a Base32-encoded [secret].
  HOTP({
    required String secret,
    this.digits = 6,
    this.algorithm = OTPAlgorithm.sha1,
  }) : _secret = Base32.decode(secret) {
    RangeError.checkValueInInterval(digits, 1, 8, 'digits');
  }

  /// Creates an HOTP instance from raw [secret] bytes.
  HOTP.fromBytes({
    required Uint8List secret,
    this.digits = 6,
    this.algorithm = OTPAlgorithm.sha1,
  }) : _secret = Uint8List.fromList(secret) {
    RangeError.checkValueInInterval(digits, 1, 8, 'digits');
  }

  /// Generates the OTP for the given [counter].
  String at(int counter) {
    final hmac = Hmac(algorithm.hash, _secret);
    final counterBytes = ByteData(8)..setInt64(0, counter);
    final hash = hmac.convert(counterBytes.buffer.asUint8List()).bytes;

    // Dynamic truncation (RFC 4226 Section 5.4)
    final offset = hash.last & 0x0f;
    final code = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    final mod =
        [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000][digits];
    return (code % mod).toString().padLeft(digits, '0');
  }

  /// Verifies the [code] against the given [counter].
  ///
  /// Optionally checks [window] values before and after [counter]
  /// to account for synchronization drift.
  bool verify(String code, int counter, {int window = 0}) {
    for (var i = counter - window; i <= counter + window; i++) {
      if (_constantTimeEquals(at(i), code)) return true;
    }
    return false;
  }
}

/// Constant-time string comparison to prevent timing attacks.
bool _constantTimeEquals(String a, String b) {
  final length = a.length;
  // Pad shorter string to avoid leaking length through timing.
  final bPadded = b.padRight(length, '\x00');
  var result = a.length ^ b.length;
  for (var i = 0; i < length; i++) {
    result |= a.codeUnitAt(i) ^ bPadded.codeUnitAt(i);
  }
  return result == 0;
}

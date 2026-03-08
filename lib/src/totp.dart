import 'dart:typed_data';
import 'package:otp_auth/src/algorithm.dart';
import 'package:otp_auth/src/hotp.dart';

/// Time-based One-Time Password (RFC 6238).
class TOTP {
  final HOTP _hotp;

  /// Time step in seconds (default: 30).
  final int period;

  /// Number of digits in the generated code.
  int get digits => _hotp.digits;

  /// Hash algorithm used.
  OTPAlgorithm get algorithm => _hotp.algorithm;

  /// Creates a TOTP instance from a Base32-encoded [secret].
  TOTP({
    required String secret,
    int digits = 6,
    OTPAlgorithm algorithm = OTPAlgorithm.sha1,
    this.period = 30,
  }) : _hotp = HOTP(secret: secret, digits: digits, algorithm: algorithm) {
    if (period <= 0) {
      throw ArgumentError.value(period, 'period', 'Must be positive');
    }
  }

  /// Creates a TOTP instance from raw [secret] bytes.
  TOTP.fromBytes({
    required Uint8List secret,
    int digits = 6,
    OTPAlgorithm algorithm = OTPAlgorithm.sha1,
    this.period = 30,
  }) : _hotp = HOTP.fromBytes(
            secret: secret, digits: digits, algorithm: algorithm) {
    if (period <= 0) {
      throw ArgumentError.value(period, 'period', 'Must be positive');
    }
  }

  /// Generates the current OTP code.
  String now() => at(DateTime.now());

  /// Generates the OTP code for the given [time].
  String at(DateTime time) {
    final counter = time.millisecondsSinceEpoch ~/ (period * 1000);
    return _hotp.at(counter);
  }

  /// Seconds remaining until the current code expires.
  int get remaining {
    final seconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return period - (seconds % period);
  }

  /// Verifies the [code] against the given [time] (or now).
  ///
  /// The [window] parameter allows [window] steps before and after
  /// the current time step to account for clock drift.
  bool verify(String code, {DateTime? time, int window = 1}) {
    time ??= DateTime.now();
    final counter = time.millisecondsSinceEpoch ~/ (period * 1000);
    return _hotp.verify(code, counter, window: window);
  }

  /// Formats a code with a space in the middle for readability.
  ///
  /// Example: `'492039'` → `'492 039'`
  static String format(String code) {
    if (code.length < 4) return code;
    final mid = code.length ~/ 2;
    return '${code.substring(0, mid)} ${code.substring(mid)}';
  }
}

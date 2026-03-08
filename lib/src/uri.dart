import 'package:otp_auth/src/algorithm.dart';
import 'package:otp_auth/src/hotp.dart';
import 'package:otp_auth/src/totp.dart';

/// Parses and builds `otpauth://` URIs (RFC 6238 Appendix / Google Authenticator).
class OTPUri {
  /// OTP type: `'totp'` or `'hotp'`.
  final String type;

  /// The account name (e.g. `user@example.com`).
  final String? account;

  /// The issuer (e.g. `GitHub`).
  final String? issuer;

  /// Base32-encoded secret.
  final String secret;

  /// Hash algorithm.
  final OTPAlgorithm algorithm;

  /// Number of digits.
  final int digits;

  /// Time period in seconds (TOTP only).
  final int period;

  /// Counter value (HOTP only).
  final int? counter;

  const OTPUri({
    required this.type,
    required this.secret,
    this.account,
    this.issuer,
    this.algorithm = OTPAlgorithm.sha1,
    this.digits = 6,
    this.period = 30,
    this.counter,
  });

  /// Parses an `otpauth://` URI string.
  ///
  /// Supports format:
  /// `otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30`
  static OTPUri parse(String uriString) {
    final uri = Uri.parse(uriString);
    if (uri.scheme != 'otpauth') {
      throw FormatException('Expected otpauth:// scheme, got: ${uri.scheme}');
    }

    final type = uri.host; // 'totp' or 'hotp'
    if (type != 'totp' && type != 'hotp') {
      throw FormatException('Unknown OTP type: $type');
    }

    // Parse label: /Issuer:account or /account
    String? issuer;
    String? account;
    final path = uri.path.startsWith('/') ? uri.path.substring(1) : uri.path;
    if (path.isNotEmpty) {
      final decoded = Uri.decodeComponent(path);
      if (decoded.contains(':')) {
        final parts = decoded.split(':');
        issuer = parts[0].trim();
        account = parts.sublist(1).join(':').trim();
      } else {
        account = decoded;
      }
    }

    final params = uri.queryParameters;
    final secret = params['secret'] ?? '';
    if (secret.isEmpty) {
      throw const FormatException('Missing required "secret" parameter');
    }

    // Issuer in query overrides label prefix
    issuer = params['issuer'] ?? issuer;

    final algorithm = switch (params['algorithm']?.toUpperCase()) {
      'SHA256' => OTPAlgorithm.sha256,
      'SHA512' => OTPAlgorithm.sha512,
      _ => OTPAlgorithm.sha1,
    };

    final digits = int.tryParse(params['digits'] ?? '') ?? 6;
    final period = int.tryParse(params['period'] ?? '') ?? 30;
    final counter = int.tryParse(params['counter'] ?? '');

    return OTPUri(
      type: type,
      secret: secret,
      account: account,
      issuer: issuer,
      algorithm: algorithm,
      digits: digits,
      period: period,
      counter: counter,
    );
  }

  /// Extracts just the secret from an `otpauth://` URI.
  ///
  /// Convenience method when you only need the secret value.
  static String extractSecret(String uriString) {
    return parse(uriString).secret;
  }

  /// Creates a [TOTP] instance from this URI.
  ///
  /// Throws if [type] is not `'totp'`.
  TOTP toTOTP() {
    if (type != 'totp') {
      throw StateError('Cannot create TOTP from $type URI');
    }
    return TOTP(
      secret: secret,
      algorithm: algorithm,
      digits: digits,
      period: period,
    );
  }

  /// Creates an [HOTP] instance from this URI.
  ///
  /// Throws if [type] is not `'hotp'`.
  HOTP toHOTP() {
    if (type != 'hotp') {
      throw StateError('Cannot create HOTP from $type URI');
    }
    return HOTP(secret: secret, algorithm: algorithm, digits: digits);
  }

  /// Builds the `otpauth://` URI string.
  @override
  String toString() {
    final label = issuer != null && account != null
        ? Uri.encodeComponent('$issuer:$account')
        : Uri.encodeComponent(account ?? '');

    final params = <String, String>{
      'secret': secret,
      if (issuer != null) 'issuer': issuer!,
      if (algorithm != OTPAlgorithm.sha1)
        'algorithm': algorithm.name.toUpperCase(),
      if (digits != 6) 'digits': digits.toString(),
    };

    if (type == 'totp' && period != 30) {
      params['period'] = period.toString();
    }
    if (type == 'hotp' && counter != null) {
      params['counter'] = counter.toString();
    }

    final query = params.entries
        .map((e) =>
            '${Uri.encodeComponent(e.key)}=${Uri.encodeComponent(e.value)}')
        .join('&');
    return 'otpauth://$type/$label?$query';
  }
}

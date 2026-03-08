import 'package:crypto/crypto.dart' as crypto;

/// Hash algorithm for OTP generation.
enum OTPAlgorithm {
  /// SHA-1 (default, RFC 4226). 20-byte key recommended.
  sha1,

  /// SHA-256. 32-byte key recommended.
  sha256,

  /// SHA-512. 64-byte key recommended.
  sha512;

  /// Returns the corresponding [crypto.Hash].
  crypto.Hash get hash => switch (this) {
        sha1 => crypto.sha1,
        sha256 => crypto.sha256,
        sha512 => crypto.sha512,
      };
}

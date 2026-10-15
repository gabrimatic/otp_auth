// ignore_for_file: avoid_print

import 'package:otp_auth/otp_auth.dart';

void main() {
  // Generate a TOTP code (Google Authenticator compatible)
  final totp = TOTP(secret: 'JBSWY3DPEHPK3PXP');
  final code = totp.now();
  print('TOTP: ${TOTP.format(code)}'); // e.g. "492 039"
  print('Expires in: ${totp.remaining}s');

  // Verify a code (allows 1 step of clock drift)
  print('Valid: ${totp.verify(code)}');

  // Parse an otpauth:// URI
  final uri = OTPUri.parse(
    'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
  );
  print('Issuer: ${uri.issuer}');
  print('Account: ${uri.account}');
  final totpFromUri = uri.toTOTP();
  print('Code: ${totpFromUri.now()}');

  // HOTP
  final hotp = HOTP(secret: 'JBSWY3DPEHPK3PXP');
  print('HOTP(0): ${hotp.at(0)}');
  print('HOTP(1): ${hotp.at(1)}');
}

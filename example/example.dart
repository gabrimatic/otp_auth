import 'package:otp_auth/otp_auth.dart';

void main() {
  // Generate a TOTP code (Google Authenticator compatible)
  final totp = TOTP(secret: 'JBSWY3DPEHPK3PXP');
  final code = totp.now();
  // ignore: avoid_print
  print('TOTP: ${TOTP.format(code)}'); // e.g. "492 039"
  // ignore: avoid_print
  print('Expires in: ${totp.remaining}s');

  // Verify a code (allows 1 step of clock drift)
  // ignore: avoid_print
  print('Valid: ${totp.verify(code)}');

  // Parse an otpauth:// URI
  final uri = OTPUri.parse(
    'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
  );
  // ignore: avoid_print
  print('Issuer: ${uri.issuer}');
  // ignore: avoid_print
  print('Account: ${uri.account}');
  final totpFromUri = uri.toTOTP();
  // ignore: avoid_print
  print('Code: ${totpFromUri.now()}');

  // HOTP
  final hotp = HOTP(secret: 'JBSWY3DPEHPK3PXP');
  // ignore: avoid_print
  print('HOTP(0): ${hotp.at(0)}');
  // ignore: avoid_print
  print('HOTP(1): ${hotp.at(1)}');
}

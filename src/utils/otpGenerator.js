/**
 * Generate a 6-digit OTP code
 */
export function generateOtpCode() {
  const num = Math.floor(Math.random() * 1000000);
  return String(num).padStart(6, '0');
}

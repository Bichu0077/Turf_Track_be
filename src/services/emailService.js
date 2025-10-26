import nodemailer from 'nodemailer';
import { OTP_EXPIRY_SECONDS } from '../config/constants.js';

/**
 * Get configured email transporter
 */
async function getMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE).toLowerCase() === "true";
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    console.warn("SMTP config missing (SMTP_HOST/SMTP_USER/SMTP_PASS)");
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: user && pass ? { user, pass } : undefined,
    tls: { rejectUnauthorized: false } // dev: allow self-signed
  });

  // verify connection early and log result
  try {
    await transporter.verify();
    console.log("SMTP transporter verified");
  } catch (err) {
    console.error("SMTP verify failed:", err);
  }

  return transporter;
}

/**
 * Send OTP email to user
 */
export async function sendOtpEmail(toEmail, code) {
  try {
    const transporter = await getMailer();
    const from = process.env.MAIL_FROM || `no-reply@${process.env.SUPABASE_URL?.replace(/^https?:\/\//, "") || "local"}`;
    const info = await transporter.sendMail({
      from,
      to: toEmail,
      subject: `Your verification code`,
      text: `Your OTP code: ${code}`,
      html: `<p>Your OTP code: <strong>${code}</strong></p><p>It expires in ${Math.floor(OTP_EXPIRY_SECONDS/60)} minutes.</p>`
    });
    console.log(`OTP email sent to ${toEmail} messageId=${info.messageId}`);
    return info;
  } catch (err) {
    console.error("Failed to send OTP email:", err);
    throw err;
  }
}

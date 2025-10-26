import crypto from 'crypto';
import { razorpayKeySecret } from '../config/razorpay.js';

/**
 * Verify Razorpay signature
 */
export function verifyRazorpaySignature(orderId, paymentId, signature) {
  if (!razorpayKeySecret) return false;
  
  const body = orderId + "|" + paymentId;
  const expectedSignature = crypto
    .createHmac("sha256", razorpayKeySecret)
    .update(body.toString())
    .digest("hex");
  
  return expectedSignature === signature;
}

export const OTP_EXPIRY_SECONDS = Number(process.env.OTP_EXPIRY_SECONDS || 600); // 10 minutes default
export const isProduction = process.env.NODE_ENV === 'production';
export const PORT = process.env.PORT || 3000;

// In-memory stores (consider moving to Redis in production)
export const pendingRegistrations = new Map();
export const pendingPasswordResets = new Map();
export const pendingResetTokens = new Map();
export const userActivities = new Map();

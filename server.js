
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import { createClient } from '@supabase/supabase-js';
import nodemailer from "nodemailer";
import crypto from 'crypto';
import Razorpay from 'razorpay';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increase limit for image uploads
app.use(morgan('dev'));

// Supabase clients
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseAnonKey || !supabaseServiceKey) {
  console.warn('Missing Supabase environment variables. Please set SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY');
}

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, { auth: { persistSession: false } });
const supabaseAnon = createClient(supabaseUrl, supabaseAnonKey, { auth: { persistSession: false } });

// Razorpay configuration
const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;

let razorpay = null;
if (razorpayKeyId && razorpayKeySecret) {
  razorpay = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret,
  });
  console.log('Razorpay initialized successfully');
} else {
  console.warn('Razorpay configuration missing. Payment features will be disabled.');
}

// In-memory store for pending registrations and OTP codes (dev/demo usage)
// NOTE: For production, persist this in a database or cache (e.g., Redis) with TTLs
const pendingRegistrations = new Map();
const OTP_EXPIRY_SECONDS = Number(process.env.OTP_EXPIRY_SECONDS || 600); // 10 minutes default
const isProduction = process.env.NODE_ENV === 'production';

// In-memory store for forgot-password flows
const pendingPasswordResets = new Map();
const pendingResetTokens = new Map();


// Simple in-memory activity store per user (consider persisting in DB for production)
const userActivities = new Map();
function appendUserActivity(userId, activity) {
  const maxItems = 100;
  const list = userActivities.get(userId) || [];
  const entry = {
    id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    type: activity.type,
    message: activity.message,
    details: activity.details || {},
    createdAt: new Date().toISOString()
  };
  list.unshift(entry);
  if (list.length > maxItems) list.length = maxItems;
  userActivities.set(userId, list);
  return entry;
}

async function getUserFromAuthHeader(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  console.log('[getUserFromAuthHeader] Authorization header:', authHeader);
  console.log('[getUserFromAuthHeader] Extracted token:', token);
  if (!token) {
    console.error('[getUserFromAuthHeader] Missing token');
    return { error: 'Missing token' };
  }
  const { data, error } = await supabaseAnon.auth.getUser(token);
  if (error) {
    console.error('[getUserFromAuthHeader] supabaseAnon.auth.getUser error:', error);
    return { error: 'Invalid token' };
  }
  const user = data.user;
  
  // Get role from profiles table for more accurate role checking
  let userRole = 'user'; // default
  try {
    const { data: profile } = await supabaseAdmin
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .single();
    
    if (profile && profile.role) {
      userRole = profile.role;
    } else {
      // Fallback to user metadata
      userRole = (user?.user_metadata?.role === 'admin') ? 'admin' : 'user';
    }
  } catch (e) {
    console.error('[getUserFromAuthHeader] Error fetching profile role:', e);
    // Fallback to user metadata
    userRole = (user?.user_metadata?.role === 'admin') ? 'admin' : 'user';
  }
  
  return {
    user: {
      sub: user.id,
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name || '',
      role: userRole,
    },
    token,
  };
}

function generateOtpCode() {
  const num = Math.floor(Math.random() * 1000000);
  return String(num).padStart(6, '0');
}

// Helper function to format dates consistently
function formatDate(dateString) {
  if (!dateString) {
    console.log('[formatDate] No date string provided');
    return null;
  }
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      console.log('[formatDate] Invalid date:', dateString);
      return null;
    }
    const formatted = date.toISOString();
    console.log('[formatDate] Formatted date:', dateString, '->', formatted);
    return formatted;
  } catch (error) {
    console.error('[formatDate] Error formatting date:', error, 'Input:', dateString);
    return null;
  }
}

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

async function sendOtpEmail(toEmail, code) {
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

function auth(requiredRole) {
  return async (req, res, next) => {
    const result = await getUserFromAuthHeader(req);
    if (result.error) return res.status(401).json({ message: result.error });
    req.user = result.user;
    
    // Special handling for superadmin role
    if (requiredRole === 'superadmin') {
      if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Forbidden - Super Admin access required' });
      }
      
      // Security check: Ensure only one superadmin exists
      try {
        const { data: superAdmins, error } = await supabaseAdmin
          .from('profiles')
          .select('id')
          .eq('role', 'superadmin');
        
        if (error) {
          console.error('Error checking superadmin count:', error);
          return res.status(500).json({ message: 'Authentication error' });
        }
        
        if (superAdmins.length > 1) {
          console.error('Multiple superadmin accounts detected! IDs:', superAdmins.map(s => s.id));
          return res.status(403).json({ 
            message: 'Security violation: Multiple super admin accounts detected. Please contact system administrator.' 
          });
        }
        
        if (superAdmins.length === 0 || superAdmins[0].id !== req.user.id) {
          return res.status(403).json({ message: 'Forbidden - Invalid super admin account' });
        }
      } catch (e) {
        console.error('Error in superadmin security check:', e);
        return res.status(500).json({ message: 'Authentication error' });
      }
    } else if (requiredRole && req.user.role !== requiredRole) {
      // Allow superadmin to access admin endpoints
      if (requiredRole === 'admin' && req.user.role === 'superadmin') {
        // Superadmin can access admin endpoints
      } else {
        return res.status(403).json({ message: 'Forbidden' });
      }
    }
    
    next();
  };
}

// Images are stored as base64 data directly in the database (like profile pictures)

// Routes
app.get('/', (req, res) => res.json({ ok: true }));

// Internal helper to check if email exists using GoTrue Admin REST (reliable by-email)
async function emailExists(rawEmail) {
  const email = String(rawEmail || '').trim().toLowerCase();
  if (!email) return false;
  try {
    const url = `${supabaseUrl}/auth/v1/admin/users?email=${encodeURIComponent(email)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': supabaseServiceKey,
        'Authorization': `Bearer ${supabaseServiceKey}`,
      },
    });
    if (!resp.ok) {
      console.error('[emailExists] Admin REST error status:', resp.status);
      return false;
    }
    const json = await resp.json().catch(() => ({ users: [] }));
    const users = Array.isArray(json?.users) ? json.users : (Array.isArray(json) ? json : []);
    return users.some(u => (u.email || '').toLowerCase() === email);
  } catch (err) {
    console.error('[emailExists] error:', err);
    return false;
  }
}

// Helper: fetch user object by email via Admin REST
async function getUserByEmail(rawEmail) {
  const email = String(rawEmail || '').trim().toLowerCase();
  if (!email) return null;
  try {
    const url = `${supabaseUrl}/auth/v1/admin/users?email=${encodeURIComponent(email)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': supabaseServiceKey,
        'Authorization': `Bearer ${supabaseServiceKey}`,
      },
    });
    if (!resp.ok) {
      console.error('[getUserByEmail] Admin REST error status:', resp.status);
      return null;
    }
    const json = await resp.json().catch(() => ({ users: [] }));
    const users = Array.isArray(json?.users) ? json.users : (Array.isArray(json) ? json : []);
    const user = users.find(u => (u.email || '').toLowerCase() === email);
    return user || null;
  } catch (err) {
    console.error('[getUserByEmail] error:', err);
    return null;
  }
}

// Check if an email is already registered
app.get('/api/auth/email-available', async (req, res) => {
  try {
    const rawEmail = (req.query.email || '').toString();
    if (!rawEmail) return res.status(400).json({ message: 'Missing email' });
    const exists = await emailExists(rawEmail);
    return res.json({ available: !exists });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start registration: create pending registration and send OTP
app.post('/api/auth/register/start', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const finalRole = role === 'admin' ? 'admin' : 'user';

    // Prevent starting registration if email already exists (reliable by-email)
    const exists = await emailExists(email);
    if (exists) return res.status(409).json({ message: 'Account is already registered' });

    // Create transaction and OTP
    const transactionId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const code = generateOtpCode();
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;

    // Store pending
    pendingRegistrations.set(transactionId, { name, email, phone, password, role: finalRole, code, createdAt: now, expiresAt });

    // Attempt to send email
    try {
      await sendOtpEmail(email, code);
    } catch (mailErr) {
      // In dev/non-production we still allow returning the code for convenience
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send OTP. Please try again later.' });
      }
    }

    res.status(201).json({
      transactionId,
      email,
      expiresInSeconds: OTP_EXPIRY_SECONDS,
      // Expose devCode only in non-production to aid local testing
      ...(isProduction ? {} : { devCode: pendingRegistrations.get(transactionId).code })
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify OTP and complete registration
app.post('/api/auth/register/verify', async (req, res) => {
  try {
    const { transactionId, code, otp, email } = req.body || {};
    const providedCode = (otp || code || '').toString();
    if ((!transactionId && !email) || !providedCode) return res.status(400).json({ message: 'Missing transaction or code' });

    // Find pending by transactionId first; fallback to email lookup for FE compatibility
    let entryKey = transactionId;
    let entry = transactionId ? pendingRegistrations.get(transactionId) : undefined;
    if (!entry && email) {
      for (const [key, value] of pendingRegistrations.entries()) {
        if (value.email === email) { entry = value; entryKey = key; break; }
      }
    }
    if (!entry) return res.status(404).json({ message: 'No pending registration found' });
    if (Date.now() > entry.expiresAt) {
      pendingRegistrations.delete(entryKey);
      return res.status(400).json({ message: 'OTP expired. Please resend.' });
    }
    if (entry.code !== providedCode) return res.status(400).json({ message: 'Invalid OTP' });

    // Create the user (confirmed) via Admin API
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email: entry.email,
      password: entry.password,
      email_confirm: true,
      user_metadata: { name: entry.name, phone: entry.phone, role: entry.role },
    });
    if (createError) return res.status(400).json({ message: createError.message });
    const newUser = created.user;

    // Ensure a profile row exists
    await supabaseAdmin.from('profiles').upsert({ id: newUser.id, name: entry.name, phone: entry.phone, role: entry.role });

    // Sign in to mint an access token for the client
    const { data: signInData, error: signInError } = await supabaseAnon.auth.signInWithPassword({ email: entry.email, password: entry.password });
    if (signInError || !signInData.session) return res.status(500).json({ message: signInError?.message || 'Failed to create session' });

    // Cleanup
    pendingRegistrations.delete(entryKey);

    const accessToken = signInData.session.access_token;
    const userResponse = { 
      token: accessToken, 
      user: { 
        id: newUser.id, 
        name: entry.name, 
        email: entry.email, 
        role: entry.role,
        createdAt: formatDate(newUser.created_at),
        memberSince: formatDate(newUser.created_at),
        lastLoginAt: new Date().toISOString()
      } 
    };
    
    console.log("[POST /api/auth/register/verify] user response:", userResponse);
    console.log("[POST /api/auth/register/verify] Raw new user data:", {
      id: newUser.id,
      email: newUser.email,
      created_at: newUser.created_at,
      formatted_created_at: formatDate(newUser.created_at)
    });
    
    res.json(userResponse);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Resend OTP for an existing pending registration
app.post('/api/auth/register/resend', async (req, res) => {
  try {
    const { transactionId, email } = req.body || {};
    if (!transactionId && !email) return res.status(400).json({ message: 'Missing transaction or email' });

    // Find pending
    let entryKey = transactionId;
    let entry = transactionId ? pendingRegistrations.get(transactionId) : undefined;
    if (!entry && email) {
      for (const [key, value] of pendingRegistrations.entries()) {
        if (value.email === email) { entry = value; entryKey = key; break; }
      }
    }
    if (!entry) return res.status(404).json({ message: 'No pending registration found' });

    // Generate a new code and extend expiry
    entry.code = generateOtpCode();
    entry.expiresAt = Date.now() + OTP_EXPIRY_SECONDS * 1000;
    pendingRegistrations.set(entryKey, entry);

    try {
      await sendOtpEmail(entry.email, entry.code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send OTP. Please try again later.' });
      }
    }

    res.json({ expiresInSeconds: OTP_EXPIRY_SECONDS, ...(isProduction ? {} : { devCode: entry.code }) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (error || !data.session) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = data.session.access_token;
    const { data: userData } = await supabaseAnon.auth.getUser(accessToken);
    const meta = userData?.user?.user_metadata || {};
    
    // Get role from profiles table for more accurate role checking
    let userRole = 'user'; // default
    try {
      const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('role')
        .eq('id', userData?.user?.id)
        .single();
      
      if (profile && profile.role) {
        userRole = profile.role;
      } else {
        // Fallback to user metadata
        userRole = (meta.role === 'admin') ? 'admin' : 'user';
      }
    } catch (e) {
      console.error('Error fetching profile role during login:', e);
      // Fallback to user metadata
      userRole = (meta.role === 'admin') ? 'admin' : 'user';
    }
    
    // Security check for superadmin - ensure only one exists
    if (userRole === 'superadmin') {
      try {
        const { data: superAdmins, error: saError } = await supabaseAdmin
          .from('profiles')
          .select('id')
          .eq('role', 'superadmin');
        
        if (saError) {
          console.error('Error checking superadmin count during login:', saError);
          return res.status(500).json({ message: 'Authentication error' });
        }
        
        if (superAdmins.length > 1) {
          console.error('Multiple superadmin accounts detected during login! IDs:', superAdmins.map(s => s.id));
          return res.status(403).json({ 
            message: 'Security violation: Multiple super admin accounts detected. Please contact system administrator.' 
          });
        }
        
        if (superAdmins.length === 0 || superAdmins[0].id !== userData?.user?.id) {
          return res.status(403).json({ message: 'Invalid super admin account' });
        }
      } catch (e) {
        console.error('Error in superadmin security check during login:', e);
        return res.status(500).json({ message: 'Authentication error' });
      }
    }
    
    const userResponse = { 
      token: accessToken, 
      user: { 
        id: userData?.user?.id, 
        name: meta.name || '', 
        email: userData?.user?.email, 
        role: userRole,
        createdAt: formatDate(userData?.user?.created_at),
        memberSince: formatDate(userData?.user?.created_at),
        lastLoginAt: new Date().toISOString()
      } 
    };
    
    console.log("[POST /api/auth/login] user response:", userResponse);
    console.log("[POST /api/auth/login] Raw user data:", {
      id: userData?.user?.id,
      email: userData?.user?.email,
      created_at: userData?.user?.created_at,
      formatted_created_at: formatDate(userData?.user?.created_at)
    });
    
    res.json(userResponse);
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Start forgot password: create pending reset and send OTP
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: 'Missing email' });

    const user = await getUserByEmail(email);
    if (!user) {
      // For this app we return 404 so FE can show proper error
      return res.status(404).json({ message: 'No account found with that email' });
    }

    const transactionId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const code = generateOtpCode();
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;

    pendingPasswordResets.set(transactionId, { email: user.email, code, createdAt: now, expiresAt });

    try {
      await sendOtpEmail(user.email, code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send reset code. Please try again later.' });
      }
    }

    res.status(201).json({
      transactionId,
      email: user.email,
      expiresInSeconds: OTP_EXPIRY_SECONDS,
      ...(isProduction ? {} : { devCode: code })
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify forgot password OTP -> issue reset token
app.post('/api/auth/forgot-password/verify', async (req, res) => {
  try {
    const { transactionId, code, otp } = req.body || {};
    const providedCode = (otp || code || '').toString();
    if (!transactionId || !providedCode) return res.status(400).json({ message: 'Missing transaction or code' });

    const entry = pendingPasswordResets.get(transactionId);
    if (!entry) return res.status(404).json({ message: 'No pending reset found' });
    if (Date.now() > entry.expiresAt) {
      pendingPasswordResets.delete(transactionId);
      return res.status(400).json({ message: 'OTP expired. Please resend.' });
    }
    if (entry.code !== providedCode) return res.status(400).json({ message: 'Invalid OTP' });

    const resetToken = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;
    pendingResetTokens.set(resetToken, { email: entry.email, createdAt: now, expiresAt });

    // Cleanup OTP entry
    pendingPasswordResets.delete(transactionId);

    res.json({ resetToken, email: entry.email, expiresInSeconds: OTP_EXPIRY_SECONDS });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Resend forgot password OTP
app.post('/api/auth/forgot-password/resend', async (req, res) => {
  try {
    const { transactionId } = req.body || {};
    if (!transactionId) return res.status(400).json({ message: 'Missing transaction' });

    const entry = pendingPasswordResets.get(transactionId);
    if (!entry) return res.status(404).json({ message: 'No pending reset found' });

    entry.code = generateOtpCode();
    entry.expiresAt = Date.now() + OTP_EXPIRY_SECONDS * 1000;
    pendingPasswordResets.set(transactionId, entry);

    try {
      await sendOtpEmail(entry.email, entry.code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to resend reset code. Please try again later.' });
      }
    }

    res.json({ expiresInSeconds: OTP_EXPIRY_SECONDS, ...(isProduction ? {} : { devCode: entry.code }) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Perform password reset with reset token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body || {};
    if (!resetToken || !newPassword) return res.status(400).json({ message: 'Missing reset token or new password' });
    if (String(newPassword).length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });

    const entry = pendingResetTokens.get(resetToken);
    if (!entry) return res.status(400).json({ message: 'Invalid or expired reset token' });
    if (Date.now() > entry.expiresAt) {
      pendingResetTokens.delete(resetToken);
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const user = await getUserByEmail(entry.email);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(user.id, { password: String(newPassword) });
    if (updateError) return res.status(400).json({ message: updateError.message });

    // Cleanup reset token after successful update
    pendingResetTokens.delete(resetToken);

    res.json({ message: 'Password updated' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/me', auth(), async (req, res) => {
  try {
    // Get user data from auth (for email)
    const { data: userData, error: authError } = await supabaseAdmin.auth.admin.getUserById(req.user.sub);
    if (authError) return res.status(400).json({ message: authError.message });
    
    // Debug: Log the complete Supabase auth response
    console.log("[GET /api/auth/me] Complete Supabase auth response:", JSON.stringify(userData, null, 2));
    console.log("[GET /api/auth/me] Available user fields:", Object.keys(userData.user || {}));
    console.log("[GET /api/auth/me] All user field values:", Object.fromEntries(
      Object.entries(userData.user || {}).map(([key, value]) => [key, typeof value === 'string' ? value : typeof value])
    ));
    console.log("[GET /api/auth/me] All user field values (detailed):", Object.fromEntries(
      Object.entries(userData.user || {}).map(([key, value]) => [key, {
        type: typeof value,
        value: value,
        isDate: value instanceof Date,
        isString: typeof value === 'string',
        length: typeof value === 'string' ? value.length : undefined
      }])
    ));
    console.log("[GET /api/auth/me] Searching for date fields:");
    Object.entries(userData.user || {}).forEach(([key, value]) => {
      if (typeof value === 'string' && (key.toLowerCase().includes('created') || key.toLowerCase().includes('date'))) {
        console.log(`  - Found potential date field: ${key} = ${value}`);
      }
    });
    console.log("[GET /api/auth/me] All field names (case-insensitive search):");
    Object.keys(userData.user || {}).forEach(key => {
      console.log(`  - ${key}`);
    });
    console.log("[GET /api/auth/me] Checking for common date field variations:");
    const commonDateFields = ['created_at', 'createdAt', 'created', 'created_at_iso', 'created_at_utc', 'created_at_local'];
    commonDateFields.forEach(field => {
      console.log(`  - ${field}: ${userData.user?.[field]}`);
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'created':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('created')) {
        console.log(`  - Found field with 'created': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'date':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('date')) {
        console.log(`  - Found field with 'date': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'time':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('time')) {
        console.log(`  - Found field with 'time': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'stamp':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('stamp')) {
        console.log(`  - Found field with 'stamp': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'when':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('when')) {
        console.log(`  - Found field with 'when': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'at':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('at')) {
        console.log(`  - Found field with 'at': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'on':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('on')) {
        console.log(`  - Found field with 'on': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'since':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('since')) {
        console.log(`  - Found field with 'since': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'from':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('from')) {
        console.log(`  - Found field with 'from': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'to':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('to')) {
        console.log(`  - Found field with 'to': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] Checking for any field containing 'in':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('in')) {
        console.log(`  - Found field with 'in': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/me] User created_at field:", userData.user?.created_at);
    console.log("[GET /api/auth/me] User created_at type:", typeof userData.user?.created_at);
    console.log("[GET /api/auth/me] User createdAt field:", userData.user?.createdAt);
    console.log("[GET /api/auth/me] User created field:", userData.user?.created);
    console.log("[GET /api/auth/me] User created_at_iso field:", userData.user?.created_at_iso);
    console.log("[GET /api/auth/me] User metadata:", userData.user?.user_metadata);
    console.log("[GET /api/auth/me] User app_metadata:", userData.user?.app_metadata);
    console.log("[GET /api/auth/me] Raw created_at value:", userData.user?.created_at);
    console.log("[GET /api/auth/me] Raw created_at value type:", typeof userData.user?.created_at);
    console.log("[GET /api/auth/me] Raw created_at value length:", userData.user?.created_at?.length);

    // Get profile data from profiles table
    const { data: profileData, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('id, name, phone, location, company, role, profile_pic')
      .eq('id', req.user.sub)
      .single();
    
    if (profileError) return res.status(400).json({ message: profileError.message });

    // Combine auth data with profile data
    const userObj = {
      ...profileData,
      email: userData.user.email, // Get email from auth.users
      avatar: profileData?.profile_pic,
      createdAt: formatDate(userData.user.created_at), // Add account creation date from auth.users
      memberSince: formatDate(userData.user.created_at), // Add member since date for frontend compatibility
      lastLoginAt: new Date().toISOString() // Add current login time
    };
    
    // Debug: Log the date processing
    console.log("[GET /api/auth/me] Date processing debug:");
    console.log("  - Raw created_at:", userData.user.created_at);
    console.log("  - Formatted createdAt:", userObj.createdAt);
    console.log("  - Formatted memberSince:", userObj.memberSince);
    console.log("  - lastLoginAt:", userObj.lastLoginAt);
    console.log("[GET /api/auth/me] user response:", userObj);
    console.log("[GET /api/auth/me] Raw auth user data:", {
      id: userData.user.id,
      email: userData.user.email,
      created_at: userData.user.created_at,
      formatted_created_at: formatDate(userData.user.created_at)
    });
    console.log("[GET /api/auth/me] Complete user object being sent:", JSON.stringify(userObj, null, 2));
    res.json({ user: userObj });
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Recent activity endpoint
app.get('/api/auth/activity', auth(), async (req, res) => {
  try {
    const userId = req.user.sub;
    const limit = Number(req.query.limit || 20);
    const list = (userActivities.get(userId) || []).slice(0, Math.max(1, Math.min(100, limit)));
    res.json({ activities: list });
  } catch (e) {
    console.error('Server error fetching activity:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/auth/me', auth(), async (req, res) => {
  try {
    // Debug logs for troubleshooting 401 errors
    console.log('[PUT /api/auth/me] Authorization header:', req.headers.authorization);
    console.log('[PUT /api/auth/me] req.user:', req.user);

    const { name, email, phone, location, company, avatar } = req.body;
    const userId = req.user.sub;

    // Validate avatar size if provided
    if (avatar && typeof avatar === 'string') {
      // Check if it's a data URL
      if (avatar.startsWith('data:image/')) {
        const base64Length = avatar.length - (avatar.indexOf(',') + 1);
        const sizeInBytes = Math.ceil((base64Length * 3) / 4);
        const sizeInMB = sizeInBytes / (1024 * 1024);
        
        if (sizeInMB > 1) { // 1MB limit for compressed images
          return res.status(400).json({ 
            message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
          });
        }
      }
    }

    // Update profile fields in profiles table if any profile data is provided
    if (name !== undefined || phone !== undefined || location !== undefined || company !== undefined || avatar !== undefined) {
      const profileUpdateFields = {};
      // Fetch current profile to compute diffs for activity log
      const { data: currentProfile } = await supabaseAdmin
        .from('profiles')
        .select('name, phone, location, company, profile_pic')
        .eq('id', userId)
        .single();
      if (name !== undefined) profileUpdateFields.name = name;
      if (phone !== undefined) profileUpdateFields.phone = phone;
      if (location !== undefined) profileUpdateFields.location = location;
      if (company !== undefined) profileUpdateFields.company = company;
      if (avatar !== undefined) profileUpdateFields.profile_pic = avatar;

      const { error: profileError } = await supabaseAdmin
        .from('profiles')
        .update(profileUpdateFields)
        .eq('id', userId);

      if (profileError) return res.status(400).json({ message: profileError.message });

      // Compute changed fields
      const changed = {};
      if (currentProfile) {
        if (name !== undefined && currentProfile.name !== name) changed.name = { from: currentProfile.name, to: name };
        if (phone !== undefined && currentProfile.phone !== phone) changed.phone = { from: currentProfile.phone, to: phone };
        if (location !== undefined && currentProfile.location !== location) changed.location = { from: currentProfile.location, to: location };
        if (company !== undefined && currentProfile.company !== company) changed.company = { from: currentProfile.company, to: company };
        if (avatar !== undefined && currentProfile.profile_pic !== avatar) changed.avatar = { from: currentProfile.profile_pic, to: avatar };
      }
      // Append activity if there are changes
      if (Object.keys(changed).length > 0) {
        appendUserActivity(userId, {
          type: 'profile_update',
          message: 'Updated profile information',
          details: { changed }
        });
      }
    }

    // Update email in auth.users table if provided and different
    if (email && email !== req.user.email) {
      const { error: emailError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        email: email
      });
      if (emailError) return res.status(400).json({ message: emailError.message });
      appendUserActivity(userId, {
        type: 'email_update',
        message: 'Updated account email',
        details: { from: req.user.email, to: email }
      });
    }

    // Fetch and return updated profile data
    const { data: updatedProfile, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, name, phone, location, company, role, profile_pic')
      .eq('id', userId)
      .single();
    
    if (fetchError) return res.status(400).json({ message: fetchError.message });
    
    res.json({ 
      message: 'Profile updated successfully',
      profile: {
        ...updatedProfile,
        avatar: updatedProfile.profile_pic
      }
    });
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Password change endpoint
app.post('/api/auth/change-password', auth(), async (req, res) => {
  try {
    console.log('[POST /api/auth/change-password] User ID:', req.user.sub);

    const { currentPassword, newPassword } = req.body;
    const userId = req.user.sub;

    // Validate required fields
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        message: 'Both current password and new password are required' 
      });
    }

    // Check if new password is same as current
    if (currentPassword === newPassword) {
      return res.status(400).json({ 
        message: 'New password must be different from current password' 
      });
    }

    // Create a fresh Supabase client for password verification (use ESM import)
    const tempClient = createClient(
      supabaseUrl,
      supabaseAnonKey,
      { auth: { persistSession: false } }
    );

    // Verify current password
    const { data: signInData, error: signInError } = await tempClient.auth.signInWithPassword({
      email: req.user.email,
      password: currentPassword
    });
    
    if (signInError) {
      console.log('Current password verification failed:', signInError.message);
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Clean up the temporary session
    await tempClient.auth.signOut();

    // Update password using admin API
    const { data: updateData, error: passwordError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
      password: newPassword
    });
    
    if (passwordError) {
      console.error('Password update error:', passwordError);
      return res.status(400).json({ 
        message: 'Failed to update password: ' + passwordError.message 
      });
    }

    console.log(`Password changed successfully for user: ${userId}`);
    appendUserActivity(userId, {
      type: 'password_change',
      message: 'Changed account password',
      details: {}
    });
    res.json({ message: 'Password changed successfully' });

  } catch (e) {
    console.error('Server error in password change:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});
// Updated profile fetch route to get email from auth system
app.get('/api/auth/profile', auth(), async (req, res) => {
  try {
    const userId = req.user.sub;
    
    // Get user data from auth (for email)
    const { data: userData, error: authError } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (authError) {
      console.error('Auth fetch error:', authError);
      return res.status(400).json({ message: authError.message });
    }
    
    // Debug: Log the complete Supabase auth response
    console.log("[GET /api/auth/profile] Complete Supabase auth response:", JSON.stringify(userData, null, 2));
    console.log("[GET /api/auth/profile] Available user fields:", Object.keys(userData.user || {}));
    console.log("[GET /api/auth/profile] All user field values:", Object.fromEntries(
      Object.entries(userData.user || {}).map(([key, value]) => [key, typeof value === 'string' ? value : typeof value])
    ));
    console.log("[GET /api/auth/profile] All user field values (detailed):", Object.fromEntries(
      Object.entries(userData.user || {}).map(([key, value]) => [key, {
        type: typeof value,
        value: value,
        isDate: value instanceof Date,
        isString: typeof value === 'string',
        length: typeof value === 'string' ? value.length : undefined
      }])
    ));
    console.log("[GET /api/auth/profile] Searching for date fields:");
    Object.entries(userData.user || {}).forEach(([key, value]) => {
      if (typeof value === 'string' && (key.toLowerCase().includes('created') || key.toLowerCase().includes('date'))) {
        console.log(`  - Found potential date field: ${key} = ${value}`);
      }
    });
    console.log("[GET /api/auth/profile] All field names (case-insensitive search):");
    Object.keys(userData.user || {}).forEach(key => {
      console.log(`  - ${key}`);
    });
    console.log("[GET /api/auth/profile] Checking for common date field variations:");
    const commonDateFields = ['created_at', 'createdAt', 'created', 'created_at_iso', 'created_at_utc', 'created_at_local'];
    commonDateFields.forEach(field => {
      console.log(`  - ${field}: ${userData.user?.[field]}`);
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'created':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('created')) {
        console.log(`  - Found field with 'created': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'date':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('date')) {
        console.log(`  - Found field with 'date': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'time':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('time')) {
        console.log(`  - Found field with 'time': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'stamp':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('stamp')) {
        console.log(`  - Found field with 'stamp': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'when':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('when')) {
        console.log(`  - Found field with 'when': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'at':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('at')) {
        console.log(`  - Found field with 'at': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'on':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('on')) {
        console.log(`  - Found field with 'on': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'since':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('since')) {
        console.log(`  - Found field with 'since': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'from':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('from')) {
        console.log(`  - Found field with 'from': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] Checking for any field containing 'to':");
    Object.keys(userData.user || {}).forEach(key => {
      if (key.toLowerCase().includes('to')) {
        console.log(`  - Found field with 'to': ${key} = ${userData.user[key]}`);
      }
    });
    console.log("[GET /api/auth/profile] User created_at field:", userData.user?.created_at);
    console.log("[GET /api/auth/profile] User created_at type:", typeof userData.user?.created_at);
    console.log("[GET /api/auth/profile] User createdAt field:", userData.user?.createdAt);
    console.log("[GET /api/auth/profile] User created field:", userData.user?.created);
    console.log("[GET /api/auth/profile] User created_at_iso field:", userData.user?.created_at_iso);
    console.log("[GET /api/auth/profile] User metadata:", userData.user?.user_metadata);
    console.log("[GET /api/auth/profile] User app_metadata:", userData.user?.app_metadata);
    console.log("[GET /api/auth/profile] Raw created_at value:", userData.user?.created_at);
    console.log("[GET /api/auth/profile] Raw created_at value type:", typeof userData.user?.created_at);
    console.log("[GET /api/auth/profile] Raw created_at value length:", userData.user?.created_at?.length);
    
    // Get profile data from profiles table
    const { data: profileData, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('*')
      .eq('id', userId)
      .single();

    if (profileError) {
      console.error('Profile fetch error:', profileError);
      if (profileError.code === 'PGRST116') {
        return res.status(404).json({ message: 'Profile not found' });
      }
      return res.status(400).json({ message: profileError.message });
    }

    const userResponse = {
      user: {
        id: profileData.id,
        name: profileData.name,
        email: userData.user.email, // Get email from auth system
        phone: profileData.phone,
        company: profileData.company,
        location: profileData.location,
        profile_pic: profileData.profile_pic,
        avatar: profileData.profile_pic, // Include both for compatibility
        role: profileData.role,
        createdAt: formatDate(userData.user.created_at), // Add account creation date from auth.users
        memberSince: formatDate(userData.user.created_at), // Add member since date for frontend compatibility
        lastLoginAt: new Date().toISOString() // Add current login time
      }
    };
    
    // Debug: Log the date processing
    console.log("[GET /api/auth/profile] Date processing debug:");
    console.log("  - Raw created_at:", userData.user.created_at);
    console.log("  - Formatted createdAt:", userResponse.user.createdAt);
    console.log("  - Formatted memberSince:", userResponse.user.memberSince);
    console.log("  - lastLoginAt:", userResponse.user.lastLoginAt);
    
    console.log("[GET /api/auth/profile] user response:", userResponse);
    console.log("[GET /api/auth/profile] Raw auth user data:", {
      id: userData.user.id,
      email: userData.user.email,
      created_at: userData.user.created_at,
      formatted_created_at: formatDate(userData.user.created_at)
    });
    console.log("[GET /api/auth/profile] Complete user object being sent:", JSON.stringify(userResponse, null, 2));
    
    res.json(userResponse);
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});
// Example protected routes
app.get('/api/admin/overview', auth('admin'), (req, res) => {
  res.json({ message: 'admin data' });
});

app.get('/api/user/overview', auth('user'), (req, res) => {
  res.json({ message: 'user data' });
});

function mapTurfRowToApi(row) {
  let finalLocation;
  let locationAddress;

  // Case 1: The new coordinate object exists and is valid. Use it.
  if (row.location_coordinates && typeof row.location_coordinates === 'object' && row.location_coordinates.address) {
    finalLocation = {
      address: row.location_coordinates.address,
      latitude: row.location_coordinates.latitude,
      longitude: row.location_coordinates.longitude,
    };
    locationAddress = row.location_coordinates.address;
  } 
  // Case 2: Fallback to the old location string if coordinate object is missing.
  else if (typeof row.location === 'string') {
    finalLocation = {
      address: row.location,
      latitude: null, // Mark coordinates as unavailable
      longitude: null,
    };
    locationAddress = row.location;
  } 
  // Case 3: Default to an empty object if no location data is found at all.
  else {
     finalLocation = {
      address: 'Location not available',
      latitude: null,
      longitude: null,
    };
    locationAddress = 'Location not available';
  }

  const result = {
    _id: row.id,
    id: row.id, // Add id field for frontend compatibility
    name: row.name,
    location: locationAddress, // Send as string for frontend compatibility
    locationCoordinates: finalLocation, // Keep object version for coordinate features
    description: row.description || '',
    images: Array.isArray(row.images) ? row.images : [],
    pricePerHour: Number(row.price_per_hour) || 0, // Ensure it's a number
    operatingHours: row.operating_hours || { open: '06:00', close: '22:00' },
    amenities: Array.isArray(row.amenities) ? row.amenities : [],
    createdAt: formatDate(row.created_at),
    updatedAt: formatDate(row.updated_at)
  };
  
  // Log date formatting for debugging
  if (row.id) {
    console.log(`[mapTurfRowToApi] Turf ${row.id} dates:`, {
      raw_created_at: row.created_at,
      formatted_created_at: result.createdAt,
      raw_updated_at: row.updated_at,
      formatted_updated_at: result.updatedAt
    });
  }
  
  return result;


}

function mapBookingRowToApi(row, turfNameMap = {}) {
  return {
    id: row.id,
    turfId: row.turf_id,
    turfName: row.turf_name || turfNameMap[row.turf_id] || row.turf_id,
    userName: row.user_name,
    userEmail: row.user_email,
    userPhone: row.user_phone,
    bookingDate: row.booking_date,
    startTime: row.start_time,
    endTime: row.end_time,
    totalAmount: Number(row.total_amount || 0),
    paymentStatus: row.payment_status || 'completed',
    paymentMethod: row.payment_method || null,
    bookingStatus: row.booking_status || 'confirmed',
    razorpayOrderId: row.razorpay_order_id || null,
    razorpayPaymentId: row.razorpay_payment_id || null,
    cancelledAt: row.cancelled_at || null,
    cancellationReason: row.cancellation_reason || null,
    refundAmount: row.refund_amount ? Number(row.refund_amount) : undefined,
    canCancel: row.booking_status === 'confirmed' ? canCancelBooking(row.booking_date, row.start_time) : false,
    createdAt: row.created_at,
    // Owner settlement information
    ownerSettlementStatus: row.owner_settlement_status || 'pending',
    payoutAmount: row.payout_amount ? Number(row.payout_amount) : null,
    settledAt: row.settled_at || null,
  };
}

// Helper function to check if booking can be cancelled (2 hours before start time)
function canCancelBooking(bookingDate, startTime) {
  try {
    if (!bookingDate || !startTime) return false;
    
    const now = new Date();
    // Handle both HH:mm and HH:mm:ss time formats
    const cleanStartTime = startTime.split(':').slice(0, 2).join(':');
    const bookingDateTime = new Date(`${bookingDate}T${cleanStartTime}:00`);
    
    // Check if date is valid and booking is in the future
    if (isNaN(bookingDateTime.getTime()) || bookingDateTime <= now) {
      return false;
    }
    
    const timeDiff = bookingDateTime.getTime() - now.getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    
    return hoursDiff >= 2; // Can cancel if more than 2 hours before booking
  } catch (error) {
    console.error('Error in canCancelBooking:', error);
    return false;
  }
}

// Helper function to calculate refund amount
function calculateRefundAmount(totalAmount, bookingDate, startTime) {
  const canCancel = canCancelBooking(bookingDate, startTime);
  return canCancel ? totalAmount : 0;
}

// Helper function to verify Razorpay signature
function verifyRazorpaySignature(orderId, paymentId, signature) {
  if (!razorpayKeySecret) return false;
  
  const body = orderId + "|" + paymentId;
  const expectedSignature = crypto
    .createHmac("sha256", razorpayKeySecret)
    .update(body.toString())
    .digest("hex");
  
  return expectedSignature === signature;
}

function timeToMinutes(t) {
  if (!t) return 0;
  const [h, m] = t.split(':').map(Number);
  return h * 60 + (m || 0);
}

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the Earth in kilometers
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const distance = R * c; // Distance in kilometers
  return distance;
}

// Fixed public turfs endpoint
app.get('/api/turfs/public', async (req, res) => {
  try {
    console.log('[GET /api/turfs/public] Request received with query:', req.query);
    const { lat, lon, radius } = req.query;
    
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .order('created_at', { ascending: false });
      
    console.log('[GET /api/turfs/public] Database query result:', { 
      dataCount: data?.length || 0, 
      error: error?.message || null 
    });
      
    if (error) return res.status(400).json({ message: error.message });

    let turfs = (data || []).map(mapTurfRowToApi);
    console.log('[GET /api/turfs/public] Mapped turfs count:', turfs.length);

    // If location filtering is requested, filter by radius
    if (lat && lon && radius) {
      const userLat = parseFloat(lat);
      const userLon = parseFloat(lon);
      const filterRadius = parseFloat(radius);

      turfs = turfs.filter(turf => {
        // Check if turf has coordinate data
        const turfLocation = turf.locationCoordinates;
        if (typeof turfLocation === 'object' && 
            turfLocation.latitude && 
            turfLocation.longitude) {
          const distance = calculateDistance(
            userLat, 
            userLon, 
            turfLocation.latitude, 
            turfLocation.longitude
          );
          return distance <= filterRadius;
        }
        return true; // Include turfs without coordinates (backward compatibility)
      });
    }

    console.log('[GET /api/turfs/public] Final turfs count after filtering:', turfs.length);
    res.json({ turfs });
  } catch (e) {
    console.error('Error fetching public turfs:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create turf endpoint with base64 image validation
app.post('/api/turfs', auth('admin'), async (req, res) => {
  try {
    const { name, location, description, images, pricePerHour, operatingHours, amenities } = req.body;
    
    // Validate required fields
    if (!name || !location || !pricePerHour) {
      return res.status(400).json({ message: 'Name, location, and price per hour are required' });
    }

    if (!operatingHours || !operatingHours.open || !operatingHours.close) {
      return res.status(400).json({ message: 'Operating hours (open and close) are required' });
    }

    // Validate images if provided (similar to profile picture validation)
    if (images && Array.isArray(images)) {
      for (const image of images) {
        if (image && typeof image === 'string') {
          // Check if it's a base64 data URL
          if (image.startsWith('data:image/')) {
            const base64Length = image.length - (image.indexOf(',') + 1);
            const sizeInBytes = Math.ceil((base64Length * 3) / 4);
            const sizeInMB = sizeInBytes / (1024 * 1024);
            
            if (sizeInMB > 5) { // 5MB limit for images
              return res.status(400).json({ 
                message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
              });
            }
          }
        }
      }
    }

    // Prepare location data for both old and new format
    let locationString = '';
    let locationCoordinates = null;

    if (typeof location === 'string') {
      locationString = location;
    } else if (location && typeof location === 'object' && location.address) {
      locationString = location.address;
      locationCoordinates = {
        address: location.address,
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      };
    } else {
      return res.status(400).json({ message: 'Invalid location format' });
    }

    const payload = {
      name: name.trim(),
      location: locationString,
      location_coordinates: locationCoordinates,
      description: description || '',
      images: Array.isArray(images) ? images.filter(img => img && img.trim()) : [],
      price_per_hour: Number(pricePerHour),
      operating_hours: operatingHours,
      amenities: Array.isArray(amenities) ? amenities.filter(a => a.trim()) : [],
      owner: req.user.sub,
    };

    const { data, error } = await supabaseAdmin.from('turfs').insert(payload).select().single();
    if (error) {
      console.error('Database error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.status(201).json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error creating turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update turf endpoint with base64 image validation
app.put('/api/turfs/:id', auth('admin'), async (req, res) => {
  try {
    const { name, location, description, images, pricePerHour, operatingHours, amenities } = req.body;
    
    // Validate required fields
    if (!name || !location || !pricePerHour) {
      return res.status(400).json({ message: 'Name, location, and price per hour are required' });
    }

    if (!operatingHours || !operatingHours.open || !operatingHours.close) {
      return res.status(400).json({ message: 'Operating hours (open and close) are required' });
    }

    // Validate images if provided (similar to profile picture validation)
    if (images && Array.isArray(images)) {
      for (const image of images) {
        if (image && typeof image === 'string') {
          // Check if it's a base64 data URL
          if (image.startsWith('data:image/')) {
            const base64Length = image.length - (image.indexOf(',') + 1);
            const sizeInBytes = Math.ceil((base64Length * 3) / 4);
            const sizeInMB = sizeInBytes / (1024 * 1024);
            
            if (sizeInMB > 5) { // 5MB limit for images
              return res.status(400).json({ 
                message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
              });
            }
          }
        }
      }
    }

    // Check ownership first
    const { data: existingTurf, error: fetchError } = await supabaseAdmin
      .from('turfs')
      .select('owner')
      .eq('id', req.params.id)
      .single();

    if (fetchError && fetchError.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    if (existingTurf.owner !== req.user.sub) {
      return res.status(403).json({ message: 'Not authorized to update this turf' });
    }

    // Prepare location data for both old and new format
    let locationString = '';
    let locationCoordinates = null;

    if (typeof location === 'string') {
      locationString = location;
    } else if (location && typeof location === 'object' && location.address) {
      locationString = location.address;
      locationCoordinates = {
        address: location.address,
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      };
    }

    const payload = {
      name: name.trim(),
      location: locationString,
      location_coordinates: locationCoordinates,
      description: description || '',
      images: Array.isArray(images) ? images.filter(img => img && img.trim()) : [],
      price_per_hour: Number(pricePerHour),
      operating_hours: operatingHours,
      amenities: Array.isArray(amenities) ? amenities.filter(a => a.trim()) : []
    };

    // Update the turf
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .update(payload)
      .eq('id', req.params.id)
      .eq('owner', req.user.sub)
      .select()
      .single();

    if (error) {
      console.error('Update error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error updating turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fixed get my turfs endpoint
app.get('/api/turfs/mine', auth('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .eq('owner', req.user.sub)
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Fetch mine error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turfs: (data || []).map(mapTurfRowToApi) });
  } catch (e) {
    console.error('Error fetching user turfs:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fixed get single turf endpoint
app.get('/api/turfs/:id', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (error && error.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (error) {
      console.error('Fetch turf error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error fetching turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Availability for a turf on a specific date: returns booked hour starts ["14:00", ...]
app.get('/api/turfs/:id/availability', async (req, res) => {
  try {
    const turfId = req.params.id;
    const date = req.query.date;
    if (!date) return res.status(400).json({ message: 'date (YYYY-MM-DD) is required' });
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time, booking_status')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
    if (error) return res.status(400).json({ message: error.message });
    const bookedTimes = [];
    (data || []).forEach(b => {
      const s = timeToMinutes(b.start_time);
      const e = timeToMinutes(b.end_time);
      for (let m = s; m < e; m += 60) {
        const hh = String(Math.floor(m / 60)).padStart(2, '0');
        bookedTimes.push(`${hh}:00`);
      }
    });
    res.json({ bookedTimes: Array.from(new Set(bookedTimes)) });
  } catch (e) {
    console.error('Error fetching availability:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a booking
app.post('/api/bookings', auth(), async (req, res) => {
  try {
    const {
      turfId,
      date,
      startTime,
      endTime,
      totalAmount,
      userName,
      userEmail,
      userPhone,
      paymentMethod = 'cash',
    } = req.body || {};

    if (!turfId || !date || !startTime || !endTime || !userName || !userEmail || !paymentMethod) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Validate payment method
    if (!['cash', 'online'].includes(paymentMethod)) {
      return res.status(400).json({ message: 'Invalid payment method' });
    }

    // Basic sanity: end after start and hourly increments
    const sMin = timeToMinutes(startTime);
    const eMin = timeToMinutes(endTime);
    if (!(eMin > sMin) || ((eMin - sMin) % 60) !== 0) {
      return res.status(400).json({ message: 'Invalid time range' });
    }

    // Ensure turf exists
    const { data: turfRow, error: turfErr } = await supabaseAdmin
      .from('turfs')
      .select('id, name, operating_hours, price_per_hour')
      .eq('id', turfId)
      .single();
    if (turfErr) return res.status(400).json({ message: turfErr.message });
    if (!turfRow) return res.status(404).json({ message: 'Turf not found' });

    // Availability check: no overlapping confirmed bookings for same date
    // (tentative bookings older than 15 minutes are ignored)
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    
    const { data: existing, error: conflictErr } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time, booking_status, created_at')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
    
    if (conflictErr) return res.status(400).json({ message: conflictErr.message });
    
    const conflict = (existing || []).some(b => {
      // Skip old tentative bookings (expired)
      if (b.booking_status === 'tentative' && b.created_at < fifteenMinutesAgo) {
        return false;
      }
      
      const bs = timeToMinutes(b.start_time);
      const be = timeToMinutes(b.end_time);
      // Overlap if start < be and end > bs
      return sMin < be && eMin > bs;
    });
    
    if (conflict) return res.status(409).json({ message: 'Selected time overlaps an existing booking' });

    // Default total if not provided
    const durationHours = (eMin - sMin) / 60;
    const computedTotal = Number(totalAmount ?? (Number(turfRow.price_per_hour) * durationHours));

    // Set payment status and booking status based on payment method
    let paymentStatus, bookingStatus;
    
    if (paymentMethod === 'cash') {
      // Cash payments: create booking immediately with pending payment
      paymentStatus = 'pending';
      bookingStatus = 'confirmed';
      
      // Create the booking record for cash payments
      const payload = {
        turf_id: turfId,
        turf_name: turfRow.name,
        user_id: req.user.sub,
        user_name: userName,
        user_email: userEmail,
        user_phone: userPhone || null,
        booking_date: date,
        start_time: startTime,
        end_time: endTime,
        total_amount: computedTotal,
        payment_status: paymentStatus,
        payment_method: paymentMethod,
        booking_status: bookingStatus,
        // Cash payments don't need owner settlements (handled directly at turf)
        payout_amount: null,
        owner_settlement_status: 'completed', // Cash payments are settled immediately
      };

      const { data: created, error: createErr } = await supabaseAdmin
        .from('bookings')
        .insert(payload)
        .select('*')
        .single();
      if (createErr) return res.status(400).json({ message: createErr.message });

      const api = mapBookingRowToApi(created, { [turfId]: turfRow.name });
      res.status(201).json({ booking: api });
      
    } else {
      // Online payments: don't create booking record yet, just return booking details for payment
      // The booking will be created in the payment verification endpoint
      paymentStatus = 'pending';
      bookingStatus = 'tentative';
      
      const bookingDetails = {
        turfId,
        turfName: turfRow.name,
        userId: req.user.sub,
        userName,
        userEmail,
        userPhone: userPhone || null,
        bookingDate: date,
        startTime,
        endTime,
        totalAmount: computedTotal,
        paymentMethod,
        paymentStatus,
        bookingStatus,
      };
      
      // Return booking details for payment processing, but don't create DB record yet
      res.status(200).json({ 
        booking: bookingDetails,
        message: 'Booking details prepared. Complete payment to confirm booking.',
        requiresPayment: true
      });
    }
  } catch (e) {
    console.error('Error creating booking:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Current user's bookings
app.get('/api/bookings/mine', auth(), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('user_id', req.user.sub)
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ message: error.message });

    // Fetch turf names for mapping
    const turfIds = Array.from(new Set((data || []).map(b => b.turf_id)));
    let turfNameMap = {};
    if (turfIds.length) {
      const { data: turfs, error: turfErr } = await supabaseAdmin
        .from('turfs')
        .select('id, name')
        .in('id', turfIds);
      if (!turfErr && turfs) {
        turfNameMap = Object.fromEntries(turfs.map(t => [t.id, t.name]));
      }
    }
    res.json({ bookings: (data || []).map(r => mapBookingRowToApi(r, turfNameMap)) });
  } catch (e) {
    console.error('Error fetching my bookings:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin: list all bookings
app.get('/api/bookings', auth('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ message: error.message });

    const turfIds = Array.from(new Set((data || []).map(b => b.turf_id)));
    let turfNameMap = {};
    if (turfIds.length) {
      const { data: turfs } = await supabaseAdmin
        .from('turfs')
        .select('id, name')
        .in('id', turfIds);
      if (turfs) turfNameMap = Object.fromEntries(turfs.map(t => [t.id, t.name]));
    }
    res.json({ bookings: (data || []).map(r => mapBookingRowToApi(r, turfNameMap)) });
  } catch (e) {
    console.error('Error fetching all bookings:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Payment endpoints
// Test endpoint for debugging
app.get('/api/payments/test', (req, res) => {
  res.json({ message: 'Payment endpoints are working', timestamp: new Date() });
});

// Create booking with payment for online payments (new flow)
app.post('/api/payments/create-booking-with-payment', auth(), async (req, res) => {
  console.log('[create-booking-with-payment] Endpoint called with body:', req.body);
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const {
      turfId,
      date,
      startTime,
      endTime,
      totalAmount,
      userName,
      userEmail,
      userPhone,
    } = req.body || {};

    if (!turfId || !date || !startTime || !endTime || !userName || !userEmail) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Basic sanity: end after start and hourly increments
    const sMin = timeToMinutes(startTime);
    const eMin = timeToMinutes(endTime);
    if (!(eMin > sMin) || ((eMin - sMin) % 60) !== 0) {
      return res.status(400).json({ message: 'Invalid time range' });
    }

    // Ensure turf exists
    const { data: turfRow, error: turfErr } = await supabaseAdmin
      .from('turfs')
      .select('id, name, operating_hours, price_per_hour')
      .eq('id', turfId)
      .single();
    if (turfErr) return res.status(400).json({ message: turfErr.message });
    if (!turfRow) return res.status(404).json({ message: 'Turf not found' });

    // Availability check: no overlapping confirmed bookings for same date
    const { data: existing, error: conflictErr } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time, booking_status, created_at')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
    
    if (conflictErr) return res.status(400).json({ message: conflictErr.message });
    
    const conflict = (existing || []).some(b => {
      const bs = timeToMinutes(b.start_time);
      const be = timeToMinutes(b.end_time);
      return sMin < be && eMin > bs;
    });
    
    if (conflict) return res.status(409).json({ message: 'Selected time overlaps an existing booking' });

    // Default total if not provided
    const durationHours = (eMin - sMin) / 60;
    const computedTotal = Number(totalAmount ?? (Number(turfRow.price_per_hour) * durationHours));

    // Create Razorpay order with booking details in notes
    const timestamp = Date.now().toString();
    const shortReceipt = `new_${timestamp}`.slice(0, 40);
    
    const options = {
      amount: Math.round(computedTotal * 100), // Amount in paise
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        // Store all booking details in notes for later creation
        type: 'new_booking',
        turfId: turfId,
        turfName: turfRow.name,
        userId: req.user.sub,
        userName: userName,
        userEmail: userEmail,
        userPhone: userPhone || '',
        bookingDate: date,
        startTime: startTime,
        endTime: endTime,
        totalAmount: computedTotal.toString(),
        paymentMethod: 'online',
      }
    };

    const order = await razorpay.orders.create(options);

    // Return payment details for frontend
    res.json({
      orderId: order.id,
      amount: computedTotal,
      currency: 'INR',
      key: razorpayKeyId, // Add the Razorpay key for frontend
      name: 'TurfTrack',
      description: `Booking for ${turfRow.name}`,
      prefill: {
        name: userName,
        email: userEmail,
        contact: userPhone || '',
      },
      theme: {
        color: '#3b82f6'
      },
      bookingDetails: {
        turfName: turfRow.name,
        date,
        startTime,
        endTime,
        totalAmount: computedTotal,
      }
    });
  } catch (error) {
    console.error('Error creating payment order:', error);
    res.status(500).json({ message: 'Failed to create payment order' });
  }
});

// Create Razorpay order for payment (existing bookings)
app.post('/api/payments/create-order', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const { bookingId, amount } = req.body;
    
    if (!bookingId || !amount) {
      return res.status(400).json({ message: 'Missing bookingId or amount' });
    }

    // Verify booking exists and belongs to user
    const { data: booking, error: bookingError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('id', bookingId)
      .eq('user_id', req.user.sub)
      .single();

    if (bookingError || !booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.payment_status === 'completed') {
      return res.status(400).json({ message: 'Payment already completed' });
    }

    if (booking.booking_status === 'cancelled') {
      return res.status(400).json({ message: 'Cannot pay for cancelled booking' });
    }

    // Create Razorpay order
    // Generate a short receipt ID (max 40 chars) - use timestamp + short booking ID suffix
    const timestamp = Date.now().toString();
    const bookingIdSuffix = bookingId.slice(-8); // Last 8 characters of booking ID
    const shortReceipt = `bk_${timestamp}_${bookingIdSuffix}`.slice(0, 40); // Ensure max 40 chars
    
    const options = {
      amount: Math.round(amount * 100), // Amount in paise
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        bookingId: bookingId,
        userId: req.user.sub,
        turfName: booking.turf_name,
        bookingDate: booking.booking_date,
        startTime: booking.start_time,
        endTime: booking.end_time,
      }
    };

    const order = await razorpay.orders.create(options);

    // Update booking with Razorpay order ID
    await supabaseAdmin
      .from('bookings')
      .update({ razorpay_order_id: order.id })
      .eq('id', bookingId);

    // Return payment details for frontend
    const paymentDetails = {
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: razorpayKeyId,
      name: 'TurfTrack',
      description: `Turf booking for ${booking.turf_name}`,
      image: '/logo.png', // You can add your logo URL here
      prefill: {
        name: booking.user_name,
        email: booking.user_email,
        contact: booking.user_phone || '',
      },
      theme: {
        color: '#16a34a', // TurfTrack green
      }
    };

    res.json({ paymentDetails });
  } catch (error) {
    console.error('Error creating payment order:', error);
    res.status(500).json({ message: 'Failed to create payment order' });
  }
});

// Verify Razorpay payment
app.post('/api/payments/verify', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const { bookingId, razorpayResponse } = req.body;
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = razorpayResponse;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ message: 'Missing payment verification data' });
    }

    // Verify Razorpay signature
    const isValidSignature = verifyRazorpaySignature(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    );

    if (!isValidSignature) {
      return res.status(400).json({ message: 'Invalid payment signature' });
    }

    // Fetch order details from Razorpay to get notes
    const order = await razorpay.orders.fetch(razorpay_order_id);
    
    // Check if this is a new booking (from create-booking-with-payment) or existing booking
    if (order.notes.type === 'new_booking') {
      // This is a new booking - create the booking record now
      console.log('Creating new booking from payment verification');
      
      // Double-check availability again before creating booking
      const { data: existing, error: conflictErr } = await supabaseAdmin
        .from('bookings')
        .select('start_time, end_time, booking_status')
        .eq('turf_id', order.notes.turfId)
        .eq('booking_date', order.notes.bookingDate)
        .neq('booking_status', 'cancelled');
      
      if (!conflictErr) {
        const sMin = timeToMinutes(order.notes.startTime);
        const eMin = timeToMinutes(order.notes.endTime);
        const conflict = (existing || []).some(b => {
          const bs = timeToMinutes(b.start_time);
          const be = timeToMinutes(b.end_time);
          return sMin < be && eMin > bs;
        });
        
        if (conflict) {
          return res.status(409).json({ message: 'Time slot no longer available' });
        }
      }

      // Create the booking record
      const bookingPayload = {
        turf_id: order.notes.turfId,
        turf_name: order.notes.turfName,
        user_id: order.notes.userId,
        user_name: order.notes.userName,
        user_email: order.notes.userEmail,
        user_phone: order.notes.userPhone || null,
        booking_date: order.notes.bookingDate,
        start_time: order.notes.startTime,
        end_time: order.notes.endTime,
        total_amount: parseFloat(order.notes.totalAmount),
        payment_status: 'completed',
        payment_method: 'online',
        booking_status: 'confirmed',
        razorpay_order_id: razorpay_order_id,
        razorpay_payment_id: razorpay_payment_id,
        // Full amount goes to owner for online payments
        payout_amount: parseFloat(order.notes.totalAmount),
        owner_settlement_status: 'pending',
      };

      const { data: newBooking, error: createError } = await supabaseAdmin
        .from('bookings')
        .insert(bookingPayload)
        .select('*')
        .single();

      if (createError) {
        console.error('Error creating booking after payment:', createError);
        return res.status(500).json({ message: 'Payment successful but booking creation failed' });
      }

      const api = mapBookingRowToApi(newBooking);
      res.json({ booking: api, message: 'Payment successful and booking created' });
      
    } else {
      // This is an existing booking - update it
      console.log('Updating existing booking payment status');
      
      if (!bookingId) {
        return res.status(400).json({ message: 'BookingId required for existing booking payments' });
      }

      // Verify booking exists and belongs to user
      const { data: booking, error: bookingError } = await supabaseAdmin
        .from('bookings')
        .select('*')
        .eq('id', bookingId)
        .eq('user_id', req.user.sub)
        .single();

      if (bookingError || !booking) {
        return res.status(404).json({ message: 'Booking not found' });
      }

      if (booking.razorpay_order_id !== razorpay_order_id) {
        return res.status(400).json({ message: 'Order ID mismatch' });
      }

      // Update booking with payment details and confirm tentative booking
      const { data: updatedBooking, error: updateError } = await supabaseAdmin
        .from('bookings')
        .update({
          payment_status: 'completed',
          booking_status: 'confirmed', // Confirm tentative booking
          razorpay_payment_id: razorpay_payment_id,
          // Full amount goes to owner if not already set
          payout_amount: booking.payout_amount || booking.total_amount,
          owner_settlement_status: 'pending',
        })
        .eq('id', bookingId)
        .select('*')
        .single();

      if (updateError) {
        console.error('Error updating booking payment status:', updateError);
        return res.status(500).json({ message: 'Failed to update payment status' });
      }

      const api = mapBookingRowToApi(updatedBooking);
      res.json({ booking: api, message: 'Payment successful and booking confirmed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

// Pay later endpoint (for cash bookings that want to pay online)
app.post('/api/bookings/:id/pay-later', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const bookingId = req.params.id;

    // Verify booking exists and belongs to user
    const { data: booking, error: bookingError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('id', bookingId)
      .eq('user_id', req.user.sub)
      .single();

    if (bookingError || !booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.payment_status === 'completed') {
      return res.status(400).json({ message: 'Payment already completed' });
    }

    if (booking.booking_status === 'cancelled') {
      return res.status(400).json({ message: 'Cannot pay for cancelled booking' });
    }

    if (booking.payment_method !== 'cash') {
      return res.status(400).json({ message: 'This booking is not eligible for pay later' });
    }

    // Create Razorpay order
    // Generate a short receipt ID (max 40 chars) - use timestamp + short booking ID suffix
    const timestamp = Date.now().toString();
    const bookingIdSuffix = bookingId.slice(-8); // Last 8 characters of booking ID
    const shortReceipt = `pl_${timestamp}_${bookingIdSuffix}`.slice(0, 40); // Ensure max 40 chars
    
    const options = {
      amount: Math.round(booking.total_amount * 100), // Amount in paise
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        bookingId: bookingId,
        userId: req.user.sub,
        turfName: booking.turf_name,
        bookingDate: booking.booking_date,
        startTime: booking.start_time,
        endTime: booking.end_time,
        payLater: true,
      }
    };

    const order = await razorpay.orders.create(options);

    // Update booking with Razorpay order ID and change payment method to online
    await supabaseAdmin
      .from('bookings')
      .update({ 
        razorpay_order_id: order.id,
        payment_method: 'online'
      })
      .eq('id', bookingId);

    // Return payment details for frontend
    const paymentDetails = {
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: razorpayKeyId,
      name: 'TurfTrack',
      description: `Pay later for ${booking.turf_name} booking`,
      image: '/logo.png',
      prefill: {
        name: booking.user_name,
        email: booking.user_email,
        contact: booking.user_phone || '',
      },
      theme: {
        color: '#16a34a',
      }
    };

    res.json({ paymentDetails });
  } catch (error) {
    console.error('Error creating pay later order:', error);
    res.status(500).json({ message: 'Failed to create pay later order' });
  }
});

// Cancel booking endpoint
app.post('/api/bookings/:id/cancel', auth(), async (req, res) => {
  try {
    const bookingId = req.params.id;
    const { reason } = req.body || {};

    // Verify booking exists and belongs to user
    const { data: booking, error: bookingError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('id', bookingId)
      .eq('user_id', req.user.sub)
      .single();

    if (bookingError || !booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.booking_status === 'cancelled') {
      return res.status(400).json({ message: 'Booking is already cancelled' });
    }

    // Check if booking is in the future
    const now = new Date();
    const cleanStartTime = booking.start_time.split(':').slice(0, 2).join(':'); // Handle HH:mm:ss format
    const bookingDateTime = new Date(`${booking.booking_date}T${cleanStartTime}:00`);
    
    const isInFuture = bookingDateTime > now && !isNaN(bookingDateTime.getTime());
    
    if (!isInFuture) {
      return res.status(400).json({ message: 'Cannot cancel past or invalid bookings' });
    }

    // Check if booking can be cancelled (2 hours before start time)
    const timeDiff = bookingDateTime.getTime() - now.getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    const isWithinRefundWindow = hoursDiff >= 2;
    
    // Calculate refund amount - only for completed payments within refund window
    let refundAmount = 0;
    if (booking.payment_status === 'completed' && isWithinRefundWindow) {
      refundAmount = booking.total_amount;
    }

    const updateData = {
      booking_status: 'cancelled',
      cancelled_at: new Date().toISOString(),
      cancellation_reason: reason || null,
      refund_amount: refundAmount,
    };

    // If payment was completed and refund is applicable, mark payment as refunded
    if (booking.payment_status === 'completed' && refundAmount > 0) {
      updateData.payment_status = 'refunded';
    }

    const { data: updatedBooking, error: updateError } = await supabaseAdmin
      .from('bookings')
      .update(updateData)
      .eq('id', bookingId)
      .select('*')
      .single();

    if (updateError) {
      console.error('Error cancelling booking:', updateError);
      return res.status(500).json({ message: 'Failed to cancel booking' });
    }

    // TODO: Implement actual refund processing with Razorpay if payment was made online
    // For now, we just mark it as refunded in the database

    const api = mapBookingRowToApi(updatedBooking);
    res.json({ booking: api });
  } catch (error) {
    console.error('Error cancelling booking:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete turf endpoint
app.delete('/api/turfs/:id', auth('admin'), async (req, res) => {
  try {
    // Check ownership
    const { data: existingTurf, error: fetchError } = await supabaseAdmin
      .from('turfs')
      .select('owner, name')
      .eq('id', req.params.id)
      .single();

    if (fetchError && fetchError.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    if (existingTurf.owner !== req.user.sub) {
      return res.status(403).json({ message: 'Not authorized to delete this turf' });
    }

    // Delete the turf (images are base64 data in DB, so they're deleted automatically)
    const { error } = await supabaseAdmin
      .from('turfs')
      .delete()
      .eq('id', req.params.id)
      .eq('owner', req.user.sub);

    if (error) return res.status(400).json({ message: error.message });
    res.json({ message: 'Turf deleted successfully' });
  } catch (e) {
    console.error('Error deleting turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Cleanup function for expired tentative bookings
async function cleanupExpiredTentativeBookings() {
  try {
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    
    const { error } = await supabaseAdmin
      .from('bookings')
      .update({ booking_status: 'cancelled' })
      .eq('booking_status', 'tentative')
      .lt('created_at', fifteenMinutesAgo);
    
    if (error) {
      console.error('Error cleaning up expired tentative bookings:', error);
    } else {
      console.log('Cleaned up expired tentative bookings');
    }
  } catch (e) {
    console.error('Error in cleanup function:', e);
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredTentativeBookings, 5 * 60 * 1000);

// Super Admin endpoints
// ==================

// Super Admin Dashboard Overview
app.get('/api/superadmin/overview', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Overview requested by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_dashboard_access',
      message: 'Accessed Super Admin dashboard overview',
      details: { timestamp: new Date().toISOString() }
    });

    // Get all stats
    const [bookingsResult, paymentsResult, turfsResult, usersResult] = await Promise.all([
      // Total bookings and today's bookings
      supabaseAdmin.from('bookings').select('id, total_amount, booking_status, created_at'),
      // All payments (completed bookings for now)
      supabaseAdmin.from('bookings').select('id, total_amount, payment_status, payment_method, created_at').eq('payment_status', 'completed'),
      // All turfs
      supabaseAdmin.from('turfs').select('id, name, created_at'),
      // All users
      supabaseAdmin.from('profiles').select('id, role, created_at')
    ]);

    if (bookingsResult.error || paymentsResult.error || turfsResult.error || usersResult.error) {
      console.error('SuperAdmin overview query errors:', {
        bookings: bookingsResult.error,
        payments: paymentsResult.error,
        turfs: turfsResult.error,
        users: usersResult.error
      });
      return res.status(500).json({ message: 'Error fetching dashboard data' });
    }

    const bookings = bookingsResult.data || [];
    const payments = paymentsResult.data || [];
    const turfs = turfsResult.data || [];
    const users = usersResult.data || [];

    // Calculate stats
    const today = new Date().toISOString().split('T')[0];
    const totalBookings = bookings.length;
    const todayBookings = bookings.filter(b => b.created_at?.startsWith(today)).length;
    const totalRevenue = payments.reduce((sum, p) => sum + (Number(p.total_amount) || 0), 0);
    const todayRevenue = payments.filter(p => p.created_at?.startsWith(today)).reduce((sum, p) => sum + (Number(p.total_amount) || 0), 0);
    const activeTurfs = turfs.length;
    const totalUsers = users.filter(u => u.role !== 'superadmin').length;
    const turfOwners = users.filter(u => u.role === 'admin').length;
    const regularUsers = users.filter(u => u.role === 'user').length;

    const overview = {
      stats: {
        totalBookings,
        todayBookings,
        totalRevenue: totalRevenue.toFixed(2),
        todayRevenue: todayRevenue.toFixed(2),
        activeTurfs,
        totalUsers,
        turfOwners,
        regularUsers
      },
      recentActivity: [
        `${todayBookings} bookings created today`,
        `₹${todayRevenue.toFixed(2)} revenue generated today`,
        `${activeTurfs} active turfs on platform`,
        `${totalUsers} total users registered`
      ]
    };

    res.json(overview);
  } catch (e) {
    console.error('SuperAdmin overview error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Super Admin - Get All Bookings
app.get('/api/superadmin/bookings', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All bookings requested by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_bookings',
      message: 'Viewed all platform bookings',
      details: { timestamp: new Date().toISOString() }
    });

    const { page = 1, limit = 50, search = '', status = '', date = '' } = req.query;
    
    let query = supabaseAdmin
      .from('bookings')
      .select('*')
      .order('created_at', { ascending: false });

    // Apply filters
    if (search) {
      query = query.or(`user_name.ilike.%${search}%,user_email.ilike.%${search}%,turf_name.ilike.%${search}%`);
    }
    
    if (status) {
      query = query.eq('booking_status', status);
    }
    
    if (date) {
      query = query.eq('booking_date', date);
    }

    // Apply pagination
    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data, error, count } = await query;
    if (error) return res.status(400).json({ message: error.message });

    // Get turf names for mapping
    const turfIds = Array.from(new Set((data || []).map(b => b.turf_id)));
    let turfNameMap = {};
    if (turfIds.length) {
      const { data: turfs } = await supabaseAdmin
        .from('turfs')
        .select('id, name')
        .in('id', turfIds);
      if (turfs) turfNameMap = Object.fromEntries(turfs.map(t => [t.id, t.name]));
    }

    res.json({ 
      bookings: (data || []).map(r => mapBookingRowToApi(r, turfNameMap)),
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (e) {
    console.error('SuperAdmin bookings error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Super Admin - Get All Payments
app.get('/api/superadmin/payments', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All payments requested by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_payments',
      message: 'Viewed all platform payments',
      details: { timestamp: new Date().toISOString() }
    });

    const { page = 1, limit = 50, search = '', method = '', status = '' } = req.query;
    
    let query = supabaseAdmin
      .from('bookings')
      .select('*')
      .not('payment_status', 'eq', 'pending')
      .order('created_at', { ascending: false });

    // Apply filters
    if (search) {
      query = query.or(`user_name.ilike.%${search}%,user_email.ilike.%${search}%,turf_name.ilike.%${search}%`);
    }
    
    if (method) {
      query = query.eq('payment_method', method);
    }
    
    if (status) {
      query = query.eq('payment_status', status);
    }

    // Apply pagination
    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data, error, count } = await query;
    if (error) return res.status(400).json({ message: error.message });

    const payments = (data || []).map(booking => ({
      id: booking.id,
      bookingId: booking.id,
      userId: booking.user_id,
      userName: booking.user_name,
      userEmail: booking.user_email,
      turfName: booking.turf_name,
      amount: Number(booking.total_amount || 0),
      paymentMethod: booking.payment_method,
      paymentStatus: booking.payment_status,
      razorpayOrderId: booking.razorpay_order_id,
      razorpayPaymentId: booking.razorpay_payment_id,
      bookingDate: booking.booking_date,
      createdAt: booking.created_at,
    }));

    res.json({ 
      payments,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (e) {
    console.error('SuperAdmin payments error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Super Admin - Get All Turfs
app.get('/api/superadmin/turfs', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All turfs requested by user:', req.user.id);

    const { page = 1, limit = 50, search = '' } = req.query;
    
    let query = supabaseAdmin
      .from('turfs')
      .select('*')
      .order('created_at', { ascending: false });

    // Apply search filter
    if (search) {
      query = query.or(`name.ilike.%${search}%,location.ilike.%${search}%`);
    }

    // Apply pagination
    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data, error } = await query;
    if (error) {
      console.error('SuperAdmin turfs query error:', error);
      return res.status(400).json({ message: error.message });
    }

    console.log('[SuperAdmin] Turfs data retrieved:', data?.length || 0);

    // Get owner information for all turfs
    const ownerIds = Array.from(new Set((data || []).map(t => t.owner).filter(Boolean)));
    let ownerMap = {};
    
    if (ownerIds.length > 0) {
      const { data: owners } = await supabaseAdmin
        .from('profiles')
        .select('id, name, email')
        .in('id', ownerIds);
      
      if (owners) {
        ownerMap = Object.fromEntries(owners.map(o => [o.id, { name: o.name, email: o.email }]));
      }
    }

    const turfs = (data || []).map(turf => {
      const ownerInfo = ownerMap[turf.owner] || { name: 'Unknown Owner', email: 'unknown@example.com' };
      return {
        ...mapTurfRowToApi(turf),
        ownerName: ownerInfo.name,
        ownerEmail: ownerInfo.email,
        ownerId: turf.owner || 'unknown',
      };
    });

    console.log('[SuperAdmin] Mapped turfs:', turfs.length);

    res.json({ 
      turfs,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: data?.length || 0,
        totalPages: Math.ceil((data?.length || 0) / Number(limit))
      }
    });
  } catch (e) {
    console.error('SuperAdmin turfs error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Super Admin - Get All Users
app.get('/api/superadmin/users', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All users requested by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_users',
      message: 'Viewed all platform users',
      details: { timestamp: new Date().toISOString() }
    });

    const { page = 1, limit = 50, search = '', role = '' } = req.query;
    
    let query = supabaseAdmin
      .from('profiles')
      .select('*')
      .neq('role', 'superadmin') // Exclude superadmin from the list
      .order('created_at', { ascending: false });

    // Apply filters
    if (search) {
      query = query.or(`name.ilike.%${search}%,phone.ilike.%${search}%`);
    }
    
    if (role && role !== 'all') {
      query = query.eq('role', role);
    }

    // Apply pagination
    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data: profiles, error: profileError, count } = await query;
    if (profileError) return res.status(400).json({ message: profileError.message });

    // Get email addresses from auth.users for each profile
    const userIds = (profiles || []).map(p => p.id);
    const users = [];
    
    for (const profile of profiles || []) {
      try {
        const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(profile.id);
        users.push({
          id: profile.id,
          name: profile.name || '',
          email: authUser?.user?.email || '',
          phone: profile.phone || '',
          role: profile.role,
          location: profile.location || '',
          company: profile.company || '',
          createdAt: formatDate(authUser?.user?.created_at),
          lastSignIn: formatDate(authUser?.user?.last_sign_in_at),
          avatar: profile.profile_pic,
        });
      } catch (e) {
        console.error('Error fetching auth data for user:', profile.id, e);
        // Include profile even if auth data fetch fails
        users.push({
          id: profile.id,
          name: profile.name || '',
          email: 'N/A',
          phone: profile.phone || '',
          role: profile.role,
          location: profile.location || '',
          company: profile.company || '',
          createdAt: formatDate(profile.created_at),
          lastSignIn: 'N/A',
          avatar: profile.profile_pic,
        });
      }
    }

    res.json({ 
      users,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        totalPages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (e) {
    console.error('SuperAdmin users error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Super Admin - Export Data
app.get('/api/superadmin/export/:type', auth('superadmin'), async (req, res) => {
  try {
    const { type } = req.params;
    console.log('[SuperAdmin] Export requested:', type, 'by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_export_data',
      message: `Exported ${type} data`,
      details: { type, timestamp: new Date().toISOString() }
    });

    let data = [];
    let filename = '';

    switch (type) {
      case 'bookings':
        const { data: bookings, error: bookingError } = await supabaseAdmin
          .from('bookings')
          .select('*')
          .order('created_at', { ascending: false });
        
        if (bookingError) throw bookingError;
        
        data = (bookings || []).map(b => ({
          'Booking ID': b.id,
          'Turf Name': b.turf_name,
          'User Name': b.user_name,
          'User Email': b.user_email,
          'User Phone': b.user_phone,
          'Booking Date': b.booking_date,
          'Start Time': b.start_time,
          'End Time': b.end_time,
          'Total Amount': b.total_amount,
          'Payment Status': b.payment_status,
          'Payment Method': b.payment_method,
          'Booking Status': b.booking_status,
          'Created At': b.created_at,
        }));
        filename = `bookings_${new Date().toISOString().split('T')[0]}.csv`;
        break;

      case 'payments':
        const { data: payments, error: paymentError } = await supabaseAdmin
          .from('bookings')
          .select('*')
          .not('payment_status', 'eq', 'pending')
          .order('created_at', { ascending: false });
        
        if (paymentError) throw paymentError;
        
        data = (payments || []).map(p => ({
          'Payment ID': p.id,
          'Booking ID': p.id,
          'User Name': p.user_name,
          'User Email': p.user_email,
          'Turf Name': p.turf_name,
          'Amount': p.total_amount,
          'Payment Method': p.payment_method,
          'Payment Status': p.payment_status,
          'Razorpay Order ID': p.razorpay_order_id || '',
          'Razorpay Payment ID': p.razorpay_payment_id || '',
          'Created At': p.created_at,
        }));
        filename = `payments_${new Date().toISOString().split('T')[0]}.csv`;
        break;

      case 'turfs':
        const { data: turfs, error: turfError } = await supabaseAdmin
          .from('turfs')
          .select(`
            *,
            owner_profile:profiles!turfs_owner_fkey(name, email)
          `)
          .order('created_at', { ascending: false });
        
        if (turfError) throw turfError;
        
        data = (turfs || []).map(t => ({
          'Turf ID': t.id,
          'Turf Name': t.name,
          'Location': typeof t.location === 'string' ? t.location : t.location_coordinates?.address || 'N/A',
          'Price Per Hour': t.price_per_hour,
          'Owner Name': t.owner_profile?.name || 'Unknown',
          'Owner Email': t.owner_profile?.email || 'Unknown',
          'Amenities': Array.isArray(t.amenities) ? t.amenities.join(', ') : '',
          'Created At': t.created_at,
        }));
        filename = `turfs_${new Date().toISOString().split('T')[0]}.csv`;
        break;

      case 'users':
        const { data: userProfiles, error: userError } = await supabaseAdmin
          .from('profiles')
          .select('*')
          .neq('role', 'superadmin')
          .order('created_at', { ascending: false });
        
        if (userError) throw userError;
        
        // Get email from auth for each user
        const userData = [];
        for (const profile of userProfiles || []) {
          try {
            const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(profile.id);
            userData.push({
              'User ID': profile.id,
              'Name': profile.name || '',
              'Email': authUser?.user?.email || 'N/A',
              'Phone': profile.phone || '',
              'Role': profile.role,
              'Location': profile.location || '',
              'Company': profile.company || '',
              'Created At': authUser?.user?.created_at || profile.created_at,
              'Last Sign In': authUser?.user?.last_sign_in_at || 'N/A',
            });
          } catch (e) {
            userData.push({
              'User ID': profile.id,
              'Name': profile.name || '',
              'Email': 'N/A',
              'Phone': profile.phone || '',
              'Role': profile.role,
              'Location': profile.location || '',
              'Company': profile.company || '',
              'Created At': profile.created_at,
              'Last Sign In': 'N/A',
            });
          }
        }
        data = userData;
        filename = `users_${new Date().toISOString().split('T')[0]}.csv`;
        break;

      default:
        return res.status(400).json({ message: 'Invalid export type' });
    }

    // Convert to CSV
    if (data.length === 0) {
      return res.status(404).json({ message: 'No data to export' });
    }

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row => headers.map(header => {
        const value = row[header];
        // Escape commas and quotes in CSV
        if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return value;
      }).join(','))
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  } catch (e) {
    console.error('SuperAdmin export error:', e);
    res.status(500).json({ message: 'Export failed' });
  }
});

// Super Admin - Activity Logs
app.get('/api/superadmin/activity-logs', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Activity logs requested by user:', req.user.id);
    
    // Get super admin activity logs
    const userId = req.user.id;
    const { limit = 100 } = req.query;
    const activities = (userActivities.get(userId) || []).slice(0, Number(limit));
    
    res.json({ activities });
  } catch (e) {
    console.error('SuperAdmin activity logs error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Database migration endpoint - Update booking_status constraint
app.post('/api/migrate/update-booking-status-constraint', auth(), async (req, res) => {
  try {
    console.log('Running database migration: update booking_status constraint');
    
    // First, let's check current constraints
    const { data: constraints, error: constraintError } = await supabaseAdmin
      .from('pg_constraint')
      .select('conname, consrc')
      .eq('conname', 'bookings_booking_status_check');
    
    console.log('Current constraint:', constraints);
    
    // Use raw SQL to update the constraint
    // Note: This requires the SQL execution to be enabled in your Supabase project
    const sqlCommands = [
      'ALTER TABLE bookings DROP CONSTRAINT IF EXISTS bookings_booking_status_check;',
      "ALTER TABLE bookings ADD CONSTRAINT bookings_booking_status_check CHECK (booking_status IN ('confirmed', 'cancelled', 'tentative'));"
    ];
    
    console.log('Migration instructions created. Please run these SQL commands in your Supabase SQL Editor:');
    console.log(sqlCommands.join('\n'));
    
    res.json({ 
      success: true, 
      message: 'Migration instructions generated. Please run the SQL commands in your Supabase dashboard.',
      sqlCommands: sqlCommands,
      instructions: [
        '1. Go to your Supabase Dashboard',
        '2. Navigate to SQL Editor',
        '3. Run the provided SQL commands',
        '4. This will update the constraint to allow tentative bookings'
      ]
    });
    
  } catch (error) {
    console.error('Migration preparation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Migration preparation failed', 
      details: error.message 
    });
  }
});

// Super Admin - Fund Transfer System
// ==================================

// Get fund transfer history
app.get('/api/superadmin/fund-transfers', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Fund transfers requested by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_fund_transfers',
      message: 'Viewed fund transfer history',
      details: { timestamp: new Date().toISOString() }
    });

    // Get all fund transfers from the database
    const { data, error } = await supabaseAdmin
      .from('fund_transfers')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Fund transfers query error:', error);
      return res.status(400).json({ message: error.message });
    }

    res.json({ transfers: data || [] });
  } catch (e) {
    console.error('SuperAdmin fund transfers error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Process weekly fund transfers
app.post('/api/superadmin/process-weekly-transfers', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Processing weekly transfers by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_process_weekly_transfers',
      message: 'Processed weekly fund transfers',
      details: { timestamp: new Date().toISOString() }
    });

    // Allow custom date range or use current week
    let weekStart, weekEnd;
    
    if (req.body.startDate && req.body.endDate) {
      // Use custom date range
      weekStart = new Date(req.body.startDate);
      weekStart.setHours(0, 0, 0, 0);
      weekEnd = new Date(req.body.endDate);
      weekEnd.setHours(23, 59, 59, 999);
      console.log('Using custom date range:', weekStart.toISOString(), 'to', weekEnd.toISOString());
    } else {
      // Calculate the current week (Monday to Sunday)
      const now = new Date();
      const currentDay = now.getDay();
      const daysToMonday = currentDay === 0 ? 6 : currentDay - 1; // Sunday is 0, so 6 days to Monday
      weekStart = new Date(now);
      weekStart.setDate(now.getDate() - daysToMonday);
      weekStart.setHours(0, 0, 0, 0);
      
      weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      weekEnd.setHours(23, 59, 59, 999);
      console.log('Using current week:', weekStart.toISOString(), 'to', weekEnd.toISOString());
    }

    console.log('Processing transfers for week:', weekStart.toISOString(), 'to', weekEnd.toISOString());

    // Get all turf owners (users with role 'admin')
    const { data: turfOwners, error: ownersError } = await supabaseAdmin
      .from('profiles')
      .select('id, name, email')
      .eq('role', 'admin');

    if (ownersError) {
      console.error('Error fetching turf owners:', ownersError);
      return res.status(400).json({ message: ownersError.message });
    }

    if (!turfOwners || turfOwners.length === 0) {
      console.log('No turf owners found');
      return res.json({ 
        transfers: [],
        message: 'No turf owners found. Make sure you have users with role "admin".',
        weekStart: weekStart.toISOString(),
        weekEnd: weekEnd.toISOString()
      });
    }

    console.log(`Found ${turfOwners.length} turf owners`);
    const transfers = [];

    // Process each turf owner
    for (const owner of turfOwners || []) {
      try {
        // Get all completed bookings for this owner's turfs in the current week
        const { data: bookings, error: bookingsError } = await supabaseAdmin
          .from('bookings')
          .select('id, total_amount, turf_id, created_at')
          .eq('payment_status', 'completed')
          .eq('booking_status', 'confirmed')
          .gte('created_at', weekStart.toISOString())
          .lte('created_at', weekEnd.toISOString());

        if (bookingsError) {
          console.error(`Error fetching bookings for owner ${owner.id}:`, bookingsError);
          continue;
        }

        // Get owner's turfs to filter bookings
        const { data: ownerTurfs, error: turfsError } = await supabaseAdmin
          .from('turfs')
          .select('id')
          .eq('owner', owner.id);

        if (turfsError) {
          console.error(`Error fetching turfs for owner ${owner.id}:`, turfsError);
          continue;
        }

        const ownerTurfIds = (ownerTurfs || []).map(t => t.id);
        const ownerBookings = (bookings || []).filter(b => ownerTurfIds.includes(b.turf_id));

        if (ownerBookings.length === 0) {
          console.log(`No bookings found for owner ${owner.name} in this week`);
          continue;
        }

        console.log(`Found ${ownerBookings.length} bookings for owner ${owner.name}`);

        // Calculate earnings
        const totalEarnings = ownerBookings.reduce((sum, booking) => sum + (booking.total_amount || 0), 0);
        const netAmount = totalEarnings; // Full amount goes to owner

        // Create fund transfer record
        const transferData = {
          turf_owner_id: owner.id,
          turf_owner_name: owner.name,
          turf_owner_email: owner.email,
          total_earnings: totalEarnings,
          net_amount: netAmount,
          week_start: weekStart.toISOString(),
          week_end: weekEnd.toISOString(),
          status: 'pending',
          created_at: new Date().toISOString()
        };

        // Insert fund transfer record
        const { data: transfer, error: transferError } = await supabaseAdmin
          .from('fund_transfers')
          .insert(transferData)
          .select()
          .single();

        if (transferError) {
          console.error(`Error creating transfer for owner ${owner.id}:`, transferError);
          continue;
        }

        transfers.push({
          id: transfer.id,
          turfOwnerId: transfer.turf_owner_id,
          turfOwnerName: transfer.turf_owner_name,
          turfOwnerEmail: transfer.turf_owner_email,
          totalEarnings: transfer.total_earnings,
          netAmount: transfer.net_amount,
          weekStart: transfer.week_start,
          weekEnd: transfer.week_end,
          status: transfer.status,
          transferDate: transfer.transfer_date
        });

        console.log(`Created transfer for ${owner.name}: ₹${netAmount} (${ownerBookings.length} bookings)`);

      } catch (ownerError) {
        console.error(`Error processing owner ${owner.id}:`, ownerError);
        continue;
      }
    }

    console.log(`Processed ${transfers.length} fund transfers`);

    res.json({ 
      transfers,
      message: `Successfully processed ${transfers.length} fund transfers for the week`,
      weekStart: weekStart.toISOString(),
      weekEnd: weekEnd.toISOString()
    });

  } catch (e) {
    console.error('SuperAdmin process weekly transfers error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all pending transfers (paid bookings that need to be paid to owners)
app.get('/api/superadmin/pending-transfers', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting pending transfers by user:', req.user.id);
    
    // Step 1: Get all bookings (let's see what we have)
    const { data: allBookings, error: allBookingsError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .order('created_at', { ascending: false });

    if (allBookingsError) {
      console.error('Error fetching all bookings:', allBookingsError);
      return res.status(400).json({ message: allBookingsError.message });
    }

    console.log(`Total bookings found: ${allBookings?.length || 0}`);

    // Step 2: Filter for paid online bookings only (cash payments don't need settlements)
    const paidBookings = (allBookings || []).filter(booking => {
      const isPaid = booking.payment_status === 'completed' || booking.payment_status === 'paid';
      const notCancelled = booking.booking_status !== 'cancelled';
      const isOnlinePayment = booking.payment_method === 'online'; // Only online payments
      const isPendingSettlement = booking.owner_settlement_status === 'pending';
      return isPaid && notCancelled && isOnlinePayment && isPendingSettlement;
    });

    console.log(`Online bookings with pending settlements found: ${paidBookings.length}`);

    if (paidBookings.length === 0) {
      return res.json({ 
        transfers: [],
        message: 'No pending online payment settlements found. Cash payments are handled directly at turfs.',
        debug: {
          totalBookings: allBookings?.length || 0,
          filter: 'online payments with pending settlements only'
        }
      });
    }

    // Step 3: Get all turfs
    const { data: allTurfs, error: turfsError } = await supabaseAdmin
      .from('turfs')
      .select('*');

    if (turfsError) {
      console.error('Error fetching turfs:', turfsError);
      return res.status(400).json({ message: turfsError.message });
    }

    console.log(`Total turfs found: ${allTurfs?.length || 0}`);

    // Step 4: Get all profiles
    const { data: allProfiles, error: profilesError } = await supabaseAdmin
      .from('profiles')
      .select('*');

    if (profilesError) {
      console.error('Error fetching profiles:', profilesError);
      return res.status(400).json({ message: profilesError.message });
    }

    console.log(`Total profiles found: ${allProfiles?.length || 0}`);

    // Step 5: Create lookup maps
    const turfMap = {};
    (allTurfs || []).forEach(turf => {
      turfMap[turf.id] = turf;
    });

    const profileMap = {};
    (allProfiles || []).forEach(profile => {
      profileMap[profile.id] = profile;
    });

    // Step 6: Group bookings by owner
    const ownerTransfers = {};
    
    for (const booking of paidBookings) {
      const turf = turfMap[booking.turf_id];
      if (!turf || !turf.owner) {
        console.log(`No turf or owner found for booking ${booking.id}, turf_id: ${booking.turf_id}`);
        continue;
      }

      const owner = profileMap[turf.owner];
      if (!owner) {
        console.log(`No profile found for owner ${turf.owner}`);
        continue;
      }

      const ownerId = turf.owner;
      
      if (!ownerTransfers[ownerId]) {
        ownerTransfers[ownerId] = {
          turfOwnerId: ownerId,
          turfOwnerName: owner.name || 'Unknown Owner',
          turfOwnerEmail: owner.email || 'unknown@example.com',
          bookings: [],
          totalEarnings: 0,
          netAmount: 0
        };
      }
      
      ownerTransfers[ownerId].bookings.push({
        id: booking.id,
        userName: booking.user_name,
        userEmail: booking.user_email,
        turfName: booking.turf_name,
        amount: booking.total_amount,
        bookingDate: booking.booking_date,
        startTime: booking.start_time,
        endTime: booking.end_time,
        createdAt: booking.created_at
      });
      
      ownerTransfers[ownerId].totalEarnings += booking.total_amount || 0;
    }

    // Step 7: Calculate net amount for each owner (full amount)
    const transfers = Object.values(ownerTransfers).map(transfer => {
      transfer.netAmount = transfer.totalEarnings; // Full amount goes to owner
      return transfer;
    });

    console.log(`Found ${transfers.length} owners with pending payments`);
    res.json({ 
      transfers,
      debug: {
        totalBookings: allBookings?.length || 0,
        paidBookings: paidBookings.length,
        totalTurfs: allTurfs?.length || 0,
        totalProfiles: allProfiles?.length || 0,
        ownersWithTransfers: transfers.length
      }
    });

  } catch (e) {
    console.error('SuperAdmin pending transfers error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Mark owner as paid (update all pending settlements for the owner)
app.post('/api/superadmin/mark-owner-paid', auth('superadmin'), async (req, res) => {
  try {
    const { ownerId, amount } = req.body;
    console.log('[SuperAdmin] Marking owner as paid:', ownerId, 'amount:', amount, 'by user:', req.user.id);
    
    if (!ownerId) {
      return res.status(400).json({ message: 'Owner ID is required' });
    }

    // Get all turfs owned by this owner
    const { data: ownerTurfs, error: turfsError } = await supabaseAdmin
      .from('turfs')
      .select('id')
      .eq('owner', ownerId);

    if (turfsError) {
      console.error('Error fetching owner turfs:', turfsError);
      return res.status(400).json({ message: turfsError.message });
    }

    const turfIds = (ownerTurfs || []).map(t => t.id);

    if (turfIds.length === 0) {
      return res.status(404).json({ message: 'No turfs found for this owner' });
    }

    // Update all pending settlements for this owner to completed (online payments only)
    const { data: updatedBookings, error: updateError } = await supabaseAdmin
      .from('bookings')
      .update({
        owner_settlement_status: 'completed',
        settled_at: new Date().toISOString()
      })
      .in('turf_id', turfIds)
      .eq('owner_settlement_status', 'pending')
      .eq('payment_status', 'completed')
      .eq('booking_status', 'confirmed')
      .eq('payment_method', 'online') // Only mark online payments as settled
      .select('id, total_amount, payout_amount, turf_name, payment_method');

    if (updateError) {
      console.error('Error updating settlement status:', updateError);
      return res.status(400).json({ message: updateError.message });
    }

    const bookingsCount = updatedBookings?.length || 0;
    const actualAmount = (updatedBookings || []).reduce((sum, booking) => 
      sum + (booking.payout_amount || booking.total_amount), 0
    );

    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_mark_owner_paid',
      message: `Marked owner ${ownerId} as paid ₹${actualAmount} for ${bookingsCount} online bookings`,
      details: { 
        ownerId, 
        requestedAmount: amount, 
        actualAmount,
        bookingsCount,
        paymentType: 'online only',
        timestamp: new Date().toISOString() 
      }
    });

    console.log(`Payment recorded: Owner ${ownerId} paid ₹${actualAmount} for ${bookingsCount} online bookings on ${new Date().toISOString()}`);

    res.json({ 
      message: `Owner marked as paid successfully. ${bookingsCount} online payment settlements completed.`,
      ownerId,
      requestedAmount: amount,
      actualAmount,
      bookingsCount,
      paymentType: 'online only',
      paidDate: new Date().toISOString()
    });

  } catch (e) {
    console.error('SuperAdmin mark owner paid error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get pending owner settlements (individual bookings)
app.get('/api/superadmin/pending-settlements', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting pending settlements by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_pending_settlements',
      message: 'Viewed pending owner settlements',
      details: { timestamp: new Date().toISOString() }
    });

    const { ownerId } = req.query;

    let query = supabaseAdmin
      .from('pending_owner_settlements')
      .select('*')
      .order('booking_created_at', { ascending: false });

    // Filter by specific owner if provided
    if (ownerId) {
      query = query.eq('owner_id', ownerId);
    }

    const { data, error } = await query;
    if (error) {
      console.error('Error fetching pending settlements:', error);
      return res.status(400).json({ message: error.message });
    }

    console.log(`Found ${data?.length || 0} pending settlements`);
    res.json({ 
      settlements: data || [],
      total: data?.length || 0
    });

  } catch (e) {
    console.error('SuperAdmin pending settlements error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Get owner settlement summary
app.get('/api/superadmin/settlement-summary', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting settlement summary by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_settlement_summary',
      message: 'Viewed owner settlement summary',
      details: { timestamp: new Date().toISOString() }
    });

    const { data, error } = await supabaseAdmin
      .from('owner_settlement_summary')
      .select('*')
      .order('total_pending_amount', { ascending: false });

    if (error) {
      console.error('Error fetching settlement summary:', error);
      return res.status(400).json({ message: error.message });
    }

    console.log(`Found ${data?.length || 0} owners with pending settlements`);
    res.json({ 
      summary: data || [],
      total: data?.length || 0
    });

  } catch (e) {
    console.error('SuperAdmin settlement summary error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Mark specific bookings as settled
app.post('/api/superadmin/mark-bookings-settled', auth('superadmin'), async (req, res) => {
  try {
    const { bookingIds, settlementReference } = req.body;
    
    if (!bookingIds || !Array.isArray(bookingIds) || bookingIds.length === 0) {
      return res.status(400).json({ message: 'Booking IDs are required' });
    }

    console.log('[SuperAdmin] Marking bookings as settled:', bookingIds, 'by user:', req.user.id);
    
    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_mark_bookings_settled',
      message: `Marked ${bookingIds.length} bookings as settled`,
      details: { bookingIds, settlementReference, timestamp: new Date().toISOString() }
    });

    // Update bookings settlement status
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .update({
        owner_settlement_status: 'completed',
        owner_settlement_date: new Date().toISOString(),
        settlement_reference: settlementReference || `SETTLEMENT_${Date.now()}`
      })
      .in('id', bookingIds)
      .eq('owner_settlement_status', 'pending')
      .select('id, owner_settlement_amount, turf_name, user_name');

    if (error) {
      console.error('Error updating settlement status:', error);
      return res.status(400).json({ message: error.message });
    }

    const totalAmount = (data || []).reduce((sum, booking) => sum + (booking.owner_settlement_amount || 0), 0);

    console.log(`Successfully marked ${data?.length || 0} bookings as settled, total amount: ₹${totalAmount}`);

    res.json({ 
      message: `Successfully marked ${data?.length || 0} bookings as settled`,
      settledBookings: data || [],
      totalAmount,
      settlementReference: settlementReference || `SETTLEMENT_${Date.now()}`
    });

  } catch (e) {
    console.error('SuperAdmin mark bookings settled error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Mark all pending settlements for an owner as settled
app.post('/api/superadmin/mark-owner-settlements-completed', auth('superadmin'), async (req, res) => {
  try {
    const { ownerId, settlementReference } = req.body;
    
    if (!ownerId) {
      return res.status(400).json({ message: 'Owner ID is required' });
    }

    console.log('[SuperAdmin] Marking all settlements for owner as completed:', ownerId, 'by user:', req.user.id);
    
    // Get all pending bookings for this owner
    const { data: ownerTurfs, error: turfsError } = await supabaseAdmin
      .from('turfs')
      .select('id')
      .eq('owner', ownerId);

    if (turfsError) {
      console.error('Error fetching owner turfs:', turfsError);
      return res.status(400).json({ message: turfsError.message });
    }

    const turfIds = (ownerTurfs || []).map(t => t.id);

    if (turfIds.length === 0) {
      return res.status(404).json({ message: 'No turfs found for this owner' });
    }

    // Update all pending settlements for this owner
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .update({
        owner_settlement_status: 'completed',
        owner_settlement_date: new Date().toISOString(),
        settlement_reference: settlementReference || `OWNER_SETTLEMENT_${ownerId}_${Date.now()}`
      })
      .in('turf_id', turfIds)
      .eq('owner_settlement_status', 'pending')
      .eq('payment_status', 'completed')
      .eq('booking_status', 'confirmed')
      .select('id, owner_settlement_amount, turf_name, user_name');

    if (error) {
      console.error('Error updating owner settlements:', error);
      return res.status(400).json({ message: error.message });
    }

    const totalAmount = (data || []).reduce((sum, booking) => sum + (booking.owner_settlement_amount || 0), 0);

    // Log activity
    appendUserActivity(req.user.id, {
      type: 'superadmin_mark_owner_settlements_completed',
      message: `Marked all settlements for owner ${ownerId} as completed (₹${totalAmount})`,
      details: { ownerId, totalAmount, bookingsCount: data?.length || 0, settlementReference, timestamp: new Date().toISOString() }
    });

    console.log(`Successfully marked ${data?.length || 0} settlements as completed for owner ${ownerId}, total amount: ₹${totalAmount}`);

    res.json({ 
      message: `Successfully completed settlements for owner`,
      settledBookings: data || [],
      totalAmount,
      bookingsCount: data?.length || 0,
      settlementReference: settlementReference || `OWNER_SETTLEMENT_${ownerId}_${Date.now()}`
    });

  } catch (e) {
    console.error('SuperAdmin mark owner settlements completed error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});




import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import { createClient } from '@supabase/supabase-js';
import nodemailer from "nodemailer";
import crypto from 'crypto';

// ...existing code...

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
  const role = (user?.user_metadata?.role === 'admin') ? 'admin' : 'user';
  return {
    user: {
      sub: user.id,
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name || '',
      role,
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
    if (requiredRole && req.user.role !== requiredRole) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

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
    const role = (meta.role === 'admin') ? 'admin' : 'user';
    const userResponse = { 
      token: accessToken, 
      user: { 
        id: userData?.user?.id, 
        name: meta.name || '', 
        email: userData?.user?.email, 
        role,
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

  // Case 1: The new coordinate object exists and is valid. Use it.
  if (row.location_coordinates && typeof row.location_coordinates === 'object' && row.location_coordinates.address) {
    finalLocation = {
      address: row.location_coordinates.address,
      latitude: row.location_coordinates.latitude,
      longitude: row.location_coordinates.longitude,
    };
  } 
  // Case 2: Fallback to the old location string if coordinate object is missing.
  else if (typeof row.location === 'string') {
    finalLocation = {
      address: row.location,
      latitude: null, // Mark coordinates as unavailable
      longitude: null,
    };
  } 
  // Case 3: Default to an empty object if no location data is found at all.
  else {
     finalLocation = {
      address: 'Location not available',
      latitude: null,
      longitude: null,
    };
  }

  const result = {
    _id: row.id,
    name: row.name,
    location: finalLocation, // This is now ALWAYS an object
    description: row.description || '',
    images: Array.isArray(row.images) ? row.images : [],
    pricePerHour: row.price_per_hour,
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

// Helper: map DB booking row to FE API shape
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
    bookingStatus: row.booking_status || 'confirmed',
    createdAt: row.created_at,
  };
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
    const { lat, lon, radius } = req.query;
    
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .order('created_at', { ascending: false });
      
    if (error) return res.status(400).json({ message: error.message });

    let turfs = (data || []).map(mapTurfRowToApi);

    // If location filtering is requested, filter by radius
    if (lat && lon && radius) {
      const userLat = parseFloat(lat);
      const userLon = parseFloat(lon);
      const filterRadius = parseFloat(radius);

      turfs = turfs.filter(turf => {
        // Check if turf has coordinate data
        const turfLocation = turf.location;
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

    res.json({ turfs });
  } catch (e) {
    console.error('Error fetching public turfs:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fixed create turf endpoint with better validation
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
      images: Array.isArray(images) ? images.filter(img => img.trim()) : [],
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

// Fixed update turf endpoint
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
      images: Array.isArray(images) ? images.filter(img => img.trim()) : [],
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

    // Availability check: no overlapping non-cancelled bookings for same date
    const { data: existing, error: conflictErr } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
    if (conflictErr) return res.status(400).json({ message: conflictErr.message });
    const conflict = (existing || []).some(b => {
      const bs = timeToMinutes(b.start_time);
      const be = timeToMinutes(b.end_time);
      // Overlap if start < be and end > bs
      return sMin < be && eMin > bs;
    });
    if (conflict) return res.status(409).json({ message: 'Selected time overlaps an existing booking' });

    // Default total if not provided
    const durationHours = (eMin - sMin) / 60;
    const computedTotal = Number(totalAmount ?? (Number(turfRow.price_per_hour) * durationHours));

    const payload = {
      turf_id: turfId,
      turf_name: turfRow.name, // Fix: include turf_name
      user_id: req.user.sub,
      user_name: userName,
      user_email: userEmail,
      user_phone: userPhone || null,
      booking_date: date,
      start_time: startTime,
      end_time: endTime,
      total_amount: computedTotal,
      payment_status: 'completed',
      booking_status: 'confirmed',
    };

    const { data: created, error: createErr } = await supabaseAdmin
      .from('bookings')
      .insert(payload)
      .select('*')
      .single();
    if (createErr) return res.status(400).json({ message: createErr.message });

    const api = mapBookingRowToApi(created, { [turfId]: turfRow.name });
    res.status(201).json({ booking: api });
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

// Delete turf endpoint (unchanged, working correctly)
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

    // Delete the turf
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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});



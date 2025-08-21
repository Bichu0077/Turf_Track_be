import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import { createClient } from '@supabase/supabase-js';
import nodemailer from "nodemailer";
import crypto from 'crypto';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
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

function mapTurfRowToApi(row) {
  if (!row) return null;
  return {
    _id: row.id,
    id: row.id,
    name: row.name,
    location: row.location,
    description: row.description || '',
    images: Array.isArray(row.images) ? row.images : [],
    pricePerHour: Number(row.price_per_hour || 0),
    operatingHours: row.operating_hours || { open: '06:00', close: '22:00' },
    amenities: Array.isArray(row.amenities) ? row.amenities : [],
    owner: row.owner || null,
  };
}

async function getUserFromAuthHeader(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return { error: 'Missing token' };
  const { data, error } = await supabaseAnon.auth.getUser(token);
  if (error) return { error: 'Invalid token' };
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

// Start registration: create pending registration and send OTP
app.post('/api/auth/register/start', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const finalRole = role === 'admin' ? 'admin' : 'user';

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
    res.json({ token: accessToken, user: { id: newUser.id, name: entry.name, email: entry.email, role: entry.role } });
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
    res.json({ token: accessToken, user: { id: userData?.user?.id, name: meta.name || '', email: userData?.user?.email, role } });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/me', auth(), async (req, res) => {
  res.json({ user: { id: req.user.sub, name: req.user.name, email: req.user.email, role: req.user.role } });
});

// Example protected routes
app.get('/api/admin/overview', auth('admin'), (req, res) => {
  res.json({ message: 'admin data' });
});

app.get('/api/user/overview', auth('user'), (req, res) => {
  res.json({ message: 'user data' });
});

// Turf routes (admin-owned)
app.post('/api/turfs', auth('admin'), async (req, res) => {
  try {
    const { name, location, description, images, pricePerHour, operatingHours, amenities } = req.body;
    if (!name || !location || !pricePerHour || !operatingHours?.open || !operatingHours?.close) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const payload = {
      name,
      location,
      description: description || '',
      images: Array.isArray(images) ? images : [],
      price_per_hour: Number(pricePerHour),
      operating_hours: operatingHours,
      amenities: Array.isArray(amenities) ? amenities : [],
      owner: req.user.sub,
    };
    const { data, error } = await supabaseAdmin.from('turfs').insert(payload).select().single();
    if (error) return res.status(400).json({ message: error.message });
    res.status(201).json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/turfs/mine', auth('admin'), async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('turfs')
    .select('*')
    .eq('owner', req.user.sub)
    .order('created_at', { ascending: false });
  if (error) return res.status(400).json({ message: error.message });
  res.json({ turfs: (data || []).map(mapTurfRowToApi) });
});

app.get('/api/turfs/public', async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('turfs')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(400).json({ message: error.message });
  res.json({ turfs: (data || []).map(mapTurfRowToApi) });
});

app.get('/api/turfs/:id', async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('turfs')
    .select('*')
    .eq('id', req.params.id)
    .single();
  if (error && error.code === 'PGRST116') return res.status(404).json({ message: 'Not found' });
  if (error) return res.status(400).json({ message: error.message });
  res.json({ turf: mapTurfRowToApi(data) });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});



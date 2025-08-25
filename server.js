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
  try {
    // Get user data from auth (for email)
    const { data: userData, error: authError } = await supabaseAdmin.auth.admin.getUserById(req.user.sub);
    if (authError) return res.status(400).json({ message: authError.message });

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
      avatar: profileData?.profile_pic
    };
    console.log("[GET /api/auth/me] user response:", userObj);
    res.json({ user: userObj });
  } catch (e) {
    console.error('Server error:', e);
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

    // Update profile fields in profiles table
    const profileUpdateFields = { name, phone, location, company };
    if (avatar) profileUpdateFields.profile_pic = avatar;

    const { error: profileError } = await supabaseAdmin
      .from('profiles')
      .update(profileUpdateFields)
      .eq('id', userId);

    if (profileError) return res.status(400).json({ message: profileError.message });

    // Update email in auth.users table if provided and different
    if (email && email !== req.user.email) {
      const { error: emailError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
        email: email
      });
      if (emailError) return res.status(400).json({ message: emailError.message });
    }

    res.json({ message: 'Profile updated successfully' });
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
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

    res.json({ 
      user: {
        id: profileData.id,
        name: profileData.name,
        email: userData.user.email, // Get email from auth system
        phone: profileData.phone,
        company: profileData.company,
        location: profileData.location,
        profile_pic: profileData.profile_pic,
        avatar: profileData.profile_pic, // Include both for compatibility
        role: profileData.role
      }
    });
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

  return {
    _id: row.id,
    name: row.name,
    location: finalLocation, // This is now ALWAYS an object
    description: row.description || '',
    images: Array.isArray(row.images) ? row.images : [],
    pricePerHour: row.price_per_hour,
    operatingHours: row.operating_hours || { open: '06:00', close: '22:00' },
    amenities: Array.isArray(row.amenities) ? row.amenities : [],
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
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



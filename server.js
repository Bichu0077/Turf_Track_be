import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import { createClient } from '@supabase/supabase-js';

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

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const finalRole = role === 'admin' ? 'admin' : 'user';

    // Create the user (confirmed) via Admin API
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { name, phone, role: finalRole },
    });
    if (createError) return res.status(400).json({ message: createError.message });

    const newUser = created.user;

    // Ensure a profile row exists
    await supabaseAdmin.from('profiles').upsert({ id: newUser.id, name, phone, role: finalRole });

    // Sign in to mint an access token for the client
    const { data: signInData, error: signInError } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (signInError || !signInData.session) return res.status(500).json({ message: signInError?.message || 'Failed to create session' });

    const accessToken = signInData.session.access_token;
    res.status(201).json({ token: accessToken, user: { id: newUser.id, name, email, role: finalRole } });
  } catch (e) {
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



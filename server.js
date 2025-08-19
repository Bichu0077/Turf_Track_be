import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// MongoDB connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/turf';
await mongoose.connect(mongoUri);

// Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const turfSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: { type: String, required: true },
  description: { type: String },
  images: { type: [String], default: [] },
  pricePerHour: { type: Number, required: true },
  operatingHours: {
    open: { type: String, required: true },
    close: { type: String, required: true }
  },
  amenities: { type: [String], default: [] },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

const Turf = mongoose.model('Turf', turfSchema);

// Helpers
const jwtSecret = process.env.JWT_SECRET || 'dev_secret_change_me';
const jwtExpiresIn = '7d';

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role, email: user.email, name: user.name }, jwtSecret, { expiresIn: jwtExpiresIn });
}

function auth(requiredRole) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Missing token' });
    try {
      const payload = jwt.verify(token, jwtSecret);
      req.user = payload;
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      next();
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
}

// Routes
app.get('/', (req, res) => res.json({ ok: true }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Email already registered' });
    const passwordHash = await bcrypt.hash(password, 10);
    const finalRole = role === 'admin' ? 'admin' : 'user';
    const user = await User.create({ name, email, phone, passwordHash, role: finalRole });
    const token = signToken(user);
    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
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
    const turf = await Turf.create({
      name,
      location,
      description,
      images: Array.isArray(images) ? images : [],
      pricePerHour,
      operatingHours,
      amenities: Array.isArray(amenities) ? amenities : [],
      owner: req.user.sub
    });
    res.status(201).json({ turf });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/turfs/mine', auth('admin'), async (req, res) => {
  const turfs = await Turf.find({ owner: req.user.sub }).sort({ createdAt: -1 });
  res.json({ turfs });
});

app.get('/api/turfs/public', async (req, res) => {
  const turfs = await Turf.find().sort({ createdAt: -1 });
  res.json({ turfs });
});

app.get('/api/turfs/:id', async (req, res) => {
  try {
    const turf = await Turf.findById(req.params.id);
    if (!turf) return res.status(404).json({ message: 'Not found' });
    res.json({ turf });
  } catch (e) {
    res.status(400).json({ message: 'Invalid id' });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});



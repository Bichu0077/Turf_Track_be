import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { supabaseAdmin } from './src/config/database.js';
import { PORT } from './src/config/constants.js';

// Import routes
import authRoutes from './src/routes/authRoutes.js';
import turfRoutes from './src/routes/turfRoutes.js';
import bookingRoutes from './src/routes/bookingRoutes.js';
import paymentRoutes from './src/routes/paymentRoutes.js';
import superadminRoutes from './src/routes/superadminRoutes.js';
import exportRoutes from './src/routes/exportRoutes.js';
import settlementRoutes from './src/routes/settlementRoutes.js';

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Health check
app.get('/', (req, res) => res.json({ ok: true, message: 'TurfTrack API Server' }));

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/turfs', turfRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/superadmin', superadminRoutes);
app.use('/api/superadmin/export', exportRoutes);
app.use('/api/superadmin', settlementRoutes);

// Legacy routes for backward compatibility
app.get('/api/admin/overview', (req, res) => {
  res.json({ message: 'admin data' });
});

app.get('/api/user/overview', (req, res) => {
  res.json({ message: 'user data' });
});

// Database migration endpoint
app.post('/api/migrate/update-booking-status-constraint', async (req, res) => {
  try {
    console.log('Running database migration: update booking_status constraint');
    
    const sqlCommands = [
      'ALTER TABLE bookings DROP CONSTRAINT IF EXISTS bookings_booking_status_check;',
      "ALTER TABLE bookings ADD CONSTRAINT bookings_booking_status_check CHECK (booking_status IN ('confirmed', 'cancelled', 'tentative'));"
    ];
    
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    message: 'Internal server error', 
    error: process.env.NODE_ENV === 'production' ? undefined : err.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ TurfTrack API Server listening on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔧 Morgan logging: enabled`);
  console.log(`🚀 Server started at: ${new Date().toISOString()}`);
});

export default app;

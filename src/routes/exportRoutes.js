import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { formatDate } from '../utils/dateFormatter.js';
import { appendUserActivity } from '../utils/activityLogger.js';

const router = express.Router();

// Export Data
router.get('/:type', auth('superadmin'), async (req, res) => {
  try {
    const { type } = req.params;
    console.log('[SuperAdmin] Export requested:', type, 'by user:', req.user.id);
    
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

export default router;

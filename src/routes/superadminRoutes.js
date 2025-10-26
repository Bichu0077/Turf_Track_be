import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { mapBookingRowToApi } from '../mappers/bookingMapper.js';
import { mapTurfRowToApi } from '../mappers/turfMapper.js';
import { formatDate } from '../utils/dateFormatter.js';
import { appendUserActivity } from '../utils/activityLogger.js';
import { userActivities } from '../config/constants.js';

const router = express.Router();

// Dashboard Overview
router.get('/overview', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Overview requested by user:', req.user.id);
    
    appendUserActivity(req.user.id, {
      type: 'superadmin_dashboard_access',
      message: 'Accessed Super Admin dashboard overview',
      details: { timestamp: new Date().toISOString() }
    });

    const [bookingsResult, paymentsResult, turfsResult, usersResult] = await Promise.all([
      supabaseAdmin.from('bookings').select('id, total_amount, booking_status, created_at'),
      supabaseAdmin.from('bookings').select('id, total_amount, payment_status, payment_method, created_at').eq('payment_status', 'completed'),
      supabaseAdmin.from('turfs').select('id, name, created_at'),
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

// Get All Bookings
router.get('/bookings', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All bookings requested by user:', req.user.id);
    
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

    if (search) {
      query = query.or(`user_name.ilike.%${search}%,user_email.ilike.%${search}%,turf_name.ilike.%${search}%`);
    }
    
    if (status) {
      query = query.eq('booking_status', status);
    }
    
    if (date) {
      query = query.eq('booking_date', date);
    }

    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data, error, count } = await query;
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

// Get All Payments
router.get('/payments', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All payments requested by user:', req.user.id);
    
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

    if (search) {
      query = query.or(`user_name.ilike.%${search}%,user_email.ilike.%${search}%,turf_name.ilike.%${search}%`);
    }
    
    if (method) {
      query = query.eq('payment_method', method);
    }
    
    if (status) {
      query = query.eq('payment_status', status);
    }

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

// Get All Turfs
router.get('/turfs', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All turfs requested by user:', req.user.id);

    const { page = 1, limit = 50, search = '' } = req.query;
    
    let query = supabaseAdmin
      .from('turfs')
      .select('*')
      .order('created_at', { ascending: false });

    if (search) {
      query = query.or(`name.ilike.%${search}%,location.ilike.%${search}%`);
    }

    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data, error } = await query;
    if (error) {
      console.error('SuperAdmin turfs query error:', error);
      return res.status(400).json({ message: error.message });
    }

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

// Get All Users
router.get('/users', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] All users requested by user:', req.user.id);
    
    appendUserActivity(req.user.id, {
      type: 'superadmin_view_users',
      message: 'Viewed all platform users',
      details: { timestamp: new Date().toISOString() }
    });

    const { page = 1, limit = 50, search = '', role = '' } = req.query;
    
    let query = supabaseAdmin
      .from('profiles')
      .select('*')
      .neq('role', 'superadmin')
      .order('created_at', { ascending: false });

    if (search) {
      query = query.or(`name.ilike.%${search}%,phone.ilike.%${search}%`);
    }
    
    if (role && role !== 'all') {
      query = query.eq('role', role);
    }

    const offset = (Number(page) - 1) * Number(limit);
    query = query.range(offset, offset + Number(limit) - 1);

    const { data: profiles, error: profileError, count } = await query;
    if (profileError) return res.status(400).json({ message: profileError.message });

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

// Activity Logs
router.get('/activity-logs', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Activity logs requested by user:', req.user.id);
    
    const userId = req.user.id;
    const { limit = 100 } = req.query;
    const activities = (userActivities.get(userId) || []).slice(0, Number(limit));
    
    res.json({ activities });
  } catch (e) {
    console.error('SuperAdmin activity logs error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;

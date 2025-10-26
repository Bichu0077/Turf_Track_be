import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { appendUserActivity } from '../utils/activityLogger.js';

const router = express.Router();

// Get pending transfers (paid bookings that need to be paid to owners)
router.get('/pending-transfers', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting pending transfers by user:', req.user.id);
    
    const { data: allBookings, error: allBookingsError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .order('created_at', { ascending: false });

    if (allBookingsError) {
      console.error('Error fetching all bookings:', allBookingsError);
      return res.status(400).json({ message: allBookingsError.message });
    }

    const paidBookings = (allBookings || []).filter(booking => {
      const isPaid = booking.payment_status === 'completed' || booking.payment_status === 'paid';
      const notCancelled = booking.booking_status !== 'cancelled';
      const isOnlinePayment = booking.payment_method === 'online';
      const isPendingSettlement = booking.owner_settlement_status === 'pending';
      return isPaid && notCancelled && isOnlinePayment && isPendingSettlement;
    });

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

    const { data: allTurfs, error: turfsError } = await supabaseAdmin
      .from('turfs')
      .select('*');

    if (turfsError) {
      console.error('Error fetching turfs:', turfsError);
      return res.status(400).json({ message: turfsError.message });
    }

    const { data: allProfiles, error: profilesError } = await supabaseAdmin
      .from('profiles')
      .select('*');

    if (profilesError) {
      console.error('Error fetching profiles:', profilesError);
      return res.status(400).json({ message: profilesError.message });
    }

    const turfMap = {};
    (allTurfs || []).forEach(turf => {
      turfMap[turf.id] = turf;
    });

    const profileMap = {};
    (allProfiles || []).forEach(profile => {
      profileMap[profile.id] = profile;
    });

    const ownerTransfers = {};
    
    for (const booking of paidBookings) {
      const turf = turfMap[booking.turf_id];
      if (!turf || !turf.owner) {
        continue;
      }

      const owner = profileMap[turf.owner];
      if (!owner) {
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

    const transfers = Object.values(ownerTransfers).map(transfer => {
      transfer.netAmount = transfer.totalEarnings;
      return transfer;
    });

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

// Mark owner as paid
router.post('/mark-owner-paid', auth('superadmin'), async (req, res) => {
  try {
    const { ownerId, amount } = req.body;
    console.log('[SuperAdmin] Marking owner as paid:', ownerId, 'amount:', amount, 'by user:', req.user.id);
    
    if (!ownerId) {
      return res.status(400).json({ message: 'Owner ID is required' });
    }

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
      .eq('payment_method', 'online')
      .select('id, total_amount, payout_amount, turf_name, payment_method');

    if (updateError) {
      console.error('Error updating settlement status:', updateError);
      return res.status(400).json({ message: updateError.message });
    }

    const bookingsCount = updatedBookings?.length || 0;
    const actualAmount = (updatedBookings || []).reduce((sum, booking) => 
      sum + (booking.payout_amount || booking.total_amount), 0
    );

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

// Get pending settlements view
router.get('/pending-settlements', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting pending settlements by user:', req.user.id);
    
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

    if (ownerId) {
      query = query.eq('owner_id', ownerId);
    }

    const { data, error } = await query;
    if (error) {
      console.error('Error fetching pending settlements:', error);
      return res.status(400).json({ message: error.message });
    }

    res.json({ 
      settlements: data || [],
      total: data?.length || 0
    });

  } catch (e) {
    console.error('SuperAdmin pending settlements error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Get settlement summary
router.get('/settlement-summary', auth('superadmin'), async (req, res) => {
  try {
    console.log('[SuperAdmin] Getting settlement summary by user:', req.user.id);
    
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

    res.json({ 
      summary: data || [],
      total: data?.length || 0
    });

  } catch (e) {
    console.error('SuperAdmin settlement summary error:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

export default router;

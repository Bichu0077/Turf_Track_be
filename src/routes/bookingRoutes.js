import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { mapBookingRowToApi } from '../mappers/bookingMapper.js';
import { timeToMinutes } from '../utils/timeUtils.js';

const router = express.Router();

// Get current user's bookings
router.get('/mine', auth(), async (req, res) => {
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
router.get('/', auth('admin'), async (req, res) => {
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

// Create a booking
router.post('/', auth(), async (req, res) => {
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

    // Availability check
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
      return sMin < be && eMin > bs;
    });
    
    if (conflict) return res.status(409).json({ message: 'Selected time overlaps an existing booking' });

    const durationHours = (eMin - sMin) / 60;
    const computedTotal = Number(totalAmount ?? (Number(turfRow.price_per_hour) * durationHours));

    let paymentStatus, bookingStatus;
    
    if (paymentMethod === 'cash') {
      paymentStatus = 'pending';
      bookingStatus = 'confirmed';
      
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
        payout_amount: null,
        owner_settlement_status: 'completed',
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

// Cancel booking
router.post('/:id/cancel', auth(), async (req, res) => {
  try {
    const bookingId = req.params.id;
    const { reason } = req.body || {};

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
    const cleanStartTime = booking.start_time.split(':').slice(0, 2).join(':');
    const bookingDateTime = new Date(`${booking.booking_date}T${cleanStartTime}:00`);
    
    const isInFuture = bookingDateTime > now && !isNaN(bookingDateTime.getTime());
    
    if (!isInFuture) {
      return res.status(400).json({ message: 'Cannot cancel past or invalid bookings' });
    }

    // Check if booking can be cancelled (2 hours before)
    const timeDiff = bookingDateTime.getTime() - now.getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    const isWithinRefundWindow = hoursDiff >= 2;
    
    // Calculate refund amount
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

    const api = mapBookingRowToApi(updatedBooking);
    res.json({ booking: api });
  } catch (error) {
    console.error('Error cancelling booking:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;

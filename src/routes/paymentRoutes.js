import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { razorpay, razorpayKeyId } from '../config/razorpay.js';
import { auth } from '../middleware/auth.js';
import { mapBookingRowToApi } from '../mappers/bookingMapper.js';
import { verifyRazorpaySignature } from '../utils/paymentUtils.js';
import { timeToMinutes } from '../utils/timeUtils.js';

const router = express.Router();

// Test endpoint
router.get('/test', (req, res) => {
  res.json({ message: 'Payment endpoints are working', timestamp: new Date() });
});

// Create booking with payment for online payments
router.post('/create-booking-with-payment', auth(), async (req, res) => {
  console.log('[create-booking-with-payment] Endpoint called with body:', req.body);
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

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

    const sMin = timeToMinutes(startTime);
    const eMin = timeToMinutes(endTime);
    if (!(eMin > sMin) || ((eMin - sMin) % 60) !== 0) {
      return res.status(400).json({ message: 'Invalid time range' });
    }

    const { data: turfRow, error: turfErr } = await supabaseAdmin
      .from('turfs')
      .select('id, name, operating_hours, price_per_hour')
      .eq('id', turfId)
      .single();
    if (turfErr) return res.status(400).json({ message: turfErr.message });
    if (!turfRow) return res.status(404).json({ message: 'Turf not found' });

    const { data: existing, error: conflictErr } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time, booking_status, created_at')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
    
    if (conflictErr) return res.status(400).json({ message: conflictErr.message });
    
    const conflict = (existing || []).some(b => {
      const bs = timeToMinutes(b.start_time);
      const be = timeToMinutes(b.end_time);
      return sMin < be && eMin > bs;
    });
    
    if (conflict) return res.status(409).json({ message: 'Selected time overlaps an existing booking' });

    const durationHours = (eMin - sMin) / 60;
    const computedTotal = Number(totalAmount ?? (Number(turfRow.price_per_hour) * durationHours));

    const timestamp = Date.now().toString();
    const shortReceipt = `new_${timestamp}`.slice(0, 40);
    
    const options = {
      amount: Math.round(computedTotal * 100),
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        type: 'new_booking',
        turfId: turfId,
        turfName: turfRow.name,
        userId: req.user.sub,
        userName: userName,
        userEmail: userEmail,
        userPhone: userPhone || '',
        bookingDate: date,
        startTime: startTime,
        endTime: endTime,
        totalAmount: computedTotal.toString(),
        paymentMethod: 'online',
      }
    };

    const order = await razorpay.orders.create(options);

    res.json({
      orderId: order.id,
      amount: computedTotal,
      currency: 'INR',
      key: razorpayKeyId,
      name: 'TurfTrack',
      description: `Booking for ${turfRow.name}`,
      prefill: {
        name: userName,
        email: userEmail,
        contact: userPhone || '',
      },
      theme: {
        color: '#3b82f6'
      },
      bookingDetails: {
        turfName: turfRow.name,
        date,
        startTime,
        endTime,
        totalAmount: computedTotal,
      }
    });
  } catch (error) {
    console.error('Error creating payment order:', error);
    res.status(500).json({ message: 'Failed to create payment order' });
  }
});

// Create Razorpay order for existing bookings
router.post('/create-order', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const { bookingId, amount } = req.body;
    
    if (!bookingId || !amount) {
      return res.status(400).json({ message: 'Missing bookingId or amount' });
    }

    const { data: booking, error: bookingError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('id', bookingId)
      .eq('user_id', req.user.sub)
      .single();

    if (bookingError || !booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.payment_status === 'completed') {
      return res.status(400).json({ message: 'Payment already completed' });
    }

    if (booking.booking_status === 'cancelled') {
      return res.status(400).json({ message: 'Cannot pay for cancelled booking' });
    }

    const timestamp = Date.now().toString();
    const bookingIdSuffix = bookingId.slice(-8);
    const shortReceipt = `bk_${timestamp}_${bookingIdSuffix}`.slice(0, 40);
    
    const options = {
      amount: Math.round(amount * 100),
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        bookingId: bookingId,
        userId: req.user.sub,
        turfName: booking.turf_name,
        bookingDate: booking.booking_date,
        startTime: booking.start_time,
        endTime: booking.end_time,
      }
    };

    const order = await razorpay.orders.create(options);

    await supabaseAdmin
      .from('bookings')
      .update({ razorpay_order_id: order.id })
      .eq('id', bookingId);

    const paymentDetails = {
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: razorpayKeyId,
      name: 'TurfTrack',
      description: `Turf booking for ${booking.turf_name}`,
      image: '/logo.png',
      prefill: {
        name: booking.user_name,
        email: booking.user_email,
        contact: booking.user_phone || '',
      },
      theme: {
        color: '#16a34a',
      }
    };

    res.json({ paymentDetails });
  } catch (error) {
    console.error('Error creating payment order:', error);
    res.status(500).json({ message: 'Failed to create payment order' });
  }
});

// Verify Razorpay payment
router.post('/verify', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const { bookingId, razorpayResponse } = req.body;
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = razorpayResponse;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ message: 'Missing payment verification data' });
    }

    const isValidSignature = verifyRazorpaySignature(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    );

    if (!isValidSignature) {
      return res.status(400).json({ message: 'Invalid payment signature' });
    }

    const order = await razorpay.orders.fetch(razorpay_order_id);
    
    if (order.notes.type === 'new_booking') {
      console.log('Creating new booking from payment verification');
      
      const { data: existing, error: conflictErr } = await supabaseAdmin
        .from('bookings')
        .select('start_time, end_time, booking_status')
        .eq('turf_id', order.notes.turfId)
        .eq('booking_date', order.notes.bookingDate)
        .neq('booking_status', 'cancelled');
      
      if (!conflictErr) {
        const sMin = timeToMinutes(order.notes.startTime);
        const eMin = timeToMinutes(order.notes.endTime);
        const conflict = (existing || []).some(b => {
          const bs = timeToMinutes(b.start_time);
          const be = timeToMinutes(b.end_time);
          return sMin < be && eMin > bs;
        });
        
        if (conflict) {
          return res.status(409).json({ message: 'Time slot no longer available' });
        }
      }

      const bookingPayload = {
        turf_id: order.notes.turfId,
        turf_name: order.notes.turfName,
        user_id: order.notes.userId,
        user_name: order.notes.userName,
        user_email: order.notes.userEmail,
        user_phone: order.notes.userPhone || null,
        booking_date: order.notes.bookingDate,
        start_time: order.notes.startTime,
        end_time: order.notes.endTime,
        total_amount: parseFloat(order.notes.totalAmount),
        payment_status: 'completed',
        payment_method: 'online',
        booking_status: 'confirmed',
        razorpay_order_id: razorpay_order_id,
        razorpay_payment_id: razorpay_payment_id,
        payout_amount: parseFloat(order.notes.totalAmount),
        owner_settlement_status: 'pending',
      };

      const { data: newBooking, error: createError } = await supabaseAdmin
        .from('bookings')
        .insert(bookingPayload)
        .select('*')
        .single();

      if (createError) {
        console.error('Error creating booking after payment:', createError);
        return res.status(500).json({ message: 'Payment successful but booking creation failed' });
      }

      const api = mapBookingRowToApi(newBooking);
      res.json({ booking: api, message: 'Payment successful and booking created' });
      
    } else {
      console.log('Updating existing booking payment status');
      
      if (!bookingId) {
        return res.status(400).json({ message: 'BookingId required for existing booking payments' });
      }

      const { data: booking, error: bookingError } = await supabaseAdmin
        .from('bookings')
        .select('*')
        .eq('id', bookingId)
        .eq('user_id', req.user.sub)
        .single();

      if (bookingError || !booking) {
        return res.status(404).json({ message: 'Booking not found' });
      }

      if (booking.razorpay_order_id !== razorpay_order_id) {
        return res.status(400).json({ message: 'Order ID mismatch' });
      }

      const { data: updatedBooking, error: updateError } = await supabaseAdmin
        .from('bookings')
        .update({
          payment_status: 'completed',
          booking_status: 'confirmed',
          razorpay_payment_id: razorpay_payment_id,
          payout_amount: booking.payout_amount || booking.total_amount,
          owner_settlement_status: 'pending',
        })
        .eq('id', bookingId)
        .select('*')
        .single();

      if (updateError) {
        console.error('Error updating booking payment status:', updateError);
        return res.status(500).json({ message: 'Failed to update payment status' });
      }

      const api = mapBookingRowToApi(updatedBooking);
      res.json({ booking: api, message: 'Payment successful and booking confirmed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

// Pay later endpoint
router.post('/:id/pay-later', auth(), async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const bookingId = req.params.id;

    const { data: booking, error: bookingError } = await supabaseAdmin
      .from('bookings')
      .select('*')
      .eq('id', bookingId)
      .eq('user_id', req.user.sub)
      .single();

    if (bookingError || !booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.payment_status === 'completed') {
      return res.status(400).json({ message: 'Payment already completed' });
    }

    if (booking.booking_status === 'cancelled') {
      return res.status(400).json({ message: 'Cannot pay for cancelled booking' });
    }

    if (booking.payment_method !== 'cash') {
      return res.status(400).json({ message: 'This booking is not eligible for pay later' });
    }

    const timestamp = Date.now().toString();
    const bookingIdSuffix = bookingId.slice(-8);
    const shortReceipt = `pl_${timestamp}_${bookingIdSuffix}`.slice(0, 40);
    
    const options = {
      amount: Math.round(booking.total_amount * 100),
      currency: 'INR',
      receipt: shortReceipt,
      notes: {
        bookingId: bookingId,
        userId: req.user.sub,
        turfName: booking.turf_name,
        bookingDate: booking.booking_date,
        startTime: booking.start_time,
        endTime: booking.end_time,
        payLater: true,
      }
    };

    const order = await razorpay.orders.create(options);

    await supabaseAdmin
      .from('bookings')
      .update({ 
        razorpay_order_id: order.id,
        payment_method: 'online'
      })
      .eq('id', bookingId);

    const paymentDetails = {
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: razorpayKeyId,
      name: 'TurfTrack',
      description: `Pay later for ${booking.turf_name} booking`,
      image: '/logo.png',
      prefill: {
        name: booking.user_name,
        email: booking.user_email,
        contact: booking.user_phone || '',
      },
      theme: {
        color: '#16a34a',
      }
    };

    res.json({ paymentDetails });
  } catch (error) {
    console.error('Error creating pay later order:', error);
    res.status(500).json({ message: 'Failed to create pay later order' });
  }
});

export default router;

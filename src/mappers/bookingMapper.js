import { canCancelBooking } from '../utils/timeUtils.js';

/**
 * Map booking database row to API response
 */
export function mapBookingRowToApi(row, turfNameMap = {}) {
  return {
    id: row.id,
    turfId: row.turf_id,
    turfName: row.turf_name || turfNameMap[row.turf_id] || row.turf_id,
    userName: row.user_name,
    userEmail: row.user_email,
    userPhone: row.user_phone,
    bookingDate: row.booking_date,
    startTime: row.start_time,
    endTime: row.end_time,
    totalAmount: Number(row.total_amount || 0),
    paymentStatus: row.payment_status || 'completed',
    paymentMethod: row.payment_method || null,
    bookingStatus: row.booking_status || 'confirmed',
    razorpayOrderId: row.razorpay_order_id || null,
    razorpayPaymentId: row.razorpay_payment_id || null,
    cancelledAt: row.cancelled_at || null,
    cancellationReason: row.cancellation_reason || null,
    refundAmount: row.refund_amount ? Number(row.refund_amount) : undefined,
    canCancel: row.booking_status === 'confirmed' ? canCancelBooking(row.booking_date, row.start_time) : false,
    createdAt: row.created_at,
    // Owner settlement information
    ownerSettlementStatus: row.owner_settlement_status || 'pending',
    payoutAmount: row.payout_amount ? Number(row.payout_amount) : null,
    settledAt: row.settled_at || null,
  };
}

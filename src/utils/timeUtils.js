/**
 * Convert time string to minutes
 */
export function timeToMinutes(t) {
  if (!t) return 0;
  const [h, m] = t.split(':').map(Number);
  return h * 60 + (m || 0);
}

/**
 * Check if booking can be cancelled (2 hours before start time)
 */
export function canCancelBooking(bookingDate, startTime) {
  try {
    if (!bookingDate || !startTime) return false;
    
    const now = new Date();
    // Handle both HH:mm and HH:mm:ss time formats
    const cleanStartTime = startTime.split(':').slice(0, 2).join(':');
    const bookingDateTime = new Date(`${bookingDate}T${cleanStartTime}:00`);
    
    // Check if date is valid and booking is in the future
    if (isNaN(bookingDateTime.getTime()) || bookingDateTime <= now) {
      return false;
    }
    
    const timeDiff = bookingDateTime.getTime() - now.getTime();
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    
    return hoursDiff >= 2; // Can cancel if more than 2 hours before booking
  } catch (error) {
    console.error('Error in canCancelBooking:', error);
    return false;
  }
}

/**
 * Calculate refund amount
 */
export function calculateRefundAmount(totalAmount, bookingDate, startTime) {
  const canCancel = canCancelBooking(bookingDate, startTime);
  return canCancel ? totalAmount : 0;
}

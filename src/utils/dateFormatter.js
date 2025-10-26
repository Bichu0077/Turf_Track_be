/**
 * Helper function to format dates consistently
 */
export function formatDate(dateString) {
  if (!dateString) {
    console.log('[formatDate] No date string provided');
    return null;
  }
  try {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      console.log('[formatDate] Invalid date:', dateString);
      return null;
    }
    const formatted = date.toISOString();
    console.log('[formatDate] Formatted date:', dateString, '->', formatted);
    return formatted;
  } catch (error) {
    console.error('[formatDate] Error formatting date:', error, 'Input:', dateString);
    return null;
  }
}

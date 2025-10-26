import { formatDate } from '../utils/dateFormatter.js';

/**
 * Map turf database row to API response
 */
export function mapTurfRowToApi(row) {
  let finalLocation;
  let locationAddress;

  // Case 1: The new coordinate object exists and is valid. Use it.
  if (row.location_coordinates && typeof row.location_coordinates === 'object' && row.location_coordinates.address) {
    finalLocation = {
      address: row.location_coordinates.address,
      latitude: row.location_coordinates.latitude,
      longitude: row.location_coordinates.longitude,
    };
    locationAddress = row.location_coordinates.address;
  } 
  // Case 2: Fallback to the old location string if coordinate object is missing.
  else if (typeof row.location === 'string') {
    finalLocation = {
      address: row.location,
      latitude: null, // Mark coordinates as unavailable
      longitude: null,
    };
    locationAddress = row.location;
  } 
  // Case 3: Default to an empty object if no location data is found at all.
  else {
     finalLocation = {
      address: 'Location not available',
      latitude: null,
      longitude: null,
    };
    locationAddress = 'Location not available';
  }

  const result = {
    _id: row.id,
    id: row.id, // Add id field for frontend compatibility
    name: row.name,
    location: locationAddress, // Send as string for frontend compatibility
    locationCoordinates: finalLocation, // Keep object version for coordinate features
    description: row.description || '',
    images: Array.isArray(row.images) ? row.images : [],
    pricePerHour: Number(row.price_per_hour) || 0, // Ensure it's a number
    operatingHours: row.operating_hours || { open: '06:00', close: '22:00' },
    amenities: Array.isArray(row.amenities) ? row.amenities : [],
    createdAt: formatDate(row.created_at),
    updatedAt: formatDate(row.updated_at)
  };
  
  // Log date formatting for debugging
  if (row.id) {
    console.log(`[mapTurfRowToApi] Turf ${row.id} dates:`, {
      raw_created_at: row.created_at,
      formatted_created_at: result.createdAt,
      raw_updated_at: row.updated_at,
      formatted_updated_at: result.updatedAt
    });
  }
  
  return result;
}

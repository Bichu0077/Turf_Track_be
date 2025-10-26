import express from 'express';
import { supabaseAdmin } from '../config/database.js';
import { auth } from '../middleware/auth.js';
import { mapTurfRowToApi } from '../mappers/turfMapper.js';
import { timeToMinutes } from '../utils/timeUtils.js';
import { calculateDistance } from '../utils/locationUtils.js';

const router = express.Router();

// Get all public turfs
router.get('/public', async (req, res) => {
  try {
    console.log('[GET /api/turfs/public] Request received with query:', req.query);
    const { lat, lon, radius } = req.query;
    
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .order('created_at', { ascending: false });
      
    console.log('[GET /api/turfs/public] Database query result:', { 
      dataCount: data?.length || 0, 
      error: error?.message || null 
    });
      
    if (error) return res.status(400).json({ message: error.message });

    let turfs = (data || []).map(mapTurfRowToApi);
    console.log('[GET /api/turfs/public] Mapped turfs count:', turfs.length);

    // If location filtering is requested, filter by radius
    if (lat && lon && radius) {
      const userLat = parseFloat(lat);
      const userLon = parseFloat(lon);
      const filterRadius = parseFloat(radius);

      turfs = turfs.filter(turf => {
        const turfLocation = turf.locationCoordinates;
        if (typeof turfLocation === 'object' && 
            turfLocation.latitude && 
            turfLocation.longitude) {
          const distance = calculateDistance(
            userLat, 
            userLon, 
            turfLocation.latitude, 
            turfLocation.longitude
          );
          return distance <= filterRadius;
        }
        return true; // Include turfs without coordinates
      });
    }

    console.log('[GET /api/turfs/public] Final turfs count after filtering:', turfs.length);
    res.json({ turfs });
  } catch (e) {
    console.error('Error fetching public turfs:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get turfs owned by current user
router.get('/mine', auth('admin'), async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .eq('owner', req.user.sub)
      .order('created_at', { ascending: false });
    
    if (error) {
      console.error('Fetch mine error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turfs: (data || []).map(mapTurfRowToApi) });
  } catch (e) {
    console.error('Error fetching user turfs:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single turf by ID
router.get('/:id', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('turfs')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (error && error.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (error) {
      console.error('Fetch turf error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error fetching turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get turf availability
router.get('/:id/availability', async (req, res) => {
  try {
    const turfId = req.params.id;
    const date = req.query.date;
    if (!date) return res.status(400).json({ message: 'date (YYYY-MM-DD) is required' });
    
    const { data, error } = await supabaseAdmin
      .from('bookings')
      .select('start_time, end_time, booking_status')
      .eq('turf_id', turfId)
      .eq('booking_date', date)
      .neq('booking_status', 'cancelled');
      
    if (error) return res.status(400).json({ message: error.message });
    
    const bookedTimes = [];
    (data || []).forEach(b => {
      const s = timeToMinutes(b.start_time);
      const e = timeToMinutes(b.end_time);
      for (let m = s; m < e; m += 60) {
        const hh = String(Math.floor(m / 60)).padStart(2, '0');
        bookedTimes.push(`${hh}:00`);
      }
    });
    
    res.json({ bookedTimes: Array.from(new Set(bookedTimes)) });
  } catch (e) {
    console.error('Error fetching availability:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create turf
router.post('/', auth('admin'), async (req, res) => {
  try {
    const { name, location, description, images, pricePerHour, operatingHours, amenities } = req.body;
    
    // Validate required fields
    if (!name || !location || !pricePerHour) {
      return res.status(400).json({ message: 'Name, location, and price per hour are required' });
    }

    if (!operatingHours || !operatingHours.open || !operatingHours.close) {
      return res.status(400).json({ message: 'Operating hours (open and close) are required' });
    }

    // Validate images
    if (images && Array.isArray(images)) {
      for (const image of images) {
        if (image && typeof image === 'string' && image.startsWith('data:image/')) {
          const base64Length = image.length - (image.indexOf(',') + 1);
          const sizeInBytes = Math.ceil((base64Length * 3) / 4);
          const sizeInMB = sizeInBytes / (1024 * 1024);
          
          if (sizeInMB > 5) {
            return res.status(400).json({ 
              message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
            });
          }
        }
      }
    }

    // Prepare location data
    let locationString = '';
    let locationCoordinates = null;

    if (typeof location === 'string') {
      locationString = location;
    } else if (location && typeof location === 'object' && location.address) {
      locationString = location.address;
      locationCoordinates = {
        address: location.address,
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      };
    } else {
      return res.status(400).json({ message: 'Invalid location format' });
    }

    const payload = {
      name: name.trim(),
      location: locationString,
      location_coordinates: locationCoordinates,
      description: description || '',
      images: Array.isArray(images) ? images.filter(img => img && img.trim()) : [],
      price_per_hour: Number(pricePerHour),
      operating_hours: operatingHours,
      amenities: Array.isArray(amenities) ? amenities.filter(a => a.trim()) : [],
      owner: req.user.sub,
    };

    const { data, error } = await supabaseAdmin.from('turfs').insert(payload).select().single();
    if (error) {
      console.error('Database error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.status(201).json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error creating turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update turf
router.put('/:id', auth('admin'), async (req, res) => {
  try {
    const { name, location, description, images, pricePerHour, operatingHours, amenities } = req.body;
    
    // Validate required fields
    if (!name || !location || !pricePerHour) {
      return res.status(400).json({ message: 'Name, location, and price per hour are required' });
    }

    if (!operatingHours || !operatingHours.open || !operatingHours.close) {
      return res.status(400).json({ message: 'Operating hours (open and close) are required' });
    }

    // Validate images
    if (images && Array.isArray(images)) {
      for (const image of images) {
        if (image && typeof image === 'string' && image.startsWith('data:image/')) {
          const base64Length = image.length - (image.indexOf(',') + 1);
          const sizeInBytes = Math.ceil((base64Length * 3) / 4);
          const sizeInMB = sizeInBytes / (1024 * 1024);
          
          if (sizeInMB > 5) {
            return res.status(400).json({ 
              message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
            });
          }
        }
      }
    }

    // Check ownership
    const { data: existingTurf, error: fetchError } = await supabaseAdmin
      .from('turfs')
      .select('owner')
      .eq('id', req.params.id)
      .single();

    if (fetchError && fetchError.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    if (existingTurf.owner !== req.user.sub) {
      return res.status(403).json({ message: 'Not authorized to update this turf' });
    }

    // Prepare location data
    let locationString = '';
    let locationCoordinates = null;

    if (typeof location === 'string') {
      locationString = location;
    } else if (location && typeof location === 'object' && location.address) {
      locationString = location.address;
      locationCoordinates = {
        address: location.address,
        latitude: parseFloat(location.latitude),
        longitude: parseFloat(location.longitude)
      };
    }

    const payload = {
      name: name.trim(),
      location: locationString,
      location_coordinates: locationCoordinates,
      description: description || '',
      images: Array.isArray(images) ? images.filter(img => img && img.trim()) : [],
      price_per_hour: Number(pricePerHour),
      operating_hours: operatingHours,
      amenities: Array.isArray(amenities) ? amenities.filter(a => a.trim()) : []
    };

    const { data, error } = await supabaseAdmin
      .from('turfs')
      .update(payload)
      .eq('id', req.params.id)
      .eq('owner', req.user.sub)
      .select()
      .single();

    if (error) {
      console.error('Update error:', error);
      return res.status(400).json({ message: error.message });
    }
    
    res.json({ turf: mapTurfRowToApi(data) });
  } catch (e) {
    console.error('Error updating turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete turf
router.delete('/:id', auth('admin'), async (req, res) => {
  try {
    // Check ownership
    const { data: existingTurf, error: fetchError } = await supabaseAdmin
      .from('turfs')
      .select('owner, name')
      .eq('id', req.params.id)
      .single();

    if (fetchError && fetchError.code === 'PGRST116') {
      return res.status(404).json({ message: 'Turf not found' });
    }
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    if (existingTurf.owner !== req.user.sub) {
      return res.status(403).json({ message: 'Not authorized to delete this turf' });
    }

    const { error } = await supabaseAdmin
      .from('turfs')
      .delete()
      .eq('id', req.params.id)
      .eq('owner', req.user.sub);

    if (error) return res.status(400).json({ message: error.message });
    res.json({ message: 'Turf deleted successfully' });
  } catch (e) {
    console.error('Error deleting turf:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;

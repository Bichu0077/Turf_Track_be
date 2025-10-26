import { supabaseAdmin, supabaseAnon, supabaseUrl, supabaseServiceKey } from '../config/database.js';

/**
 * Get user from authorization header
 */
export async function getUserFromAuthHeader(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  console.log('[getUserFromAuthHeader] Authorization header:', authHeader);
  console.log('[getUserFromAuthHeader] Extracted token:', token);
  
  if (!token) {
    console.error('[getUserFromAuthHeader] Missing token');
    return { error: 'Missing token' };
  }
  
  const { data, error } = await supabaseAnon.auth.getUser(token);
  if (error) {
    console.error('[getUserFromAuthHeader] supabaseAnon.auth.getUser error:', error);
    return { error: 'Invalid token' };
  }
  
  const user = data.user;
  
  // Get role from profiles table for more accurate role checking
  let userRole = 'user'; // default
  try {
    const { data: profile } = await supabaseAdmin
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .single();
    
    if (profile && profile.role) {
      userRole = profile.role;
    } else {
      // Fallback to user metadata
      userRole = (user?.user_metadata?.role === 'admin') ? 'admin' : 'user';
    }
  } catch (e) {
    console.error('[getUserFromAuthHeader] Error fetching profile role:', e);
    // Fallback to user metadata
    userRole = (user?.user_metadata?.role === 'admin') ? 'admin' : 'user';
  }
  
  return {
    user: {
      sub: user.id,
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name || '',
      role: userRole,
    },
    token,
  };
}

/**
 * Check if an email exists using GoTrue Admin REST API
 */
export async function emailExists(rawEmail) {
  const email = String(rawEmail || '').trim().toLowerCase();
  if (!email) return false;
  try {
    const url = `${supabaseUrl}/auth/v1/admin/users?email=${encodeURIComponent(email)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': supabaseServiceKey,
        'Authorization': `Bearer ${supabaseServiceKey}`,
      },
    });
    if (!resp.ok) {
      console.error('[emailExists] Admin REST error status:', resp.status);
      return false;
    }
    const json = await resp.json().catch(() => ({ users: [] }));
    const users = Array.isArray(json?.users) ? json.users : (Array.isArray(json) ? json : []);
    return users.some(u => (u.email || '').toLowerCase() === email);
  } catch (err) {
    console.error('[emailExists] error:', err);
    return false;
  }
}

/**
 * Get user object by email via Admin REST API
 */
export async function getUserByEmail(rawEmail) {
  const email = String(rawEmail || '').trim().toLowerCase();
  if (!email) return null;
  try {
    const url = `${supabaseUrl}/auth/v1/admin/users?email=${encodeURIComponent(email)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': supabaseServiceKey,
        'Authorization': `Bearer ${supabaseServiceKey}`,
      },
    });
    if (!resp.ok) {
      console.error('[getUserByEmail] Admin REST error status:', resp.status);
      return null;
    }
    const json = await resp.json().catch(() => ({ users: [] }));
    const users = Array.isArray(json?.users) ? json.users : (Array.isArray(json) ? json : []);
    const user = users.find(u => (u.email || '').toLowerCase() === email);
    return user || null;
  } catch (err) {
    console.error('[getUserByEmail] error:', err);
    return null;
  }
}

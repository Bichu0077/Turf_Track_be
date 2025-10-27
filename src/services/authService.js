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
    // Prefer Supabase Admin SDK if available (avoids relying on global `fetch` which may be missing on some Node versions)
    try {
      if (supabaseAdmin && supabaseAdmin.auth && supabaseAdmin.auth.admin && typeof supabaseAdmin.auth.admin.listUsers === 'function') {
        const res = await supabaseAdmin.auth.admin.listUsers();
        // `res` shape may vary between SDK versions. Try common locations.
        const users = (res?.data && (Array.isArray(res.data.users) ? res.data.users : (Array.isArray(res.data) ? res.data : []))) || (Array.isArray(res?.users) ? res.users : []);
        if (Array.isArray(users) && users.length > 0) {
          return users.some(u => (u.email || '').toLowerCase() === email);
        }
        // If SDK returned no users, fallthrough to other checks below
      }
    } catch (sdkErr) {
      console.error('[emailExists] Supabase admin SDK listUsers error:', sdkErr);
      // continue to fallback approaches
    }

    // Fallback: use global fetch to call the Admin REST endpoint if available
    if (typeof fetch === 'function') {
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
      } else {
        const json = await resp.json().catch(() => ({ users: [] }));
        const users = Array.isArray(json?.users) ? json.users : (Array.isArray(json) ? json : []);
        return users.some(u => (u.email || '').toLowerCase() === email);
      }
    } else {
      console.warn('[emailExists] global fetch is not available in this Node runtime. Falling back to SDK-only approach');
    }

    // As a last-resort, try to iterate listUsers with pagination (if SDK supports parameters)
    try {
      if (supabaseAdmin && supabaseAdmin.auth && supabaseAdmin.auth.admin && typeof supabaseAdmin.auth.admin.listUsers === 'function') {
        // Try with a paginated call if supported by SDK (some versions accept { page, per_page })
        const res2 = await supabaseAdmin.auth.admin.listUsers({ page: 1, per_page: 100 });
        const users = (res2?.data && (Array.isArray(res2.data.users) ? res2.data.users : (Array.isArray(res2.data) ? res2.data : []))) || (Array.isArray(res2?.users) ? res2.users : []);
        return Array.isArray(users) && users.some(u => (u.email || '').toLowerCase() === email);
      }
    } catch (e) {
      console.error('[emailExists] fallback SDK paginated listUsers error:', e);
    }

    return false;
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
    // Prefer SDK
    try {
      if (supabaseAdmin && supabaseAdmin.auth && supabaseAdmin.auth.admin && typeof supabaseAdmin.auth.admin.listUsers === 'function') {
        const res = await supabaseAdmin.auth.admin.listUsers();
        const users = (res?.data && (Array.isArray(res.data.users) ? res.data.users : (Array.isArray(res.data) ? res.data : []))) || (Array.isArray(res?.users) ? res.users : []);
        const user = Array.isArray(users) ? users.find(u => (u.email || '').toLowerCase() === email) : null;
        if (user) return user;
      }
    } catch (sdkErr) {
      console.error('[getUserByEmail] Supabase admin SDK listUsers error:', sdkErr);
    }

    // Fallback to REST admin endpoint if fetch available
    if (typeof fetch === 'function') {
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
    }

    // Try a paginated SDK call as a last option
    try {
      if (supabaseAdmin && supabaseAdmin.auth && supabaseAdmin.auth.admin && typeof supabaseAdmin.auth.admin.listUsers === 'function') {
        const res2 = await supabaseAdmin.auth.admin.listUsers({ page: 1, per_page: 100 });
        const users = (res2?.data && (Array.isArray(res2.data.users) ? res2.data.users : (Array.isArray(res2.data) ? res2.data : []))) || (Array.isArray(res2?.users) ? res2.users : []);
        const user = Array.isArray(users) ? users.find(u => (u.email || '').toLowerCase() === email) : null;
        return user || null;
      }
    } catch (e) {
      console.error('[getUserByEmail] fallback SDK paginated listUsers error:', e);
    }

    return null;
  } catch (err) {
    console.error('[getUserByEmail] error:', err);
    return null;
  }
}

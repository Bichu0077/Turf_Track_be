import { getUserFromAuthHeader } from '../services/authService.js';
import { supabaseAdmin } from '../config/database.js';

/**
 * Authentication middleware
 */
export function auth(requiredRole) {
  return async (req, res, next) => {
    const result = await getUserFromAuthHeader(req);
    if (result.error) return res.status(401).json({ message: result.error });
    req.user = result.user;
    
    // Special handling for superadmin role
    if (requiredRole === 'superadmin') {
      if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Forbidden - Super Admin access required' });
      }
      
      // Security check: Ensure only one superadmin exists
      try {
        const { data: superAdmins, error } = await supabaseAdmin
          .from('profiles')
          .select('id')
          .eq('role', 'superadmin');
        
        if (error) {
          console.error('Error checking superadmin count:', error);
          return res.status(500).json({ message: 'Authentication error' });
        }
        
        if (superAdmins.length > 1) {
          console.error('Multiple superadmin accounts detected! IDs:', superAdmins.map(s => s.id));
          return res.status(403).json({ 
            message: 'Security violation: Multiple super admin accounts detected. Please contact system administrator.' 
          });
        }
        
        if (superAdmins.length === 0 || superAdmins[0].id !== req.user.id) {
          return res.status(403).json({ message: 'Forbidden - Invalid super admin account' });
        }
      } catch (e) {
        console.error('Error in superadmin security check:', e);
        return res.status(500).json({ message: 'Authentication error' });
      }
    } else if (requiredRole && req.user.role !== requiredRole) {
      // Allow superadmin to access admin endpoints
      if (requiredRole === 'admin' && req.user.role === 'superadmin') {
        // Superadmin can access admin endpoints
      } else {
        return res.status(403).json({ message: 'Forbidden' });
      }
    }
    
    next();
  };
}

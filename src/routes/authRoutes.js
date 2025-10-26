import express from 'express';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { supabaseAdmin, supabaseAnon, supabaseUrl, supabaseAnonKey } from '../config/database.js';
import { 
  pendingRegistrations, 
  pendingPasswordResets, 
  pendingResetTokens, 
  OTP_EXPIRY_SECONDS, 
  isProduction,
  userActivities 
} from '../config/constants.js';
import { auth } from '../middleware/auth.js';
import { emailExists, getUserByEmail } from '../services/authService.js';
import { sendOtpEmail } from '../services/emailService.js';
import { generateOtpCode } from '../utils/otpGenerator.js';
import { formatDate } from '../utils/dateFormatter.js';
import { appendUserActivity } from '../utils/activityLogger.js';

const router = express.Router();

// Check if an email is already registered
router.get('/email-available', async (req, res) => {
  try {
    const rawEmail = (req.query.email || '').toString();
    if (!rawEmail) return res.status(400).json({ message: 'Missing email' });
    const exists = await emailExists(rawEmail);
    return res.json({ available: !exists });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start registration: create pending registration and send OTP
router.post('/register/start', async (req, res) => {
  try {
    const { name, email, phone, password, role } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const finalRole = role === 'admin' ? 'admin' : 'user';

    // Prevent starting registration if email already exists
    const exists = await emailExists(email);
    if (exists) return res.status(409).json({ message: 'Account is already registered' });

    // Create transaction and OTP
    const transactionId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const code = generateOtpCode();
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;

    // Store pending
    pendingRegistrations.set(transactionId, { name, email, phone, password, role: finalRole, code, createdAt: now, expiresAt });

    // Attempt to send email
    try {
      await sendOtpEmail(email, code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send OTP. Please try again later.' });
      }
    }

    res.status(201).json({
      transactionId,
      email,
      expiresInSeconds: OTP_EXPIRY_SECONDS,
      ...(isProduction ? {} : { devCode: pendingRegistrations.get(transactionId).code })
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify OTP and complete registration
router.post('/register/verify', async (req, res) => {
  try {
    const { transactionId, code, otp, email } = req.body || {};
    const providedCode = (otp || code || '').toString();
    if ((!transactionId && !email) || !providedCode) return res.status(400).json({ message: 'Missing transaction or code' });

    // Find pending by transactionId first; fallback to email lookup for FE compatibility
    let entryKey = transactionId;
    let entry = transactionId ? pendingRegistrations.get(transactionId) : undefined;
    if (!entry && email) {
      for (const [key, value] of pendingRegistrations.entries()) {
        if (value.email === email) { entry = value; entryKey = key; break; }
      }
    }
    if (!entry) return res.status(404).json({ message: 'No pending registration found' });
    if (Date.now() > entry.expiresAt) {
      pendingRegistrations.delete(entryKey);
      return res.status(400).json({ message: 'OTP expired. Please resend.' });
    }
    if (entry.code !== providedCode) return res.status(400).json({ message: 'Invalid OTP' });

    // Create the user (confirmed) via Admin API
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email: entry.email,
      password: entry.password,
      email_confirm: true,
      user_metadata: { name: entry.name, phone: entry.phone, role: entry.role },
    });
    if (createError) return res.status(400).json({ message: createError.message });
    const newUser = created.user;

    // Ensure a profile row exists
    await supabaseAdmin.from('profiles').upsert({ id: newUser.id, name: entry.name, phone: entry.phone, role: entry.role });

    // Sign in to mint an access token for the client
    const { data: signInData, error: signInError } = await supabaseAnon.auth.signInWithPassword({ email: entry.email, password: entry.password });
    if (signInError || !signInData.session) return res.status(500).json({ message: signInError?.message || 'Failed to create session' });

    // Cleanup
    pendingRegistrations.delete(entryKey);

    const accessToken = signInData.session.access_token;
    const userResponse = { 
      token: accessToken, 
      user: { 
        id: newUser.id, 
        name: entry.name, 
        email: entry.email, 
        role: entry.role,
        createdAt: formatDate(newUser.created_at),
        memberSince: formatDate(newUser.created_at),
        lastLoginAt: new Date().toISOString()
      } 
    };
    
    console.log("[POST /api/auth/register/verify] user response:", userResponse);
    res.json(userResponse);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Resend OTP for an existing pending registration
router.post('/register/resend', async (req, res) => {
  try {
    const { transactionId, email } = req.body || {};
    if (!transactionId && !email) return res.status(400).json({ message: 'Missing transaction or email' });

    // Find pending
    let entryKey = transactionId;
    let entry = transactionId ? pendingRegistrations.get(transactionId) : undefined;
    if (!entry && email) {
      for (const [key, value] of pendingRegistrations.entries()) {
        if (value.email === email) { entry = value; entryKey = key; break; }
      }
    }
    if (!entry) return res.status(404).json({ message: 'No pending registration found' });

    // Generate a new code and extend expiry
    entry.code = generateOtpCode();
    entry.expiresAt = Date.now() + OTP_EXPIRY_SECONDS * 1000;
    pendingRegistrations.set(entryKey, entry);

    try {
      await sendOtpEmail(entry.email, entry.code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send OTP. Please try again later.' });
      }
    }

    res.json({ expiresInSeconds: OTP_EXPIRY_SECONDS, ...(isProduction ? {} : { devCode: entry.code }) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (error || !data.session) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = data.session.access_token;
    const { data: userData } = await supabaseAnon.auth.getUser(accessToken);
    const meta = userData?.user?.user_metadata || {};
    
    // Get role from profiles table
    let userRole = 'user';
    try {
      const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('role')
        .eq('id', userData?.user?.id)
        .single();
      
      if (profile && profile.role) {
        userRole = profile.role;
      } else {
        userRole = (meta.role === 'admin') ? 'admin' : 'user';
      }
    } catch (e) {
      console.error('Error fetching profile role during login:', e);
      userRole = (meta.role === 'admin') ? 'admin' : 'user';
    }
    
    // Security check for superadmin
    if (userRole === 'superadmin') {
      try {
        const { data: superAdmins, error: saError } = await supabaseAdmin
          .from('profiles')
          .select('id')
          .eq('role', 'superadmin');
        
        if (saError) {
          console.error('Error checking superadmin count during login:', saError);
          return res.status(500).json({ message: 'Authentication error' });
        }
        
        if (superAdmins.length > 1) {
          console.error('Multiple superadmin accounts detected during login! IDs:', superAdmins.map(s => s.id));
          return res.status(403).json({ 
            message: 'Security violation: Multiple super admin accounts detected. Please contact system administrator.' 
          });
        }
        
        if (superAdmins.length === 0 || superAdmins[0].id !== userData?.user?.id) {
          return res.status(403).json({ message: 'Invalid super admin account' });
        }
      } catch (e) {
        console.error('Error in superadmin security check during login:', e);
        return res.status(500).json({ message: 'Authentication error' });
      }
    }
    
    const userResponse = { 
      token: accessToken, 
      user: { 
        id: userData?.user?.id, 
        name: meta.name || '', 
        email: userData?.user?.email, 
        role: userRole,
        createdAt: formatDate(userData?.user?.created_at),
        memberSince: formatDate(userData?.user?.created_at),
        lastLoginAt: new Date().toISOString()
      } 
    };
    
    console.log("[POST /api/auth/login] user response:", userResponse);
    res.json(userResponse);
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Start forgot password: create pending reset and send OTP
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: 'Missing email' });

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'No account found with that email' });
    }

    const transactionId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const code = generateOtpCode();
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;

    pendingPasswordResets.set(transactionId, { email: user.email, code, createdAt: now, expiresAt });

    try {
      await sendOtpEmail(user.email, code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to send reset code. Please try again later.' });
      }
    }

    res.status(201).json({
      transactionId,
      email: user.email,
      expiresInSeconds: OTP_EXPIRY_SECONDS,
      ...(isProduction ? {} : { devCode: code })
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify forgot password OTP -> issue reset token
router.post('/forgot-password/verify', async (req, res) => {
  try {
    const { transactionId, code, otp } = req.body || {};
    const providedCode = (otp || code || '').toString();
    if (!transactionId || !providedCode) return res.status(400).json({ message: 'Missing transaction or code' });

    const entry = pendingPasswordResets.get(transactionId);
    if (!entry) return res.status(404).json({ message: 'No pending reset found' });
    if (Date.now() > entry.expiresAt) {
      pendingPasswordResets.delete(transactionId);
      return res.status(400).json({ message: 'OTP expired. Please resend.' });
    }
    if (entry.code !== providedCode) return res.status(400).json({ message: 'Invalid OTP' });

    const resetToken = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const now = Date.now();
    const expiresAt = now + OTP_EXPIRY_SECONDS * 1000;
    pendingResetTokens.set(resetToken, { email: entry.email, createdAt: now, expiresAt });

    // Cleanup OTP entry
    pendingPasswordResets.delete(transactionId);

    res.json({ resetToken, email: entry.email, expiresInSeconds: OTP_EXPIRY_SECONDS });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Resend forgot password OTP
router.post('/forgot-password/resend', async (req, res) => {
  try {
    const { transactionId } = req.body || {};
    if (!transactionId) return res.status(400).json({ message: 'Missing transaction' });

    const entry = pendingPasswordResets.get(transactionId);
    if (!entry) return res.status(404).json({ message: 'No pending reset found' });

    entry.code = generateOtpCode();
    entry.expiresAt = Date.now() + OTP_EXPIRY_SECONDS * 1000;
    pendingPasswordResets.set(transactionId, entry);

    try {
      await sendOtpEmail(entry.email, entry.code);
    } catch (mailErr) {
      if (isProduction) {
        console.error('Failed to send OTP email:', mailErr);
        return res.status(500).json({ message: 'Failed to resend reset code. Please try again later.' });
      }
    }

    res.json({ expiresInSeconds: OTP_EXPIRY_SECONDS, ...(isProduction ? {} : { devCode: entry.code }) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Perform password reset with reset token
router.post('/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body || {};
    if (!resetToken || !newPassword) return res.status(400).json({ message: 'Missing reset token or new password' });
    if (String(newPassword).length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });

    const entry = pendingResetTokens.get(resetToken);
    if (!entry) return res.status(400).json({ message: 'Invalid or expired reset token' });
    if (Date.now() > entry.expiresAt) {
      pendingResetTokens.delete(resetToken);
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const user = await getUserByEmail(entry.email);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(user.id, { password: String(newPassword) });
    if (updateError) return res.status(400).json({ message: updateError.message });

    // Cleanup reset token after successful update
    pendingResetTokens.delete(resetToken);

    res.json({ message: 'Password updated' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user
router.get('/me', auth(), async (req, res) => {
  try {
    const { data: userData, error: authError } = await supabaseAdmin.auth.admin.getUserById(req.user.sub);
    if (authError) return res.status(400).json({ message: authError.message });

    const { data: profileData, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('id, name, phone, location, company, role, profile_pic')
      .eq('id', req.user.sub)
      .single();
    
    if (profileError) return res.status(400).json({ message: profileError.message });

    const userObj = {
      ...profileData,
      email: userData.user.email,
      avatar: profileData?.profile_pic,
      createdAt: formatDate(userData.user.created_at),
      memberSince: formatDate(userData.user.created_at),
      lastLoginAt: new Date().toISOString()
    };
    
    res.json({ user: userObj });
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Recent activity endpoint
router.get('/activity', auth(), async (req, res) => {
  try {
    const userId = req.user.sub;
    const limit = Number(req.query.limit || 20);
    const list = (userActivities.get(userId) || []).slice(0, Math.max(1, Math.min(100, limit)));
    res.json({ activities: list });
  } catch (e) {
    console.error('Server error fetching activity:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update profile
router.put('/me', auth(), async (req, res) => {
  try {
    const { name, email, phone, location, company, avatar } = req.body;
    const userId = req.user.sub;

    // Validate avatar size if provided
    if (avatar && typeof avatar === 'string') {
      if (avatar.startsWith('data:image/')) {
        const base64Length = avatar.length - (avatar.indexOf(',') + 1);
        const sizeInBytes = Math.ceil((base64Length * 3) / 4);
        const sizeInMB = sizeInBytes / (1024 * 1024);
        
        if (sizeInMB > 1) {
          return res.status(400).json({ 
            message: `Image size (${sizeInMB.toFixed(1)}MB) is too large. Please compress the image or choose a smaller one.` 
          });
        }
      }
    }

    // Update profile fields
    if (name !== undefined || phone !== undefined || location !== undefined || company !== undefined || avatar !== undefined) {
      const profileUpdateFields = {};
      const { data: currentProfile } = await supabaseAdmin
        .from('profiles')
        .select('name, phone, location, company, profile_pic')
        .eq('id', userId)
        .single();
        
      if (name !== undefined) profileUpdateFields.name = name;
      if (phone !== undefined) profileUpdateFields.phone = phone;
      if (location !== undefined) profileUpdateFields.location = location;
      if (company !== undefined) profileUpdateFields.company = company;
      if (avatar !== undefined) profileUpdateFields.profile_pic = avatar;

      const { error: profileError } = await supabaseAdmin
        .from('profiles')
        .update(profileUpdateFields)
        .eq('id', userId);

      if (profileError) return res.status(400).json({ message: profileError.message });

      // Log activity
      const changed = {};
      if (currentProfile) {
        if (name !== undefined && currentProfile.name !== name) changed.name = { from: currentProfile.name, to: name };
        if (phone !== undefined && currentProfile.phone !== phone) changed.phone = { from: currentProfile.phone, to: phone };
        if (location !== undefined && currentProfile.location !== location) changed.location = { from: currentProfile.location, to: location };
        if (company !== undefined && currentProfile.company !== company) changed.company = { from: currentProfile.company, to: company };
        if (avatar !== undefined && currentProfile.profile_pic !== avatar) changed.avatar = { from: currentProfile.profile_pic, to: avatar };
      }
      if (Object.keys(changed).length > 0) {
        appendUserActivity(userId, {
          type: 'profile_update',
          message: 'Updated profile information',
          details: { changed }
        });
      }
    }

    // Update email if provided
    if (email && email !== req.user.email) {
      const { error: emailError } = await supabaseAdmin.auth.admin.updateUserById(userId, { email: email });
      if (emailError) return res.status(400).json({ message: emailError.message });
      appendUserActivity(userId, {
        type: 'email_update',
        message: 'Updated account email',
        details: { from: req.user.email, to: email }
      });
    }

    // Fetch updated profile
    const { data: updatedProfile, error: fetchError } = await supabaseAdmin
      .from('profiles')
      .select('id, name, phone, location, company, role, profile_pic')
      .eq('id', userId)
      .single();
    
    if (fetchError) return res.status(400).json({ message: fetchError.message });
    
    res.json({ 
      message: 'Profile updated successfully',
      profile: {
        ...updatedProfile,
        avatar: updatedProfile.profile_pic
      }
    });
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password
router.post('/change-password', auth(), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.sub;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Both current password and new password are required' });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({ message: 'New password must be different from current password' });
    }

    // Verify current password
    const tempClient = createClient(supabaseUrl, supabaseAnonKey, { auth: { persistSession: false } });
    const { data: signInData, error: signInError } = await tempClient.auth.signInWithPassword({
      email: req.user.email,
      password: currentPassword
    });
    
    if (signInError) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    await tempClient.auth.signOut();

    // Update password
    const { error: passwordError } = await supabaseAdmin.auth.admin.updateUserById(userId, { password: newPassword });
    
    if (passwordError) {
      return res.status(400).json({ message: 'Failed to update password: ' + passwordError.message });
    }

    appendUserActivity(userId, {
      type: 'password_change',
      message: 'Changed account password',
      details: {}
    });
    res.json({ message: 'Password changed successfully' });
  } catch (e) {
    console.error('Server error in password change:', e);
    res.status(500).json({ message: 'Server error: ' + e.message });
  }
});

// Get profile
router.get('/profile', auth(), async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const { data: userData, error: authError } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (authError) return res.status(400).json({ message: authError.message });
    
    const { data: profileData, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('*')
      .eq('id', userId)
      .single();

    if (profileError) {
      if (profileError.code === 'PGRST116') {
        return res.status(404).json({ message: 'Profile not found' });
      }
      return res.status(400).json({ message: profileError.message });
    }

    const userResponse = {
      user: {
        id: profileData.id,
        name: profileData.name,
        email: userData.user.email,
        phone: profileData.phone,
        company: profileData.company,
        location: profileData.location,
        profile_pic: profileData.profile_pic,
        avatar: profileData.profile_pic,
        role: profileData.role,
        createdAt: formatDate(userData.user.created_at),
        memberSince: formatDate(userData.user.created_at),
        lastLoginAt: new Date().toISOString()
      }
    };
    
    res.json(userResponse);
  } catch (e) {
    console.error('Server error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;

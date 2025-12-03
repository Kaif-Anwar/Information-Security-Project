import express from 'express';
import bcrypt from 'bcryptjs';
import { User } from '../models/User.js';
import { logSecurityEvent } from '../middleware/securityLogger.js';

const router = express.Router();

/**
 * POST /api/auth/register
 * Register a new user
 */
router.post('/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;

    // Validation
    if (!username || !password || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      await logSecurityEvent('AUTH_ATTEMPT', null, { username, reason: 'User already exists' }, req.ip);
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      passwordHash,
      publicKey,
      lastLogin: new Date()
    });

    await user.save();

    console.log('✅ User registered successfully:');
    console.log('   Username:', username);
    console.log('   User ID:', user._id.toString());
    console.log('   Public Key stored:', publicKey ? 'Yes' : 'No');
    console.log('   Timestamp:', new Date().toISOString());

    await logSecurityEvent('AUTH_SUCCESS', user._id, { username }, req.ip);

    res.status(201).json({
      message: 'User registered successfully',
      userId: user._id.toString(),
      username: user.username
    });
  } catch (error) {
    console.error('Registration error:', error);
    await logSecurityEvent('AUTH_FAILURE', null, { error: error.message }, req.ip);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log('\n🔐 Login attempt received:');
    console.log('   Username:', username);
    // Security: Do not log password or password length
    console.log('   IP:', req.ip);
    console.log('   Timestamp:', new Date().toISOString());

    if (!username || !password) {
      console.log('❌ Login failed: Missing username or password');
      return res.status(400).json({ error: 'Missing username or password' });
    }

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      console.log('❌ Login failed: User not found');
      await logSecurityEvent('AUTH_FAILURE', null, { username, reason: 'User not found' }, req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('   User found in database');
    console.log('   User ID:', user._id.toString());
    console.log('   Has public key:', !!user.publicKey);

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      console.log('❌ Login failed: Invalid password');
      await logSecurityEvent('AUTH_FAILURE', user._id, { username, reason: 'Invalid password' }, req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('   Password verified: ✓');

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    console.log('✅ User logged in successfully:');
    console.log('   Username:', username);
    console.log('   User ID:', user._id.toString());
    console.log('   Public Key available:', user.publicKey ? 'Yes' : 'No');
    if (user.publicKey) {
      try {
        const publicKeyObj = JSON.parse(user.publicKey);
        console.log('   Public Key structure:', {
          hasEncryption: !!publicKeyObj.encryption,
          hasSigning: !!publicKeyObj.signing,
          encryptionLength: publicKeyObj.encryption?.length || 0,
          signingLength: publicKeyObj.signing?.length || 0
        });
      } catch (e) {
        console.log('   Public Key parse error:', e.message);
      }
    }
    console.log('   Timestamp:', new Date().toISOString());
    console.log('   ⚠️  Note: Private keys must be loaded from client-side IndexedDB');
    console.log('   ⚠️  If login fails on client, check browser console for key loading errors\n');

    await logSecurityEvent('AUTH_SUCCESS', user._id, { username }, req.ip);

    res.json({
      message: 'Login successful',
      userId: user._id.toString(),
      username: user.username,
      publicKey: user.publicKey
    });
  } catch (error) {
    console.error('Login error:', error);
    await logSecurityEvent('AUTH_FAILURE', null, { error: error.message }, req.ip);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/auth/user/:userId
 * Get user public key
 */
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select('username publicKey');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      userId: user._id.toString(),
      username: user.username,
      publicKey: user.publicKey
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;


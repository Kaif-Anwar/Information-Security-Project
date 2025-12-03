import { SecurityLog } from '../models/SecurityLog.js';

/**
 * Simple session-based auth middleware
 * In production, use JWT tokens
 */
export const requireAuth = async (req, res, next) => {
  try {
    // Express normalizes headers to lowercase, but also check original case
    const userId = req.headers['x-user-id'] || req.headers['X-User-Id'] || req.get('x-user-id') || req.get('X-User-Id');
    
    // Debug logging
    console.log('🔐 Auth middleware check:', {
      path: req.path,
      method: req.method,
      headers: {
        'x-user-id': req.headers['x-user-id'],
        'X-User-Id': req.headers['X-User-Id'],
        allHeaders: Object.keys(req.headers).filter(h => h.toLowerCase().includes('user'))
      },
      userId: userId || 'NOT FOUND'
    });
    
    if (!userId) {
      // Log unauthorized access attempt
      await SecurityLog.create({
        eventType: 'AUTH_ATTEMPT',
        details: { path: req.path, method: req.method },
        ipAddress: req.ip
      });
      
      console.error('❌ Unauthorized: Missing x-user-id header for', req.path);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    req.userId = userId;
    console.log('✅ Auth successful for userId:', userId);
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};


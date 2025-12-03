import { SecurityLog } from '../models/SecurityLog.js';

/**
 * Middleware to log security events
 */
export const logSecurityEvent = async (eventType, userId, details, ipAddress) => {
  try {
    await SecurityLog.create({
      eventType,
      userId,
      details,
      ipAddress,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error logging security event:', error);
  }
};

/**
 * Middleware wrapper for logging requests
 */
export const securityLogger = (eventType) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log after response
      const userId = req.userId || null;
      logSecurityEvent(eventType, userId, {
        path: req.path,
        method: req.method,
        statusCode: res.statusCode
      }, req.ip);
      
      return originalSend.call(this, data);
    };
    
    next();
  };
};


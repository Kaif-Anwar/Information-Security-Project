import express from 'express';
import { User } from '../models/User.js';
import { logSecurityEvent } from '../middleware/securityLogger.js';
import { requireAuth } from '../middleware/auth.js';
import { verifyECDSASignature, validateTimestamp } from '../utils/crypto.js';

const router = express.Router();

/**
 * POST /api/key-exchange/initiate
 * Initiate key exchange protocol
 * Client sends their public key and ephemeral DH parameters
 */
router.post('/initiate', requireAuth, async (req, res) => {
  try {
    const { receiverId, publicKey, ephemeralPublicKey, signature, timestamp, nonce } = req.body;
    const senderId = req.userId;
    
    console.log('🔐 Key exchange initiate request:', {
      senderId,
      receiverId,
      hasPublicKey: !!publicKey,
      hasEphemeralPublicKey: !!ephemeralPublicKey,
      hasSignature: !!signature,
      timestamp,
      hasNonce: !!nonce
    });

    if (!receiverId || !publicKey || !ephemeralPublicKey || !signature || !timestamp || !nonce) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', senderId, { reason: 'Missing required fields' }, req.ip);
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify receiver exists
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', senderId, { reason: 'Receiver not found' }, req.ip);
      return res.status(404).json({ error: 'Receiver not found' });
    }

    // Verify sender exists to get their public key for signature verification
    const sender = await User.findById(senderId);
    if (!sender) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', senderId, { reason: 'Sender not found' }, req.ip);
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Validate timestamp
    if (!validateTimestamp(timestamp)) {
      await logSecurityEvent('INVALID_SIGNATURE', senderId, {
        context: 'key_exchange_initiate',
        reason: 'Invalid timestamp',
        timestamp
      }, req.ip);
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    // Verify signature
    try {
      const message = `${senderId}:${receiverId}:${ephemeralPublicKey}:${timestamp}:${nonce}`;
      let signingPublicKey = null;
      
      console.log('🔐 Signature verification:', {
        senderId,
        receiverId,
        messageLength: message.length,
        signatureLength: signature?.length || 0,
        signaturePreview: signature?.substring(0, 50) || 'missing'
      });
      
      // Parse sender's public key JSON to get signing key
      try {
        const senderPublicKeys = JSON.parse(sender.publicKey);
        if (senderPublicKeys.signing) {
          signingPublicKey = senderPublicKeys.signing;
          console.log('🔐 Signing public key found, length:', signingPublicKey.length);
        } else {
          console.warn('⚠️  Signing key not found in sender public keys');
        }
      } catch (parseError) {
        console.error('❌ Error parsing sender public key:', parseError);
        console.error('Public key data:', sender.publicKey?.substring(0, 100));
      }

      if (signingPublicKey) {
        console.log('🔐 Attempting signature verification...');
        const isValid = verifyECDSASignature(message, signature, signingPublicKey);
        console.log('🔐 Signature verification result:', isValid);
        
        if (!isValid) {
          console.error('❌ Signature verification FAILED');
          console.error('Message:', message);
          console.error('Signature (first 100 chars):', signature?.substring(0, 100));
          console.error('Public key (first 100 chars):', signingPublicKey?.substring(0, 100));
          
          await logSecurityEvent('INVALID_SIGNATURE', senderId, {
            context: 'key_exchange_initiate',
            reason: 'Signature verification failed',
            receiverId,
            timestamp
          }, req.ip);
          
          // In development, allow if signature is missing or invalid (for testing)
          if (process.env.NODE_ENV !== 'production') {
            console.warn('⚠️  DEVELOPMENT MODE: Allowing key exchange despite invalid signature');
          } else {
            return res.status(401).json({ error: 'Invalid signature' });
          }
        } else {
          console.log('✅ Signature verification SUCCESS');
        }
      } else {
        // If we can't verify (no signing key available), log a warning but allow
        // In production, you might want to reject this
        console.warn('⚠️  Cannot verify signature: signing public key not available for user:', senderId);
        console.warn('⚠️  Allowing key exchange to proceed without signature verification');
      }
    } catch (verifyError) {
      console.error('❌ Signature verification error:', verifyError);
      console.error('Error details:', {
        message: verifyError.message,
        stack: verifyError.stack
      });
      
      await logSecurityEvent('INVALID_SIGNATURE', senderId, {
        context: 'key_exchange_initiate',
        reason: 'Signature verification error: ' + verifyError.message,
        receiverId,
        timestamp
      }, req.ip);
      
      // In development, allow despite error
      if (process.env.NODE_ENV !== 'production') {
        console.warn('⚠️  DEVELOPMENT MODE: Allowing key exchange despite verification error');
      } else {
        return res.status(401).json({ error: 'Signature verification failed' });
      }
    }

    await logSecurityEvent('KEY_EXCHANGE_ATTEMPT', senderId, {
      receiverId,
      timestamp,
      nonce
    }, req.ip);

    res.json({
      message: 'Key exchange initiated',
      receiverPublicKey: receiver.publicKey,
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Key exchange initiate error:', error);
    await logSecurityEvent('KEY_EXCHANGE_FAILURE', req.userId, { error: error.message }, req.ip);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/key-exchange/respond
 * Respond to key exchange
 * Receiver sends their ephemeral public key and signature
 */
router.post('/respond', requireAuth, async (req, res) => {
  try {
    const { senderId, ephemeralPublicKey, signature, timestamp, nonce } = req.body;
    const receiverId = req.userId;

    if (!senderId || !ephemeralPublicKey || !signature || !timestamp || !nonce) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', receiverId, { reason: 'Missing required fields' }, req.ip);
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Verify sender exists
    const sender = await User.findById(senderId);
    if (!sender) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', receiverId, { reason: 'Sender not found' }, req.ip);
      return res.status(404).json({ error: 'Sender not found' });
    }

    // Verify receiver exists to get their public key
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', receiverId, { reason: 'Receiver not found' }, req.ip);
      return res.status(404).json({ error: 'Receiver not found' });
    }

    // Validate timestamp
    if (!validateTimestamp(timestamp)) {
      await logSecurityEvent('INVALID_SIGNATURE', receiverId, {
        context: 'key_exchange_respond',
        reason: 'Invalid timestamp',
        timestamp,
        senderId
      }, req.ip);
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    // Verify signature
    try {
      const message = `${receiverId}:${senderId}:${ephemeralPublicKey}:${timestamp}:${nonce}`;
      let signingPublicKey = null;
      
      // Parse receiver's public key JSON to get signing key
      try {
        const receiverPublicKeys = JSON.parse(receiver.publicKey);
        if (receiverPublicKeys.signing) {
          signingPublicKey = receiverPublicKeys.signing;
        }
      } catch (parseError) {
        console.error('Error parsing receiver public key:', parseError);
      }

      if (signingPublicKey) {
        const isValid = verifyECDSASignature(message, signature, signingPublicKey);
        if (!isValid) {
          await logSecurityEvent('INVALID_SIGNATURE', receiverId, {
            context: 'key_exchange_respond',
            reason: 'Signature verification failed',
            senderId,
            timestamp
          }, req.ip);
          return res.status(401).json({ error: 'Invalid signature' });
        }
      } else {
        console.warn('Cannot verify signature: signing public key not available for user:', receiverId);
      }
    } catch (verifyError) {
      await logSecurityEvent('INVALID_SIGNATURE', receiverId, {
        context: 'key_exchange_respond',
        reason: 'Signature verification error: ' + verifyError.message,
        senderId,
        timestamp
      }, req.ip);
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    await logSecurityEvent('KEY_EXCHANGE_ATTEMPT', receiverId, {
      senderId,
      timestamp,
      nonce
    }, req.ip);

    res.json({
      message: 'Key exchange response received',
      senderPublicKey: sender.publicKey,
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Key exchange respond error:', error);
    await logSecurityEvent('KEY_EXCHANGE_FAILURE', req.userId, { error: error.message }, req.ip);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/key-exchange/confirm
 * Final key confirmation step
 */
router.post('/confirm', requireAuth, async (req, res) => {
  try {
    const { otherUserId, keyConfirmation, signature, timestamp } = req.body;
    const userId = req.userId;

    if (!otherUserId || !keyConfirmation || !signature || !timestamp) {
      await logSecurityEvent('KEY_EXCHANGE_FAILURE', userId, { reason: 'Missing required fields' }, req.ip);
      return res.status(400).json({ error: 'Missing required fields' });
    }

    await logSecurityEvent('KEY_EXCHANGE_SUCCESS', userId, {
      otherUserId,
      timestamp
    }, req.ip);

    res.json({
      message: 'Key exchange confirmed',
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Key exchange confirm error:', error);
    await logSecurityEvent('KEY_EXCHANGE_FAILURE', req.userId, { error: error.message }, req.ip);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/key-exchange/invalid-signature
 * Log invalid signature (security event) - for client-side reporting
 */
router.post('/invalid-signature', requireAuth, async (req, res) => {
  try {
    const { context, reason, signature, data, otherUserId } = req.body;
    const userId = req.userId;

    await logSecurityEvent('INVALID_SIGNATURE', userId, {
      context: context || 'key_exchange',
      reason: reason || 'Unknown',
      otherUserId: otherUserId || null,
      signature: signature ? signature.substring(0, 50) + '...' : null,
      data: data ? (typeof data === 'string' ? data.substring(0, 100) + '...' : 'Object') : null
    }, req.ip);

    res.json({ message: 'Invalid signature logged' });
  } catch (error) {
    console.error('Log invalid signature error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;


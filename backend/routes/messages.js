import express from 'express';
import { Message } from '../models/Message.js';
import { logSecurityEvent } from '../middleware/securityLogger.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

/**
 * POST /api/messages/send
 * Send an encrypted message
 */
router.post('/send', requireAuth, async (req, res) => {
  try {
    const { receiverId, ciphertext, iv, authTag, sequenceNumber, nonce, timestamp } = req.body;
    const senderId = req.userId;

    if (!receiverId || !ciphertext || !iv || !authTag || !sequenceNumber || !nonce) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Replay Attack Detection
    const messageTimestamp = timestamp ? new Date(timestamp) : new Date();
    const now = new Date();
    const maxMessageAge = 5 * 60 * 1000; // 5 minutes in milliseconds
    const messageAge = now - messageTimestamp;

    // Check 1: Duplicate nonce detection
    const existingNonce = await Message.findOne({
      senderId,
      receiverId,
      nonce
    });

    if (existingNonce) {
      await logSecurityEvent('REPLAY_DETECTED', senderId, {
        reason: 'Duplicate nonce detected',
        nonce,
        existingMessageId: existingNonce._id.toString(),
        receiverId
      }, req.ip);
      return res.status(409).json({ error: 'Replay attack detected: duplicate nonce' });
    }

    // Check 2: Duplicate sequence number detection (for same sender-receiver pair)
    const existingSequence = await Message.findOne({
      senderId,
      receiverId,
      sequenceNumber
    });

    if (existingSequence) {
      await logSecurityEvent('REPLAY_DETECTED', senderId, {
        reason: 'Duplicate sequence number detected',
        sequenceNumber,
        existingMessageId: existingSequence._id.toString(),
        receiverId
      }, req.ip);
      return res.status(409).json({ error: 'Replay attack detected: duplicate sequence number' });
    }

    // Check 3: Old timestamp detection (message too old)
    if (messageAge > maxMessageAge) {
      await logSecurityEvent('REPLAY_DETECTED', senderId, {
        reason: 'Message timestamp too old',
        messageTimestamp: messageTimestamp.toISOString(),
        age: messageAge,
        maxAge: maxMessageAge,
        receiverId
      }, req.ip);
      return res.status(409).json({ error: 'Replay attack detected: message timestamp too old' });
    }

    // Check 4: Future timestamp detection (clock skew protection)
    const clockSkew = 60 * 1000; // 1 minute tolerance
    if (messageTimestamp > new Date(now.getTime() + clockSkew)) {
      await logSecurityEvent('REPLAY_DETECTED', senderId, {
        reason: 'Message timestamp in future',
        messageTimestamp: messageTimestamp.toISOString(),
        serverTime: now.toISOString(),
        receiverId
      }, req.ip);
      return res.status(409).json({ error: 'Replay attack detected: message timestamp in future' });
    }

    // Create message
    const message = new Message({
      senderId,
      receiverId,
      ciphertext,
      iv,
      authTag,
      sequenceNumber,
      nonce,
      timestamp: messageTimestamp
    });

    await message.save();

    res.status(201).json({
      message: 'Message sent successfully',
      messageId: message._id.toString(),
      timestamp: message.timestamp
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /api/messages/receive
 * Get encrypted messages for the authenticated user
 */
router.get('/receive', requireAuth, async (req, res) => {
  try {
    const userId = req.userId;
    const { limit = 50, before, peerId } = req.query;
    let query;

    if (peerId) {
      query = {
        $or: [
          { senderId: userId, receiverId: peerId },
          { senderId: peerId, receiverId: userId }
        ]
      };
    } else {
      query = { receiverId: userId };
    }
    if (before) {
      query.timestamp = { $lt: new Date(before) };
    }

    const messages = await Message.find(query)
      .sort({ timestamp: 1 })
      .limit(parseInt(limit))
      .populate('senderId', 'username')
      .select('senderId receiverId ciphertext iv authTag sequenceNumber nonce timestamp');

    await logSecurityEvent('METADATA_ACCESS', userId, {
      action: 'fetch_messages',
      count: messages.length
    }, req.ip);

    res.json({
      messages: messages.map(msg => ({
        messageId: msg._id.toString(),
        senderId: msg.senderId._id.toString(),
        senderUsername: msg.senderId.username,
        receiverId: msg.receiverId.toString(),
        ciphertext: msg.ciphertext,
        iv: msg.iv,
        authTag: msg.authTag,
        sequenceNumber: msg.sequenceNumber,
        nonce: msg.nonce,
        timestamp: msg.timestamp
      }))
    });
  } catch (error) {
    console.error('Receive messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/messages/decrypt-failure
 * Log decryption failure (security event)
 */
router.post('/decrypt-failure', requireAuth, async (req, res) => {
  try {
    const { messageId, reason } = req.body;
    const userId = req.userId;

    await logSecurityEvent('DECRYPT_FAILURE', userId, {
      messageId,
      reason: reason || 'Unknown'
    }, req.ip);

    res.json({ message: 'Decryption failure logged' });
  } catch (error) {
    console.error('Log decrypt failure error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/messages/invalid-signature
 * Log invalid signature (security event)
 */
router.post('/invalid-signature', requireAuth, async (req, res) => {
  try {
    const { context, reason, signature, data } = req.body;
    const userId = req.userId;

    await logSecurityEvent('INVALID_SIGNATURE', userId, {
      context: context || 'Unknown',
      reason: reason || 'Unknown',
      signature: signature ? signature.substring(0, 50) + '...' : null, // Log partial signature for debugging
      data: data ? (typeof data === 'string' ? data.substring(0, 100) + '...' : 'Object') : null
    }, req.ip);

    res.json({ message: 'Invalid signature logged' });
  } catch (error) {
    console.error('Log invalid signature error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;


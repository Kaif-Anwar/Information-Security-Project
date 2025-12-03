/**
 * Messaging Service - Handles encrypted message sending/receiving
 */
import { encryptAESGCM, decryptAESGCM, generateIV, generateNonce, arrayBufferToBase64 } from '../utils/crypto.js';
import { messagesAPI, authAPI } from './api.js';
import { KeyExchangeManager } from './keyExchange.js';

export class MessagingService {
  constructor(keyExchangeManager, currentUserId) {
    this.keyExchangeManager = keyExchangeManager;
    this.currentUserId = currentUserId;
    this.sessionPromises = new Map();
  }

  /**
   * Send an encrypted message
   */
  async sendMessage(receiverId, plaintext) {
    try {
      console.log('sendMessage: Sending message to:', receiverId);
      
      // Get or establish session key
      let sessionKey = this.keyExchangeManager.getSessionKey(receiverId);
      console.log('sendMessage: Existing session key found:', !!sessionKey);
      
      if (!sessionKey) {
        console.log('sendMessage: No session key, calling ensureSession...');
        sessionKey = await this.ensureSession(receiverId);
        if (!sessionKey) {
          console.error('sendMessage: ✗ Failed to establish session key');
          throw new Error('Could not establish session key with receiver');
        }
        console.log('sendMessage: ✓ Session key established');
      }
      
      console.log('sendMessage: Using session key type:', sessionKey?.constructor?.name);

      // Generate fresh IV for this message
      const iv = generateIV();
      
      // Get next sequence number
      const sequenceNumber = this.keyExchangeManager.getNextSequenceNumber(receiverId);
      
      // Generate nonce for replay protection
      const nonce = arrayBufferToBase64(generateNonce());
      
      // Encrypt message
      const { ciphertext, iv: ivBase64, authTag } = await encryptAESGCM(plaintext, sessionKey, iv);
      
      // Send to server with timestamp for replay detection
      const timestamp = Date.now();
      const response = await messagesAPI.send(
        receiverId,
        ciphertext,
        ivBase64,
        authTag,
        sequenceNumber,
        nonce,
        timestamp
      );

      return {
        success: true,
        messageId: response.messageId,
        timestamp: response.timestamp
      };
    } catch (error) {
      console.error('Error sending message:', error);
      throw error;
    }
  }

  /**
   * Receive and decrypt messages
   */
  async receiveMessages(peerId, limit = 50) {
    if (!peerId) return [];

    try {
      const response = await messagesAPI.receive(peerId, limit);
      
      const decryptedMessages = [];
      
      for (const msg of response.messages) {
        try {
          // Skip decryption for messages we sent - they should already be in plaintext
          // or we can reconstruct them from our send history
          if (msg.senderId === this.currentUserId) {
            // For messages we sent, try to get plaintext from the message if available
            // Otherwise, we'd need to decrypt with the session key we used to send
            const counterpartId = msg.receiverId;
            let sessionKey = this.keyExchangeManager.getSessionKey(counterpartId);
            
            if (!sessionKey || !msg.ciphertext) {
              // If we don't have the session key or ciphertext, skip this message
              // In a real app, you'd store sent messages separately
              console.warn('Cannot decrypt own sent message - session key or ciphertext missing');
              continue;
            }

            // Decrypt our own message to get the plaintext back
            try {
              const plaintext = await decryptAESGCM(
                msg.ciphertext,
                msg.iv,
                msg.authTag,
                sessionKey
              );
              
              decryptedMessages.push({
                messageId: msg.messageId,
                senderId: msg.senderId,
                senderUsername: msg.senderUsername,
                plaintext,
                timestamp: msg.timestamp,
                sequenceNumber: msg.sequenceNumber
              });
            } catch (decryptError) {
              console.error('Error decrypting own sent message:', decryptError);
              // Skip this message
              continue;
            }
            continue;
          }

          // For messages from others, decrypt normally
          const counterpartId = msg.senderId;

          // Get session key - try counterpartId first, then try the other ID
          let sessionKey = this.keyExchangeManager.getSessionKey(counterpartId);
          if (!sessionKey) {
            // Try the other ID in case session was stored with different key
            sessionKey = this.keyExchangeManager.getSessionKey(msg.receiverId);
            if (sessionKey) {
              console.log('Found session key with alternative ID:', msg.receiverId);
            }
          }
          
          if (!sessionKey) {
            console.warn('Session key not found, attempting to establish session for:', counterpartId);
            console.log('Calling ensureSession to derive session key...');
            sessionKey = await this.ensureSession(counterpartId);
            if (!sessionKey) {
              console.error('Failed to derive session key for peer:', counterpartId, 'Message ID:', msg.messageId);
              console.error('This means the other party encrypted with a different key or key derivation failed');
              continue;
            }
            console.log('✓ Session key derived successfully for:', counterpartId);
          } else {
            console.log('✓ Using existing session key for:', counterpartId);
          }

          // Validate encryption data before decryption
          if (!msg.ciphertext || !msg.iv || !msg.authTag) {
            console.error('Missing encryption data for message:', msg.messageId);
            continue;
          }

          // Decrypt message
          try {
            const plaintext = await decryptAESGCM(
              msg.ciphertext,
              msg.iv,
              msg.authTag,
              sessionKey
            );

            decryptedMessages.push({
              messageId: msg.messageId,
              senderId: msg.senderId,
              senderUsername: msg.senderUsername,
              plaintext,
              timestamp: msg.timestamp,
              sequenceNumber: msg.sequenceNumber
            });
          } catch (decryptError) {
            // Log error without exposing plaintext
            console.error('Decryption failed for message:', msg.messageId);
            await messagesAPI.logDecryptFailure(msg.messageId, decryptError.message);
          }
        } catch (error) {
          console.error('Error processing message:', error);
        }
      }

      return decryptedMessages;
    } catch (error) {
      console.error('Error receiving messages:', error);
      throw error;
    }
  }

  async ensureSession(peerId) {
    if (!peerId) return null;

    const existing = this.keyExchangeManager.getSessionKey(peerId);
    if (existing) return existing;

    if (this.sessionPromises.has(peerId)) {
      return this.sessionPromises.get(peerId);
    }

    const promise = (async () => {
      try {
        console.log('ensureSession: Fetching peer data for:', peerId);
        const peerData = await authAPI.getUser(peerId);
        if (!peerData?.publicKey) {
          throw new Error('Peer public key not available');
        }
        const peerKeys = JSON.parse(peerData.publicKey);
        if (!peerKeys.encryption) {
          throw new Error('Peer encryption key missing');
        }
        
        console.log('ensureSession: Deriving session key directly...');
        // Derive session key directly (same method as initiateKeyExchange)
        // This ensures both parties derive the same key
        const sessionKey = await this.keyExchangeManager.deriveSessionKey(peerId, peerKeys.encryption);
        console.log('ensureSession: ✓ Session key derived successfully');
        return sessionKey;
      } catch (error) {
        console.error('ensureSession: Failed to derive session key directly:', error);
        console.error('ensureSession: Error details:', {
          message: error.message,
          stack: error.stack
        });
        // Fallback to full key exchange if direct derivation fails
        try {
          console.log('ensureSession: Attempting fallback to full key exchange...');
          const peerData = await authAPI.getUser(peerId);
          const peerKeys = JSON.parse(peerData.publicKey);
          const result = await this.keyExchangeManager.initiateKeyExchange(peerId, peerKeys.encryption);
          const fallbackKey = result.sessionKey || this.keyExchangeManager.getSessionKey(peerId);
          if (fallbackKey) {
            console.log('ensureSession: ✓ Fallback key exchange succeeded');
          } else {
            console.error('ensureSession: ✗ Fallback key exchange returned no key');
          }
          return fallbackKey;
        } catch (fallbackError) {
          console.error('ensureSession: ✗ Fallback key exchange also failed:', fallbackError);
          return null;
        }
      } finally {
        this.sessionPromises.delete(peerId);
      }
    })();

    this.sessionPromises.set(peerId, promise);
    return promise;
  }
}


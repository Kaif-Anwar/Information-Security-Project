/**
 * Key Exchange Protocol Implementation
 * Custom ECDH-based key exchange with digital signatures
 */
import {
  generateECCKeyPair,
  generateECDSAKeyPair,
  performECDH,
  deriveKeyHKDF,
  signData,
  verifySignature,
  exportPublicKey,
  importECCPublicKey,
  importECDSAPublicKey,
  generateNonce,
  hashSHA256,
  arrayBufferToBase64
} from '../utils/crypto.js';
import { keyExchangeAPI } from './api.js';

/**
 * Key Exchange Manager
 */
export class KeyExchangeManager {
  constructor(userId, signingKeyPair, encryptionKeyPair) {
    this.userId = userId;
    this.signingKeyPair = signingKeyPair; // ECDSA for signatures
    this.encryptionKeyPair = encryptionKeyPair; // ECDH for key exchange
    this.activeSessions = new Map(); // Store session keys
    this.sequenceNumbers = new Map(); // Track sequence numbers per session
  }

  /**
   * Step 1: Initiate key exchange
   */
  async initiateKeyExchange(receiverId, receiverPublicKey) {
    try {
      // Generate ephemeral key pair for this session
      const ephemeralKeyPair = await generateECCKeyPair('P-256');
      const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey);

      // Create message to sign
      const timestamp = Date.now();
      const nonce = arrayBufferToBase64(generateNonce());
      const message = `${this.userId}:${receiverId}:${ephemeralPublicKey}:${timestamp}:${nonce}`;

      // Sign the message
      const signature = await signData(message, this.signingKeyPair.privateKey);

      // Export public key - handle case where public key might not be imported yet
      let encryptionPublicKeyBase64;
      if (this.encryptionKeyPair.publicKey) {
        encryptionPublicKeyBase64 = await exportPublicKey(this.encryptionKeyPair.publicKey);
      } else if (this.encryptionKeyPair.publicKeyBase64) {
        // Use stored base64 if public key wasn't imported
        encryptionPublicKeyBase64 = this.encryptionKeyPair.publicKeyBase64;
      } else {
        throw new Error('Encryption public key not available');
      }

      // Send initiation request
      const response = await keyExchangeAPI.initiate(
        receiverId,
        encryptionPublicKeyBase64,
        ephemeralPublicKey,
        signature,
        timestamp,
        nonce
      );

      // Import receiver's public key - handle errors gracefully
      let receiverPublicKeyCrypto;
      try {
        console.log('Importing receiver public key...');
        console.log('Receiver public key type:', typeof receiverPublicKey);
        console.log('Receiver public key value:', typeof receiverPublicKey === 'string' ? receiverPublicKey.substring(0, 100) + '...' : JSON.stringify(receiverPublicKey).substring(0, 200));
        
        // Check if receiverPublicKey is already a base64 string or needs parsing
        let receiverPublicKeyBase64 = receiverPublicKey;
        if (typeof receiverPublicKey === 'object' && receiverPublicKey.encryption) {
          receiverPublicKeyBase64 = receiverPublicKey.encryption;
          console.log('Extracted encryption key from object, length:', receiverPublicKeyBase64.length);
        }
        
        if (!receiverPublicKeyBase64 || typeof receiverPublicKeyBase64 !== 'string') {
          throw new Error('Receiver public key is not a valid string');
        }
        
        // Validate base64 format
        const isValidBase64 = (str) => {
          try {
            const decoded = atob(str);
            const reencoded = btoa(decoded);
            return reencoded === str && str.length > 50;
          } catch (e) {
            return false;
          }
        };
        
        if (!isValidBase64(receiverPublicKeyBase64)) {
          console.error('Base64 validation failed for receiver public key');
          console.error('Key length:', receiverPublicKeyBase64.length);
          console.error('Key preview:', receiverPublicKeyBase64.substring(0, 150));
          throw new Error('Receiver public key is not valid base64 format');
        }
        
        console.log('Base64 validation passed, attempting to import...');
        receiverPublicKeyCrypto = await importECCPublicKey(receiverPublicKeyBase64, 'P-256');
        console.log('✓ Receiver public key imported successfully');
      } catch (e) {
        console.error('✗ Failed to import receiver public key:', e);
        console.error('Error details:', {
          name: e.name,
          message: e.message,
          receiverKeyType: typeof receiverPublicKey,
          receiverKeyLength: typeof receiverPublicKey === 'string' ? receiverPublicKey.length : 'N/A'
        });
        throw new Error('Failed to import receiver public key. The key may be corrupted or in wrong format. Error: ' + e.message);
      }
      
      // Derive session key immediately (simplified flow)
      console.log('Deriving session key using ECDH...');
      const sharedSecret = await performECDH(this.encryptionKeyPair.privateKey, receiverPublicKeyCrypto);
      const idSalt = [this.userId, receiverId].sort().join(':');
      const salt = new TextEncoder().encode(idSalt);
      const info = new TextEncoder().encode('e2ee-session-key');
      const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info, 256);
      console.log('✓ Session key derived and stored');

      // Store session data
      this.activeSessions.set(receiverId, {
        ephemeralKeyPair,
        receiverPublicKey: receiverPublicKeyCrypto,
        receiverPublicKeyBase64: typeof receiverPublicKey === 'string' ? receiverPublicKey : (receiverPublicKey.encryption || null),
        step: 'completed',
        timestamp,
        nonce,
        sessionKey
      });
      this.sequenceNumbers.set(receiverId, 0);

      return {
        success: true,
        ephemeralPublicKey,
        signature,
        timestamp,
        nonce,
        sessionKey
      };
    } catch (error) {
      console.error('Key exchange initiation error:', error);
      throw error;
    }
  }

  /**
   * Step 2: Respond to key exchange
   */
  async respondToKeyExchange(senderId, senderPublicKey, senderEphemeralPublicKey, signature, timestamp, nonce) {
    try {
      // Verify signature with timestamp validation
      const senderSigningKey = await importECDSAPublicKey(senderPublicKey, 'P-256');
      const message = `${senderId}:${this.userId}:${senderEphemeralPublicKey}:${timestamp}:${nonce}`;
      const isValid = await verifySignature(message, signature, senderSigningKey, timestamp);

      if (!isValid) {
        throw new Error('Invalid signature or expired timestamp in key exchange');
      }

      // Generate our ephemeral key pair
      const ephemeralKeyPair = await generateECCKeyPair('P-256');
      const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey);

      // Create response message
      const responseTimestamp = Date.now();
      const responseNonce = arrayBufferToBase64(generateNonce());
      const responseMessage = `${this.userId}:${senderId}:${ephemeralPublicKey}:${responseTimestamp}:${responseNonce}`;

      // Sign response
      const responseSignature = await signData(responseMessage, this.signingKeyPair.privateKey);

      // Send response
      await keyExchangeAPI.respond(
        senderId,
        ephemeralPublicKey,
        responseSignature,
        responseTimestamp,
        responseNonce
      );

      // Perform ECDH to derive shared secret
      const senderEphemeralKey = await importECCPublicKey(senderEphemeralPublicKey, 'P-256');
      const sharedSecret = await performECDH(ephemeralKeyPair.privateKey, senderEphemeralKey);

      // Derive session key using HKDF
      const salt = new Uint8Array(32); // Can be derived from nonces
      const info = new TextEncoder().encode(`${this.userId}:${senderId}:session-key`);
      const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info, 256);

      // Store session
      this.activeSessions.set(senderId, {
        sessionKey,
        step: 'responded',
        timestamp: responseTimestamp,
        nonce: responseNonce
      });

      return {
        success: true,
        ephemeralPublicKey,
        signature: responseSignature,
        timestamp: responseTimestamp,
        nonce: responseNonce,
        sessionKey
      };
    } catch (error) {
      console.error('Key exchange response error:', error);
      throw error;
    }
  }

  /**
   * Step 3: Complete key exchange (after receiving response)
   */
  async completeKeyExchange(receiverId, receiverEphemeralPublicKey, signature, timestamp, nonce) {
    try {
      const session = this.activeSessions.get(receiverId);
      if (!session || session.step !== 'initiated') {
        throw new Error('Invalid key exchange state');
      }

      // Verify signature with timestamp validation
      const receiverSigningKey = await importECDSAPublicKey(session.receiverPublicKey, 'P-256');
      const message = `${receiverId}:${this.userId}:${receiverEphemeralPublicKey}:${timestamp}:${nonce}`;
      const isValid = await verifySignature(message, signature, receiverSigningKey, timestamp);

      if (!isValid) {
        throw new Error('Invalid signature or expired timestamp in key exchange response');
      }

      // Perform ECDH
      const receiverEphemeralKey = await importECCPublicKey(receiverEphemeralPublicKey, 'P-256');
      const sharedSecret = await performECDH(session.ephemeralKeyPair.privateKey, receiverEphemeralKey);

      // Derive session key
      const salt = new Uint8Array(32);
      const info = new TextEncoder().encode(`${this.userId}:${receiverId}:session-key`);
      const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info, 256);

      // Update session
      session.sessionKey = sessionKey;
      session.step = 'completed';

      // Send confirmation
      const confirmationHash = await hashSHA256(`${sessionKey}:${timestamp}`);
      const confirmationSignature = await signData(confirmationHash, this.signingKeyPair.privateKey);

      await keyExchangeAPI.confirm(
        receiverId,
        confirmationHash,
        confirmationSignature,
        Date.now()
      );

      return {
        success: true,
        sessionKey
      };
    } catch (error) {
      console.error('Key exchange completion error:', error);
      throw error;
    }
  }

  /**
   * Derive session key directly (without full key exchange)
   * This allows both parties to derive the same key independently
   */
  async deriveSessionKey(peerId, peerPublicKeyBase64) {
    try {
      console.log('deriveSessionKey: Starting derivation for peer:', peerId);
      console.log('deriveSessionKey: My userId:', this.userId);
      console.log('deriveSessionKey: Peer public key length:', peerPublicKeyBase64?.length);
      
      // Import peer's public key
      const peerPublicKey = await importECCPublicKey(peerPublicKeyBase64, 'P-256');
      console.log('deriveSessionKey: ✓ Peer public key imported');
      
      // Perform ECDH to get shared secret
      console.log('deriveSessionKey: Performing ECDH...');
      const sharedSecret = await performECDH(this.encryptionKeyPair.privateKey, peerPublicKey);
      console.log('deriveSessionKey: ✓ ECDH completed, shared secret obtained');
      
      // Derive session key using same method as initiateKeyExchange
      const idSalt = [this.userId, peerId].sort().join(':');
      console.log('deriveSessionKey: Using salt from sorted IDs:', idSalt);
      const salt = new TextEncoder().encode(idSalt);
      const info = new TextEncoder().encode('e2ee-session-key');
      console.log('deriveSessionKey: Deriving session key with HKDF...');
      const sessionKey = await deriveKeyHKDF(sharedSecret, salt, info, 256);
      console.log('deriveSessionKey: ✓ Session key derived successfully');
      
      // Store session if not already stored
      if (!this.activeSessions.has(peerId)) {
        console.log('deriveSessionKey: Storing new session for peer:', peerId);
        this.activeSessions.set(peerId, {
          sessionKey,
          step: 'completed',
          timestamp: Date.now()
        });
        this.sequenceNumbers.set(peerId, 0);
      } else {
        // Update existing session with key if missing
        const session = this.activeSessions.get(peerId);
        if (!session.sessionKey) {
          console.log('deriveSessionKey: Updating existing session with derived key');
          session.sessionKey = sessionKey;
        } else {
          console.log('deriveSessionKey: Session already has a key, keeping existing');
        }
      }
      
      return sessionKey;
    } catch (error) {
      console.error('deriveSessionKey: ✗ Error deriving session key:', error);
      console.error('deriveSessionKey: Error details:', {
        message: error.message,
        stack: error.stack,
        peerId,
        hasEncryptionKeyPair: !!this.encryptionKeyPair,
        hasPrivateKey: !!this.encryptionKeyPair?.privateKey
      });
      throw error;
    }
  }

  /**
   * Get session key for a user
   */
  getSessionKey(userId) {
    const session = this.activeSessions.get(userId);
    return session?.sessionKey || null;
  }

  /**
   * Get next sequence number for a session
   */
  getNextSequenceNumber(userId) {
    const current = this.sequenceNumbers.get(userId) || 0;
    const next = current + 1;
    this.sequenceNumbers.set(userId, next);
    return next;
  }
}


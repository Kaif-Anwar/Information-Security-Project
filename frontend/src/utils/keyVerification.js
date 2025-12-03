/**
 * Utility to verify keys are stored in IndexedDB
 * Can be called from browser console: window.verifyKeys()
 */

import { keyExists, getPrivateKey } from './storage.js';

export async function verifyKeys(userId, password) {
  console.log('🔍 Verifying keys for user:', userId);
  
  try {
    // Derive password key
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const salt = encoder.encode('e2ee-salt');
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const passwordKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );

    // Check user-specific keys
    const userEncryptionExists = await keyExists(`${userId}_encryption`).catch(() => false);
    const userSigningExists = await keyExists(`${userId}_signing`).catch(() => false);
    
    console.log('📦 User-specific keys:');
    console.log('   Encryption key exists:', userEncryptionExists);
    console.log('   Signing key exists:', userSigningExists);
    
    // Check old format keys
    const oldEncryptionExists = await keyExists('encryption').catch(() => false);
    const oldSigningExists = await keyExists('signing').catch(() => false);
    
    console.log('📦 Old format keys:');
    console.log('   Encryption key exists:', oldEncryptionExists);
    console.log('   Signing key exists:', oldSigningExists);
    
    // Try to retrieve and decrypt
    if (userEncryptionExists && userSigningExists) {
      try {
        const encryptionKey = await getPrivateKey(`${userId}_encryption`, passwordKey);
        const signingKey = await getPrivateKey(`${userId}_signing`, passwordKey);
        console.log('✅ Keys can be retrieved and decrypted:');
        console.log('   Encryption key length:', encryptionKey.length);
        console.log('   Signing key length:', signingKey.length);
        return { success: true, format: 'user-specific' };
      } catch (e) {
        console.error('❌ Keys exist but cannot be decrypted:', e.message);
        return { success: false, error: 'Decryption failed: ' + e.message };
      }
    } else if (oldEncryptionExists && oldSigningExists) {
      try {
        const encryptionKey = await getPrivateKey('encryption', passwordKey);
        const signingKey = await getPrivateKey('signing', passwordKey);
        console.log('✅ Old format keys can be retrieved and decrypted:');
        console.log('   Encryption key length:', encryptionKey.length);
        console.log('   Signing key length:', signingKey.length);
        return { success: true, format: 'old' };
      } catch (e) {
        console.error('❌ Old format keys exist but cannot be decrypted:', e.message);
        return { success: false, error: 'Decryption failed: ' + e.message };
      }
    } else {
      console.error('❌ No keys found in IndexedDB');
      return { success: false, error: 'Keys not found' };
    }
  } catch (error) {
    console.error('❌ Verification error:', error);
    return { success: false, error: error.message };
  }
}

// Make it available globally for console access
if (typeof window !== 'undefined') {
  window.verifyKeys = verifyKeys;
}


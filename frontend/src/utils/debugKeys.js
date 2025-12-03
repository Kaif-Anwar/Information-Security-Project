/**
 * Debug utility to check key storage
 * Run in browser console: window.debugKeys()
 */

import { keyExists, getPrivateKey } from './storage.js';

export async function debugKeys(userId, password) {
  console.log('\n🔍 DEBUGGING KEY STORAGE');
  console.log('='.repeat(50));
  console.log('User ID:', userId);
  console.log('Password provided:', password ? 'Yes' : 'No');
  
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

    console.log('✓ Password key derived successfully');

    // Check all possible key IDs
    const keyIds = [
      `${userId}_encryption`,
      `${userId}_signing`,
      'encryption',
      'signing'
    ];

    console.log('\n📦 Checking key existence:');
    for (const keyId of keyIds) {
      const exists = await keyExists(keyId).catch(() => false);
      console.log(`   ${keyId}: ${exists ? '✓ EXISTS' : '✗ NOT FOUND'}`);
    }

    // Try to retrieve keys
    console.log('\n🔓 Attempting to retrieve keys:');
    
    let encryptionKey = null;
    let signingKey = null;
    
    // Try user-specific format first
    try {
      encryptionKey = await getPrivateKey(`${userId}_encryption`, passwordKey);
      console.log(`✓ Retrieved ${userId}_encryption (length: ${encryptionKey.length})`);
    } catch (e) {
      console.log(`✗ Failed to retrieve ${userId}_encryption:`, e.message);
      try {
        encryptionKey = await getPrivateKey('encryption', passwordKey);
        console.log(`✓ Retrieved encryption (old format, length: ${encryptionKey.length})`);
      } catch (e2) {
        console.log(`✗ Failed to retrieve encryption (old format):`, e2.message);
      }
    }

    try {
      signingKey = await getPrivateKey(`${userId}_signing`, passwordKey);
      console.log(`✓ Retrieved ${userId}_signing (length: ${signingKey.length})`);
    } catch (e) {
      console.log(`✗ Failed to retrieve ${userId}_signing:`, e.message);
      try {
        signingKey = await getPrivateKey('signing', passwordKey);
        console.log(`✓ Retrieved signing (old format, length: ${signingKey.length})`);
      } catch (e2) {
        console.log(`✗ Failed to retrieve signing (old format):`, e2.message);
      }
    }

    // Check IndexedDB directly
    console.log('\n📊 IndexedDB Contents:');
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open('E2EEKeyStore', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });

    const tx = db.transaction('keys', 'readonly');
    const store = tx.objectStore('keys');
    const allKeys = await new Promise((resolve) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
    });

    console.log(`   Total keys in storage: ${allKeys.length}`);
    allKeys.forEach(key => {
      console.log(`   - ${key.id} (stored at: ${new Date(key.timestamp).toISOString()})`);
    });

    console.log('\n' + '='.repeat(50));
    
    return {
      encryptionKey: encryptionKey ? { length: encryptionKey.length, preview: encryptionKey.substring(0, 50) } : null,
      signingKey: signingKey ? { length: signingKey.length, preview: signingKey.substring(0, 50) } : null,
      allKeys: allKeys.map(k => k.id)
    };
  } catch (error) {
    console.error('\n❌ DEBUG ERROR:', error);
    return { error: error.message };
  }
}

// Make it available globally
if (typeof window !== 'undefined') {
  window.debugKeys = debugKeys;
}


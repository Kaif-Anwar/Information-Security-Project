/**
 * Test to verify both parties derive the same session key
 * This simulates User A and User B deriving session keys independently
 */

import { webcrypto } from 'crypto';
const crypto = webcrypto;

// Simulate ECDH key generation
async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey', 'deriveBits']
  );
}

// Simulate ECDH
async function performECDH(privateKey, publicKey) {
  return await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey
    },
    privateKey,
    256
  );
}

// Simulate HKDF
async function deriveKeyHKDF(baseKey, salt, info, length) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    baseKey,
    'HKDF',
    false,
    ['deriveKey']
  );
  
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: info
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: length
    },
    true,
    ['encrypt', 'decrypt']
  );
  
  return derivedKey;
}

async function testSessionKeyDerivation() {
  console.log('=== Testing Session Key Derivation ===\n');
  
  try {
    // Generate key pairs for User A and User B
    console.log('Generating key pairs...');
    const userAKeyPair = await generateKeyPair();
    const userBKeyPair = await generateKeyPair();
    console.log('✓ Key pairs generated\n');
    
    // User A derives session key: ECDH(A_private, B_public)
    console.log('--- User A deriving session key ---');
    const userASharedSecret = await performECDH(userAKeyPair.privateKey, userBKeyPair.publicKey);
    console.log('✓ User A: ECDH completed');
    
    const userAId = 'userA';
    const userBId = 'userB';
    const idSalt = [userAId, userBId].sort().join(':');
    const salt = new TextEncoder().encode(idSalt);
    const info = new TextEncoder().encode('e2ee-session-key');
    
    console.log('Salt (sorted IDs):', idSalt);
    
    const userASessionKey = await deriveKeyHKDF(userASharedSecret, salt, info, 256);
    console.log('✓ User A: Session key derived\n');
    
    // User B derives session key: ECDH(B_private, A_public)
    console.log('--- User B deriving session key ---');
    const userBSharedSecret = await performECDH(userBKeyPair.privateKey, userAKeyPair.publicKey);
    console.log('✓ User B: ECDH completed');
    
    // Use same salt (sorted IDs)
    const userBSessionKey = await deriveKeyHKDF(userBSharedSecret, salt, info, 256);
    console.log('✓ User B: Session key derived\n');
    
    // Export keys to compare
    const exportKey = async (key) => {
      const exported = await crypto.subtle.exportKey('raw', key);
      return new Uint8Array(exported);
    };
    
    const userAKeyBytes = await exportKey(userASessionKey);
    const userBKeyBytes = await exportKey(userBSessionKey);
    
    console.log('--- Comparing session keys ---');
    console.log('User A key length:', userAKeyBytes.length);
    console.log('User B key length:', userBKeyBytes.length);
    
    // Compare keys
    let keysMatch = true;
    if (userAKeyBytes.length !== userBKeyBytes.length) {
      keysMatch = false;
    } else {
      for (let i = 0; i < userAKeyBytes.length; i++) {
        if (userAKeyBytes[i] !== userBKeyBytes[i]) {
          keysMatch = false;
          console.log(`Mismatch at byte ${i}: A=${userAKeyBytes[i]}, B=${userBKeyBytes[i]}`);
          break;
        }
      }
    }
    
    if (keysMatch) {
      console.log('\n✅ SUCCESS: Both parties derived the SAME session key!');
    } else {
      console.log('\n❌ FAILED: Session keys do NOT match!');
      console.log('User A key (first 20 bytes):', Array.from(userAKeyBytes.slice(0, 20)));
      console.log('User B key (first 20 bytes):', Array.from(userBKeyBytes.slice(0, 20)));
    }
    
    // Test encryption/decryption with both keys
    console.log('\n--- Testing encryption/decryption with derived keys ---');
    const testMessage = 'Test message for encryption';
    const encoder = new TextEncoder();
    const data = encoder.encode(testMessage);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt with User A's key
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      userASessionKey,
      data
    );
    
    const authTag = encrypted.slice(-16);
    const ciphertext = encrypted.slice(0, -16);
    
    // Try to decrypt with User B's key
    const encryptedData = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    encryptedData.set(new Uint8Array(ciphertext), 0);
    encryptedData.set(new Uint8Array(authTag), ciphertext.byteLength);
    
    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        userBSessionKey,
        encryptedData
      );
      
      const decoder = new TextDecoder();
      const decryptedText = decoder.decode(decrypted);
      
      if (decryptedText === testMessage) {
        console.log('✅ SUCCESS: User B can decrypt message encrypted by User A!');
      } else {
        console.log('❌ FAILED: Decrypted text does not match!');
      }
    } catch (error) {
      console.log('❌ FAILED: Decryption error:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    console.error('Stack:', error.stack);
  }
}

testSessionKeyDerivation().catch(console.error);


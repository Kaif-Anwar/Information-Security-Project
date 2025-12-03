/**
 * Test script to verify encryption/decryption and session key derivation
 * Run with: node test-crypto.mjs
 */

import { webcrypto } from 'crypto';

// Simulate the crypto functions
const crypto = webcrypto;

async function testEncryptionDecryption() {
  console.log('=== Testing Encryption/Decryption ===\n');
  
  try {
    // Generate a test key
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
    
    console.log('✓ Test key generated');
    
    // Test plaintext
    const plaintext = 'Hello, this is a test message!';
    console.log('Plaintext:', plaintext);
    
    // Encrypt
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      data
    );
    
    // Extract auth tag (last 16 bytes in GCM)
    const authTag = encrypted.slice(-16);
    const ciphertext = encrypted.slice(0, -16);
    
    console.log('✓ Encryption successful');
    console.log('Ciphertext length:', ciphertext.byteLength);
    console.log('IV length:', iv.byteLength);
    console.log('Auth tag length:', authTag.byteLength);
    
    // Convert to base64 for testing
    const arrayBufferToBase64 = (buffer) => {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    };
    
    const base64ToArrayBuffer = (base64) => {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    };
    
    const ciphertextBase64 = arrayBufferToBase64(ciphertext);
    const ivBase64 = arrayBufferToBase64(iv);
    const authTagBase64 = arrayBufferToBase64(authTag);
    
    console.log('\n--- Testing Decryption ---');
    
    // Decrypt
    const ciphertext2 = base64ToArrayBuffer(ciphertextBase64);
    const iv2 = base64ToArrayBuffer(ivBase64);
    const authTag2 = base64ToArrayBuffer(authTagBase64);
    
    // Combine ciphertext and auth tag for GCM
    const encryptedData = new Uint8Array(ciphertext2.byteLength + authTag2.byteLength);
    encryptedData.set(new Uint8Array(ciphertext2), 0);
    encryptedData.set(new Uint8Array(authTag2), ciphertext2.byteLength);
    
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv2
      },
      key,
      encryptedData
    );
    
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decrypted);
    
    console.log('✓ Decryption successful');
    console.log('Decrypted text:', decryptedText);
    
    if (plaintext === decryptedText) {
      console.log('\n✅ SUCCESS: Encryption/Decryption works correctly!');
    } else {
      console.log('\n❌ FAILED: Decrypted text does not match!');
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    console.error('Stack:', error.stack);
  }
}

// Run the test
testEncryptionDecryption().catch(console.error);


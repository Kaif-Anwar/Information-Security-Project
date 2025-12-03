/**
 * Test script for file encryption/decryption
 * Tests the full flow: file -> chunks -> encrypt -> decrypt -> file
 */

import { webcrypto } from 'crypto';
const crypto = webcrypto;

// Simulate the crypto functions
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('base64ToArrayBuffer: Input must be a non-empty string');
  }
  
  const cleaned = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  
  if (cleaned.length !== base64.length) {
    console.warn(`Removed ${base64.length - cleaned.length} invalid characters`);
  }
  
  try {
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    const remainder = cleaned.length % 4;
    if (remainder !== 0) {
      throw new Error(`Invalid base64 length (${cleaned.length} chars, remainder ${remainder}). Base64 must be multiples of 4. Error: ${error.message}`);
    }
    throw new Error(`Failed to decode base64: ${error.message}. Length: ${cleaned.length}`);
  }
}

async function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

async function generateKey() {
  return await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
}

async function encryptAESGCM(plaintext, key, iv) {
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
  
  const authTag = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);
  
  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    authTag: arrayBufferToBase64(authTag)
  };
}

async function decryptAESGCM(ciphertextBase64, ivBase64, authTagBase64, key) {
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const iv = base64ToArrayBuffer(ivBase64);
  const authTag = base64ToArrayBuffer(authTagBase64);
  
  const encryptedData = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
  encryptedData.set(new Uint8Array(ciphertext), 0);
  encryptedData.set(new Uint8Array(authTag), ciphertext.byteLength);
  
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encryptedData
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

async function testFileEncryption() {
  console.log('=== Testing File Encryption/Decryption ===\n');
  
  try {
    // Generate a test key
    console.log('1. Generating encryption key...');
    const sessionKey = await generateKey();
    console.log('✓ Key generated\n');
    
    // Create a test file (simulate a small file)
    console.log('2. Creating test file data...');
    const testFileSize = 1024 * 100; // 100KB test file
    const testFileData = new Uint8Array(testFileSize);
    for (let i = 0; i < testFileSize; i++) {
      testFileData[i] = Math.floor(Math.random() * 256);
    }
    console.log(`✓ Test file created: ${testFileSize} bytes\n`);
    
    // Convert file to base64 (as done in upload)
    console.log('3. Converting file to base64...');
    const fileBase64 = arrayBufferToBase64(testFileData.buffer);
    console.log(`✓ File converted to base64: ${fileBase64.length} characters`);
    console.log(`  First 50 chars: ${fileBase64.substring(0, 50)}`);
    console.log(`  Last 50 chars: ${fileBase64.substring(fileBase64.length - 50)}\n`);
    
    // Test chunking (simulate 1MB chunks)
    console.log('4. Testing chunking...');
    const CHUNK_SIZE = 1024 * 1024; // 1MB
    const totalChunks = Math.ceil(fileBase64.length / CHUNK_SIZE);
    console.log(`  Total chunks needed: ${totalChunks}`);
    
    const chunks = [];
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileBase64.length);
      const chunkBase64 = fileBase64.substring(start, end);
      chunks.push({
        data: chunkBase64,
        index: i,
        length: chunkBase64.length
      });
    }
    console.log(`✓ File split into ${chunks.length} chunks\n`);
    
    // Encrypt each chunk
    console.log('5. Encrypting chunks...');
    const encryptedChunks = [];
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const iv = await generateIV();
      const encrypted = await encryptAESGCM(chunk.data, sessionKey, iv);
      
      encryptedChunks.push({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        chunkIndex: chunk.index
      });
      
      console.log(`  ✓ Chunk ${i + 1}/${chunks.length} encrypted (ciphertext: ${encrypted.ciphertext.length} chars)`);
    }
    console.log(`✓ All ${encryptedChunks.length} chunks encrypted\n`);
    
    // Decrypt chunks
    console.log('6. Decrypting chunks...');
    const decryptedChunks = [];
    for (let i = 0; i < encryptedChunks.length; i++) {
      const encChunk = encryptedChunks[i];
      const decrypted = await decryptAESGCM(
        encChunk.ciphertext,
        encChunk.iv,
        encChunk.authTag,
        sessionKey
      );
      
      // Validate decrypted chunk is valid base64
      try {
        atob(decrypted);
        console.log(`  ✓ Chunk ${i + 1} decrypted and validated (length: ${decrypted.length} chars)`);
      } catch (e) {
        console.error(`  ✗ Chunk ${i + 1} decrypted but invalid base64:`, e.message);
        throw new Error(`Chunk ${i + 1} is not valid base64 after decryption`);
      }
      
      decryptedChunks.push({
        data: decrypted,
        index: encChunk.chunkIndex
      });
    }
    console.log(`✓ All ${decryptedChunks.length} chunks decrypted\n`);
    
    // Sort and combine chunks
    console.log('7. Combining decrypted chunks...');
    decryptedChunks.sort((a, b) => a.index - b.index);
    const combinedBase64 = decryptedChunks.map(c => c.data).join('');
    console.log(`✓ Combined base64 length: ${combinedBase64.length} characters`);
    console.log(`  First 50 chars: ${combinedBase64.substring(0, 50)}`);
    console.log(`  Last 50 chars: ${combinedBase64.substring(combinedBase64.length - 50)}`);
    
    // Validate combined base64
    console.log('\n8. Validating combined base64...');
    try {
      atob(combinedBase64.substring(0, Math.min(1000, combinedBase64.length)));
      console.log('✓ Combined base64 sample validation passed');
    } catch (e) {
      throw new Error(`Combined base64 validation failed: ${e.message}`);
    }
    
    // Check length
    const remainder = combinedBase64.length % 4;
    if (remainder !== 0) {
      throw new Error(`Combined base64 length is not multiple of 4 (length: ${combinedBase64.length}, remainder: ${remainder})`);
    }
    console.log(`✓ Combined base64 length is valid (multiple of 4)\n`);
    
    // Convert back to ArrayBuffer
    console.log('9. Converting combined base64 back to ArrayBuffer...');
    try {
      const reconstructedBuffer = base64ToArrayBuffer(combinedBase64);
      console.log(`✓ ArrayBuffer created: ${reconstructedBuffer.byteLength} bytes\n`);
      
      // Verify data matches
      console.log('10. Verifying data integrity...');
      const reconstructedArray = new Uint8Array(reconstructedBuffer);
      let matches = true;
      let firstMismatch = -1;
      
      if (reconstructedArray.length !== testFileData.length) {
        console.error(`✗ Length mismatch: original ${testFileData.length}, reconstructed ${reconstructedArray.length}`);
        matches = false;
      } else {
        for (let i = 0; i < testFileData.length; i++) {
          if (testFileData[i] !== reconstructedArray[i]) {
            matches = false;
            firstMismatch = i;
            break;
          }
        }
      }
      
      if (matches) {
        console.log('✅ SUCCESS: File encryption/decryption test passed!');
        console.log(`   Original file: ${testFileData.length} bytes`);
        console.log(`   Reconstructed file: ${reconstructedArray.length} bytes`);
        console.log(`   Data integrity: ✓ Perfect match`);
      } else {
        console.error('❌ FAILED: Data mismatch!');
        if (firstMismatch >= 0) {
          console.error(`   First mismatch at byte ${firstMismatch}`);
          console.error(`   Original: ${testFileData[firstMismatch]}, Reconstructed: ${reconstructedArray[firstMismatch]}`);
        }
      }
      
    } catch (error) {
      console.error('❌ FAILED: Error converting base64 to ArrayBuffer:', error.message);
      console.error('   Combined base64 length:', combinedBase64.length);
      console.error('   Combined base64 remainder:', combinedBase64.length % 4);
      console.error('   First 200 chars:', combinedBase64.substring(0, 200));
      console.error('   Last 200 chars:', combinedBase64.substring(Math.max(0, combinedBase64.length - 200)));
      
      // Check for invalid characters
      const invalidChars = combinedBase64.match(/[^A-Za-z0-9+/=]/g);
      if (invalidChars) {
        console.error(`   Found ${invalidChars.length} invalid characters`);
        console.error('   First 20 invalid chars:', invalidChars.slice(0, 20).map(c => `'${c}' (${c.charCodeAt(0)})`));
      }
    }
    
  } catch (error) {
    console.error('\n❌ TEST FAILED:', error);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

// Run the test
testFileEncryption().catch(console.error);


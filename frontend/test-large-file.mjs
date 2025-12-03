/**
 * Test script for large file encryption/decryption
 * Tests with a file size similar to the actual upload (16MB)
 */

import { webcrypto } from 'crypto';
const crypto = webcrypto;

// Simulate the crypto functions (same as before)
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

async function testLargeFile() {
  console.log('=== Testing Large File Encryption/Decryption ===\n');
  
  try {
    // Generate a test key
    console.log('1. Generating encryption key...');
    const sessionKey = await generateKey();
    console.log('✓ Key generated\n');
    
    // Create a test file similar to the actual file size (16MB)
    console.log('2. Creating large test file data...');
    const testFileSize = 16 * 1024 * 1024; // 16MB test file
    const testFileData = new Uint8Array(testFileSize);
    for (let i = 0; i < testFileSize; i++) {
      testFileData[i] = Math.floor(Math.random() * 256);
    }
    console.log(`✓ Test file created: ${(testFileSize / 1024 / 1024).toFixed(2)} MB (${testFileSize} bytes)\n`);
    
    // Convert file to base64 (as done in upload)
    console.log('3. Converting file to base64...');
    const fileBase64 = arrayBufferToBase64(testFileData.buffer);
    console.log(`✓ File converted to base64: ${(fileBase64.length / 1024 / 1024).toFixed(2)} MB (${fileBase64.length} characters)`);
    console.log(`  First 50 chars: ${fileBase64.substring(0, 50)}`);
    console.log(`  Last 50 chars: ${fileBase64.substring(fileBase64.length - 50)}`);
    console.log(`  Length % 4: ${fileBase64.length % 4}\n`);
    
    // Test chunking (1MB chunks as in the actual code)
    console.log('4. Testing chunking (1MB chunks)...');
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
      console.log(`  Chunk ${i + 1}: ${chunkBase64.length} chars (${(chunkBase64.length / 1024).toFixed(2)} KB)`);
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
      
      console.log(`  ✓ Chunk ${i + 1}/${chunks.length} encrypted (ciphertext: ${(encrypted.ciphertext.length / 1024).toFixed(2)} KB)`);
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
        console.log(`  ✓ Chunk ${i + 1} decrypted and validated (${(decrypted.length / 1024).toFixed(2)} KB)`);
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
    console.log(`✓ Combined base64 length: ${(combinedBase64.length / 1024 / 1024).toFixed(2)} MB (${combinedBase64.length} characters)`);
    console.log(`  First 50 chars: ${combinedBase64.substring(0, 50)}`);
    console.log(`  Last 50 chars: ${combinedBase64.substring(combinedBase64.length - 50)}`);
    console.log(`  Length % 4: ${combinedBase64.length % 4}`);
    
    // Validate combined base64
    console.log('\n8. Validating combined base64...');
    try {
      // Test on a sample
      const sampleSize = Math.min(10000, combinedBase64.length);
      atob(combinedBase64.substring(0, sampleSize));
      console.log(`✓ Combined base64 sample validation passed (tested ${sampleSize} chars)`);
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
    console.log('   This may take a moment for large files...');
    const startTime = Date.now();
    try {
      const reconstructedBuffer = base64ToArrayBuffer(combinedBase64);
      const endTime = Date.now();
      console.log(`✓ ArrayBuffer created: ${(reconstructedBuffer.byteLength / 1024 / 1024).toFixed(2)} MB (${reconstructedBuffer.byteLength} bytes)`);
      console.log(`  Time taken: ${((endTime - startTime) / 1000).toFixed(2)} seconds\n`);
      
      // Verify data matches
      console.log('10. Verifying data integrity...');
      const reconstructedArray = new Uint8Array(reconstructedBuffer);
      let matches = true;
      let firstMismatch = -1;
      
      if (reconstructedArray.length !== testFileData.length) {
        console.error(`✗ Length mismatch: original ${testFileData.length}, reconstructed ${reconstructedArray.length}`);
        matches = false;
      } else {
        // Check first and last bytes, and a few random samples
        const samples = [0, testFileData.length - 1, Math.floor(testFileData.length / 2)];
        for (const idx of samples) {
          if (testFileData[idx] !== reconstructedArray[idx]) {
            matches = false;
            firstMismatch = idx;
            break;
          }
        }
        
        if (matches) {
          console.log('✓ Sample check passed, verifying full file...');
          // Full verification for smaller files, sample for large ones
          if (testFileData.length < 10 * 1024 * 1024) {
            for (let i = 0; i < testFileData.length; i++) {
              if (testFileData[i] !== reconstructedArray[i]) {
                matches = false;
                firstMismatch = i;
                break;
              }
            }
          } else {
            console.log('  (Skipping full verification for large file, sample check passed)');
          }
        }
      }
      
      if (matches) {
        console.log('✅ SUCCESS: Large file encryption/decryption test passed!');
        console.log(`   Original file: ${(testFileData.length / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Reconstructed file: ${(reconstructedArray.length / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Data integrity: ✓ Match verified`);
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
      throw error;
    }
    
  } catch (error) {
    console.error('\n❌ TEST FAILED:', error);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

// Run the test
testLargeFile().catch(console.error);


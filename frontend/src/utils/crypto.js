/**
 * Core Cryptographic Utilities using Web Crypto API
 * Implements AES-256-GCM, RSA/ECC key generation, and key derivation
 */

/**
 * Generate RSA key pair (2048 or 3072 bits)
 */
export async function generateRSAKeyPair(keySize = 2048) {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: keySize,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );
    return keyPair;
  } catch (error) {
    console.error('Error generating RSA key pair:', error);
    throw error;
  }
}

/**
 * Generate ECC key pair (P-256 or P-384)
 */
export async function generateECCKeyPair(namedCurve = 'P-256') {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: namedCurve
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    return keyPair;
  } catch (error) {
    console.error('Error generating ECC key pair:', error);
    throw error;
  }
}

/**
 * Generate ECDSA key pair for digital signatures
 */
export async function generateECDSAKeyPair(namedCurve = 'P-256') {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: namedCurve
      },
      true,
      ['sign', 'verify']
    );
    return keyPair;
  } catch (error) {
    console.error('Error generating ECDSA key pair:', error);
    throw error;
  }
}

/**
 * Export public key to base64 string
 */
export async function exportPublicKey(key) {
  try {
    const exported = await crypto.subtle.exportKey('spki', key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('Error exporting public key:', error);
    throw error;
  }
}

/**
 * Export private key to base64 string (for secure local storage)
 */
export async function exportPrivateKey(key) {
  try {
    const exported = await crypto.subtle.exportKey('pkcs8', key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('Error exporting private key:', error);
    throw error;
  }
}

/**
 * Import public key from base64 string
 */
export async function importRSAPublicKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['encrypt']
    );
  } catch (error) {
    console.error('Error importing RSA public key:', error);
    throw error;
  }
}

/**
 * Import ECC public key from base64 string
 */
export async function importECCPublicKey(base64Key, namedCurve = 'P-256') {
  try {
    // Validate input
    if (!base64Key || typeof base64Key !== 'string') {
      throw new Error('Invalid base64 key: must be a non-empty string');
    }
    
    // Validate base64 format
    try {
      atob(base64Key);
    } catch (e) {
      throw new Error('Invalid base64 format: ' + e.message);
    }
    
    const keyData = base64ToArrayBuffer(base64Key);
    
    // Validate key data length (should be reasonable for a P-256 public key)
    if (keyData.byteLength < 50 || keyData.byteLength > 1000) {
      console.warn('Key data length seems unusual:', keyData.byteLength);
    }
    
    console.log('Importing ECC public key:', {
      base64Length: base64Key.length,
      keyDataLength: keyData.byteLength,
      namedCurve: namedCurve
    });
    
    // According to Web Crypto spec, ECDH public keys do not need key usages
    const importedKey = await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDH',
        namedCurve: namedCurve
      },
      true,
      [] // public key doesn't require derive usages
    );
    
    console.log('✓ ECC public key imported successfully');
    return importedKey;
  } catch (error) {
    console.error('Error importing ECC public key:', error);
    console.error('Key details:', {
      base64Length: base64Key?.length,
      base64Preview: base64Key?.substring(0, 100),
      errorName: error.name,
      errorMessage: error.message
    });
    throw error;
  }
}

/**
 * Import ECDSA public key from base64 string
 */
export async function importECDSAPublicKey(base64Key, namedCurve = 'P-256') {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: namedCurve
      },
      true,
      ['verify']
    );
  } catch (error) {
    console.error('Error importing ECDSA public key:', error);
    throw error;
  }
}

/**
 * Import private key from base64 string
 */
export async function importRSAPrivateKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['decrypt']
    );
  } catch (error) {
    console.error('Error importing RSA private key:', error);
    throw error;
  }
}

/**
 * Import ECC private key from base64 string
 */
export async function importECCPrivateKey(base64Key, namedCurve = 'P-256') {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDH',
        namedCurve: namedCurve
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  } catch (error) {
    console.error('Error importing ECC private key:', error);
    throw error;
  }
}

/**
 * Import ECDSA private key from base64 string
 */
export async function importECDAPrivateKey(base64Key, namedCurve = 'P-256') {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: namedCurve
      },
      true,
      ['sign']
    );
  } catch (error) {
    console.error('Error importing ECDSA private key:', error);
    throw error;
  }
}

/**
 * Encrypt message using AES-256-GCM
 */
export async function encryptAESGCM(plaintext, key, iv = null) {
  try {
    // Generate random IV if not provided
    if (!iv) {
      iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
    }

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

    return {
      ciphertext: arrayBufferToBase64(ciphertext),
      iv: arrayBufferToBase64(iv),
      authTag: arrayBufferToBase64(authTag)
    };
  } catch (error) {
    console.error('Error encrypting with AES-GCM:', error);
    throw error;
  }
}

/**
 * Decrypt message using AES-256-GCM
 */
export async function decryptAESGCM(ciphertextBase64, ivBase64, authTagBase64, key) {
  try {
    // Validate inputs
    if (!ciphertextBase64 || !ivBase64 || !authTagBase64) {
      throw new Error('Missing required encryption data');
    }
    
    if (!key) {
      throw new Error('Decryption key is null or undefined');
    }
    
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const iv = base64ToArrayBuffer(ivBase64);
    const authTag = base64ToArrayBuffer(authTagBase64);

    // Combine ciphertext and auth tag for GCM
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
    const result = decoder.decode(decrypted);
    return result;
  } catch (error) {
    // Log error without exposing plaintext
    console.error('Decryption failed:', error.name);
    throw error;
  }
}

/**
 * Derive key using HKDF (HMAC-based Key Derivation Function)
 */
export async function deriveKeyHKDF(baseKey, salt, info, length = 256) {
  try {
    // Import base key for HKDF
    const importedKey = await crypto.subtle.importKey(
      'raw',
      baseKey,
      'HKDF',
      false,
      ['deriveKey', 'deriveBits']
    );

    // Derive key using HKDF
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: info
      },
      importedKey,
      {
        name: 'AES-GCM',
        length: length
      },
      true,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } catch (error) {
    console.error('Error deriving key with HKDF:', error);
    throw error;
  }
}

/**
 * Perform ECDH key exchange
 */
export async function performECDH(privateKey, publicKey) {
  try {
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      256
    );
    return new Uint8Array(sharedSecret);
  } catch (error) {
    console.error('Error performing ECDH:', error);
    throw error;
  }
}

/**
 * Sign data using ECDSA
 */
export async function signData(data, privateKey) {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      dataBuffer
    );
    
    return arrayBufferToBase64(signature);
  } catch (error) {
    console.error('Error signing data:', error);
    throw error;
  }
}

/**
 * Validate timestamp for signature verification
 * @param {number} timestamp - Timestamp in milliseconds
 * @param {number} maxAge - Maximum age in milliseconds (default: 5 minutes)
 * @param {number} clockSkew - Allowed clock skew in milliseconds (default: 1 minute)
 * @returns {boolean} - True if timestamp is valid
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000, clockSkew = 60 * 1000) {
  const now = Date.now();
  const age = now - timestamp;
  
  // Check if timestamp is too old
  if (age > maxAge) {
    return false;
  }
  
  // Check if timestamp is too far in the future (accounting for clock skew)
  if (timestamp > now + clockSkew) {
    return false;
  }
  
  return true;
}

/**
 * Verify signature using ECDSA with timestamp validation
 * @param {string} data - The data that was signed
 * @param {string} signatureBase64 - The signature in base64
 * @param {CryptoKey} publicKey - The public key to verify with
 * @param {number} timestamp - The timestamp from the signed message (in milliseconds)
 * @param {number} maxAge - Maximum age of signature in milliseconds (default: 5 minutes)
 * @returns {Promise<boolean>} - True if signature and timestamp are valid
 */
export async function verifySignature(data, signatureBase64, publicKey, timestamp = null, maxAge = 5 * 60 * 1000) {
  try {
    // Validate timestamp if provided
    if (timestamp !== null && !validateTimestamp(timestamp, maxAge)) {
      console.error('Signature timestamp validation failed');
      return false;
    }
    
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const signature = base64ToArrayBuffer(signatureBase64);
    
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      dataBuffer
    );
    
    return isValid;
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
}

/**
 * Generate random nonce
 */
export function generateNonce(length = 16) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate random IV for AES-GCM
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
}

/**
 * Hash data using SHA-256
 */
export async function hashSHA256(data) {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    return arrayBufferToBase64(hashBuffer);
  } catch (error) {
    console.error('Error hashing data:', error);
    throw error;
  }
}

// Helper functions
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('base64ToArrayBuffer: Input must be a non-empty string');
  }
  
  // Remove any whitespace, newlines, or other non-base64 characters
  // Base64 can contain: A-Z, a-z, 0-9, +, /, and = for padding
  const cleaned = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  
  // For very large strings, skip regex validation and rely on atob error handling
  // The regex can be slow or fail on very large strings
  if (cleaned.length !== base64.length) {
    console.warn(`base64ToArrayBuffer: Removed ${base64.length - cleaned.length} invalid characters from base64 string`);
  }
  
  // Check for invalid padding - '=' should only appear at the end, max 2
  // Count all '=' characters
  const allEquals = cleaned.match(/=/g);
  if (allEquals && allEquals.length > 2) {
    // Check if '=' appears in the middle (not just at the end)
    const lastTwoChars = cleaned.slice(-2);
    const equalsAtEnd = (lastTwoChars.match(/=/g) || []).length;
    
    if (allEquals.length > equalsAtEnd) {
      // There are '=' characters in the middle, which is invalid
      // This might happen if base64 strings were incorrectly concatenated
      console.error(`base64ToArrayBuffer: Found ${allEquals.length} '=' characters, but only ${equalsAtEnd} at the end`);
      console.error('This suggests base64 strings may have been incorrectly concatenated');
      console.error('First 200 chars:', cleaned.substring(0, 200));
      console.error('Last 200 chars:', cleaned.substring(Math.max(0, cleaned.length - 200)));
      
      // Try to fix by removing '=' from the middle (this is a workaround)
      // Only keep '=' at the very end
      const dataPart = cleaned.replace(/=/g, '');
      const padding = cleaned.slice(-2).replace(/[^=]/g, '');
      const fixed = dataPart + padding;
      
      console.warn('Attempting to fix by removing middle padding...');
      if (fixed.length % 4 === 0) {
        try {
          const binary = atob(fixed);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
          }
          console.warn('✓ Fixed base64 decoded successfully');
          return bytes.buffer;
        } catch (e) {
          console.error('Failed to decode even after fixing:', e.message);
        }
      }
      
      throw new Error(`base64ToArrayBuffer: Invalid padding (${allEquals.length} '=' characters found, max 2 allowed at end only). This suggests base64 strings were incorrectly concatenated. Error: Failed to execute 'atob'`);
    }
  }
  
  try {
    // Try decoding the whole string first (works for most cases)
    try {
      const binary = atob(cleaned);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    } catch (decodeError) {
      // If decoding fails, it might be due to size or format issues
      // Try to provide more specific error information
      console.warn('Direct base64 decode failed, checking for issues...', decodeError.message);
      
      // Check if it's a size issue or format issue
      if (cleaned.length > 50 * 1024 * 1024) { // > 50MB
        throw new Error(`base64ToArrayBuffer: String too large (${cleaned.length} chars). Consider processing in smaller chunks. Error: ${decodeError.message}`);
      }
      
      // Check for common base64 issues
      // Base64 length should be multiple of 4 (with padding)
      const remainder = cleaned.length % 4;
      if (remainder !== 0) {
        throw new Error(`base64ToArrayBuffer: Invalid base64 length (${cleaned.length} chars, remainder ${remainder}). Base64 strings must be multiples of 4. Error: ${decodeError.message}`);
      }
      
      // If we get here, it's likely a character encoding issue
      throw new Error(`base64ToArrayBuffer: Failed to decode base64: ${decodeError.message}. String length: ${cleaned.length}, first 200 chars: ${cleaned.substring(0, 200)}`);
    }
  } catch (error) {
    // Provide more detailed error information
    const invalidChars = base64.match(/[^A-Za-z0-9+/=]/g);
    const errorMsg = invalidChars 
      ? `base64ToArrayBuffer: Failed to decode base64. Found ${invalidChars.length} invalid characters (first few: ${invalidChars.slice(0, 10).map(c => `'${c}' (${c.charCodeAt(0)})`).join(', ')}). Input length: ${base64.length}`
      : `base64ToArrayBuffer: Failed to decode base64: ${error.message}. Input length: ${base64.length}, first 100 chars: ${base64.substring(0, 100)}`;
    throw new Error(errorMsg);
  }
}


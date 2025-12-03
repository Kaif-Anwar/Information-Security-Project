/**
 * Secure Key Storage using IndexedDB
 * Private keys are stored encrypted in IndexedDB
 */

const DB_NAME = 'E2EEKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

let db = null;

/**
 * Initialize IndexedDB
 */
export async function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      reject(new Error('Failed to open IndexedDB'));
    };

    request.onsuccess = () => {
      db = request.result;
      resolve(db);
    };

    request.onupgradeneeded = (event) => {
      const database = event.target.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

/**
 * Store private key securely
 */
export async function storePrivateKey(keyId, privateKeyBase64, encryptionKey) {
  try {
    if (!db) await initDB();

    // Encrypt the private key before storing
    const encryptedKey = await encryptKeyForStorage(privateKeyBase64, encryptionKey);

    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    
    return new Promise((resolve, reject) => {
      const request = store.put({
        id: keyId,
        encryptedKey: encryptedKey,
        timestamp: Date.now()
      });
      
      request.onsuccess = () => {
        console.log(`Key stored successfully: ${keyId}`);
        resolve(true);
      };
      
      request.onerror = () => {
        reject(new Error('Failed to store private key'));
      };
    });
  } catch (error) {
    console.error('Error storing private key:', error);
    throw error;
  }
}

/**
 * Retrieve private key
 */
export async function getPrivateKey(keyId, encryptionKey) {
  try {
    if (!db) await initDB();

    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    
    return new Promise((resolve, reject) => {
      const request = store.get(keyId);
      
      request.onsuccess = async () => {
        if (request.result) {
          try {
            const decryptedKey = await decryptKeyFromStorage(request.result.encryptedKey, encryptionKey);
            resolve(decryptedKey);
          } catch (error) {
            console.error('Decryption error:', error);
            reject(new Error('Failed to decrypt private key - wrong password or corrupted key'));
          }
        } else {
          reject(new Error('Private key not found'));
        }
      };
      
      request.onerror = () => {
        reject(new Error('Failed to retrieve private key'));
      };
    });
  } catch (error) {
    console.error('Error retrieving private key:', error);
    throw error;
  }
}

/**
 * Check if a key exists
 */
export async function keyExists(keyId) {
  try {
    if (!db) await initDB();

    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    
    return new Promise((resolve, reject) => {
      const request = store.get(keyId);
      
      request.onsuccess = () => {
        resolve(!!request.result);
      };
      
      request.onerror = () => {
        reject(new Error('Failed to check key existence'));
      };
    });
  } catch (error) {
    console.error('Error checking key existence:', error);
    throw error;
  }
}

/**
 * Delete private key
 */
export async function deletePrivateKey(keyId) {
  try {
    if (!db) await initDB();

    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    
    return new Promise((resolve, reject) => {
      const request = store.delete(keyId);
      
      request.onsuccess = () => {
        resolve(true);
      };
      
      request.onerror = () => {
        reject(new Error('Failed to delete private key'));
      };
    });
  } catch (error) {
    console.error('Error deleting private key:', error);
    throw error;
  }
}

/**
 * Encrypt key for storage (using a derived key from user password)
 */
async function encryptKeyForStorage(keyBase64, encryptionKey) {
  // Use AES-GCM to encrypt the private key
  const encoder = new TextEncoder();
  const data = encoder.encode(keyBase64);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    encryptionKey,
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

/**
 * Decrypt key from storage
 */
async function decryptKeyFromStorage(encryptedData, encryptionKey) {
  try {
    const ciphertext = base64ToArrayBuffer(encryptedData.ciphertext);
    const iv = base64ToArrayBuffer(encryptedData.iv);
    const authTag = base64ToArrayBuffer(encryptedData.authTag);

    const encrypted = new Uint8Array(ciphertext.byteLength + authTag.byteLength);
    encrypted.set(new Uint8Array(ciphertext), 0);
    encrypted.set(new Uint8Array(authTag), ciphertext.byteLength);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      encryptionKey,
      encrypted
    );

    const decoder = new TextDecoder();
    const decryptedString = decoder.decode(decrypted);
    
    // Verify the decrypted string is valid (should be base64)
    if (!decryptedString || decryptedString.length < 50) {
      throw new Error('Decrypted key appears to be invalid or too short');
    }
    
    return decryptedString;
  } catch (error) {
    console.error('Decryption error details:', {
      message: error.message,
      name: error.name,
      hasCiphertext: !!encryptedData?.ciphertext,
      hasIV: !!encryptedData?.iv,
      hasAuthTag: !!encryptedData?.authTag
    });
    throw new Error('Failed to decrypt key from storage: ' + error.message);
  }
}

// Helper functions
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

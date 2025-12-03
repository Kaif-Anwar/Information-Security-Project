import { useState } from 'react';
import { authAPI, setAuthHeader } from '../services/api.js';
import {
  generateECCKeyPair,
  generateECDSAKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importECCPrivateKey,
  importECDAPrivateKey,
  importECCPublicKey,
  importECDSAPublicKey
} from '../utils/crypto.js';
import { storePrivateKey, getPrivateKey, keyExists } from '../utils/storage.js';

export default function Auth({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        // Login
        const response = await authAPI.login(username, password);
        setAuthHeader(response.userId);
        
        // Load private keys from IndexedDB
        try {
          const passwordKey = await deriveKeyFromPassword(password);
          const userId = response.userId;
          
          // Try user-specific keys first, then fallback to old format
          let encryptionPrivateKeyBase64, signingPrivateKeyBase64;
          let keysFound = false;
          let keyError = null;
          
          // Check if user-specific keys exist
          const userEncryptionExists = await keyExists(`${userId}_encryption`).catch(() => false);
          const userSigningExists = await keyExists(`${userId}_signing`).catch(() => false);
          
          if (userEncryptionExists && userSigningExists) {
            try {
              encryptionPrivateKeyBase64 = await getPrivateKey(`${userId}_encryption`, passwordKey);
              signingPrivateKeyBase64 = await getPrivateKey(`${userId}_signing`, passwordKey);
              keysFound = true;
              console.log('Keys found with user-specific format');
            } catch (e) {
              keyError = e;
              console.error('Failed to decrypt user-specific keys:', e);
            }
          }
          
          // If user-specific keys don't exist or failed to decrypt, try old format
          if (!keysFound) {
            const oldEncryptionExists = await keyExists('encryption').catch(() => false);
            const oldSigningExists = await keyExists('signing').catch(() => false);
            
            if (oldEncryptionExists && oldSigningExists) {
              try {
                console.log('Trying old format keys...');
                encryptionPrivateKeyBase64 = await getPrivateKey('encryption', passwordKey);
                signingPrivateKeyBase64 = await getPrivateKey('signing', passwordKey);
                keysFound = true;
                console.log('Keys found with old format, migrating...');
                // Migrate to new format
                await storePrivateKey(`${userId}_encryption`, encryptionPrivateKeyBase64, passwordKey);
                await storePrivateKey(`${userId}_signing`, signingPrivateKeyBase64, passwordKey);
              } catch (e2) {
                keyError = e2;
                console.error('Failed to decrypt old format keys:', e2);
              }
            }
          }
          
          if (!keysFound) {
            // Keys don't exist or can't be decrypted
            console.warn('Private keys not found or cannot be decrypted');
            if (keyError && keyError.message && keyError.message.includes('decrypt')) {
              setError('Failed to decrypt keys. Please verify your password is correct. If you registered on a different device, you may need to register again on this device.');
            } else {
              setError('Private keys not found in local storage. This usually means you registered on a different device. Please register again on this device to generate new keys.');
            }
            setLoading(false);
            return;
          }
          
          // Validate decrypted keys are valid base64
          console.log('Validating decrypted keys...');
          console.log('Encryption key length:', encryptionPrivateKeyBase64?.length);
          console.log('Signing key length:', signingPrivateKeyBase64?.length);
          
          // Check if keys are valid base64
          const isValidBase64 = (str) => {
            try {
              return btoa(atob(str)) === str;
            } catch (e) {
              return false;
            }
          };
          
          if (!encryptionPrivateKeyBase64 || !isValidBase64(encryptionPrivateKeyBase64)) {
            throw new Error('Encryption key is not valid base64. Decryption may have failed.');
          }
          
          if (!signingPrivateKeyBase64 || !isValidBase64(signingPrivateKeyBase64)) {
            throw new Error('Signing key is not valid base64. Decryption may have failed.');
          }
          
          console.log('✓ Keys are valid base64 format');
          
          // Import the private keys
          console.log('Importing encryption private key...');
          let encryptionPrivateKey, signingPrivateKey;
          try {
            encryptionPrivateKey = await importECCPrivateKey(encryptionPrivateKeyBase64, 'P-256');
            console.log('✓ Encryption private key imported successfully');
          } catch (e) {
            console.error('✗ Failed to import encryption private key:', e);
            console.error('Key preview (first 100 chars):', encryptionPrivateKeyBase64.substring(0, 100));
            throw new Error('Failed to import encryption private key. The key may be corrupted. Error: ' + e.message);
          }
          
          console.log('Importing signing private key...');
          try {
            signingPrivateKey = await importECDAPrivateKey(signingPrivateKeyBase64, 'P-256');
            console.log('✓ Signing private key imported successfully');
          } catch (e) {
            console.error('✗ Failed to import signing private key:', e);
            console.error('Key preview (first 100 chars):', signingPrivateKeyBase64.substring(0, 100));
            throw new Error('Failed to import signing private key. The key may be corrupted. Error: ' + e.message);
          }
          
          // Parse public keys from response to create key pairs
          console.log('Parsing public keys from server response...');
          let publicKeys;
          try {
            publicKeys = JSON.parse(response.publicKey);
            console.log('Public keys parsed:', {
              hasEncryption: !!publicKeys.encryption,
              hasSigning: !!publicKeys.signing,
              encryptionLength: publicKeys.encryption?.length || 0,
              signingLength: publicKeys.signing?.length || 0
            });
          } catch (e) {
            throw new Error('Failed to parse public keys from server: ' + e.message);
          }
          
          // Import public keys - but we actually don't need them since we have private keys
          // The KeyExchangeManager will use the private keys to derive what it needs
          // However, we need the public keys for verification purposes
          console.log('Importing encryption public key...');
          let encryptionPublicKey, signingPublicKey;
          try {
            if (!publicKeys.encryption) {
              throw new Error('Encryption public key is missing from server response');
            }
            
            // Validate base64 format
            const isValidBase64 = (str) => {
              try {
                return btoa(atob(str)) === str && str.length > 50;
              } catch (e) {
                return false;
              }
            };
            
            if (!isValidBase64(publicKeys.encryption)) {
              throw new Error('Encryption public key is not valid base64 format');
            }
            
            console.log('Encryption public key format validated, length:', publicKeys.encryption.length);
            encryptionPublicKey = await importECCPublicKey(publicKeys.encryption, 'P-256');
            console.log('✓ Encryption public key imported successfully');
          } catch (e) {
            console.error('✗ Failed to import encryption public key:', e);
            console.error('Error details:', {
              message: e.message,
              name: e.name,
              keyLength: publicKeys.encryption?.length,
              keyPreview: publicKeys.encryption?.substring(0, 100)
            });
            // Don't fail completely - we can still use the private keys
            console.warn('⚠️  Continuing without encryption public key (will use base64 version when needed)');
            encryptionPublicKey = null;
          }
          
          console.log('Importing signing public key...');
          try {
            if (!publicKeys.signing) {
              throw new Error('Signing public key is missing from server response');
            }
            
            // Validate base64 format
            const isValidBase64 = (str) => {
              try {
                return btoa(atob(str)) === str && str.length > 50;
              } catch (e) {
                return false;
              }
            };
            
            if (!isValidBase64(publicKeys.signing)) {
              throw new Error('Signing public key is not valid base64 format');
            }
            
            console.log('Signing public key format validated, length:', publicKeys.signing.length);
            signingPublicKey = await importECDSAPublicKey(publicKeys.signing, 'P-256');
            console.log('✓ Signing public key imported successfully');
          } catch (e) {
            console.error('✗ Failed to import signing public key:', e);
            console.error('Error details:', {
              message: e.message,
              name: e.name,
              keyLength: publicKeys.signing?.length,
              keyPreview: publicKeys.signing?.substring(0, 100)
            });
            console.warn('⚠️  Continuing without signing public key (will use base64 version when needed)');
            signingPublicKey = null;
          }
          
          // Create key pair objects
          // If public keys failed to import, we'll need to handle that
          // For now, we'll create the key pairs with the private keys
          // The public keys can be exported from private keys when needed (but Web Crypto doesn't support that)
          // So we'll store the base64 public keys and import them lazily when needed
          
          const encryptionKeyPair = {
            publicKey: encryptionPublicKey, // May be null if import failed
            privateKey: encryptionPrivateKey,
            publicKeyBase64: publicKeys.encryption // Store base64 for lazy import
          };
          
          const signingKeyPair = {
            publicKey: signingPublicKey, // May be null if import failed
            privateKey: signingPrivateKey,
            publicKeyBase64: publicKeys.signing // Store base64 for lazy import
          };
          
          // If public keys are null, try to import them lazily when first needed
          // For now, we'll proceed with login and handle the error if it occurs during key exchange
          
          console.log('✓ Key pairs created successfully');
          console.log('   Encryption key pair:', {
            hasPublicKey: !!encryptionKeyPair.publicKey,
            hasPrivateKey: !!encryptionKeyPair.privateKey
          });
          console.log('   Signing key pair:', {
            hasPublicKey: !!signingKeyPair.publicKey,
            hasPrivateKey: !!signingKeyPair.privateKey
          });
          
          onLogin({
            userId: response.userId,
            username: response.username,
            publicKey: response.publicKey,
            encryptionKeyPair,
            signingKeyPair
          });
        } catch (keyError) {
          console.error('\n❌ KEY LOADING ERROR:');
          console.error('   Error type:', keyError.name);
          console.error('   Error message:', keyError.message);
          console.error('   Stack:', keyError.stack);
          console.error('   User ID:', response.userId);
          console.error('   Full error object:', keyError);
          
          // More detailed error message
          let errorMessage = 'Failed to load encryption keys. ';
          if (keyError.message && keyError.message.includes('decrypt')) {
            errorMessage += 'Failed to decrypt keys. Please verify your password is correct.';
          } else if (keyError.message && keyError.message.includes('not found')) {
            errorMessage += 'Keys not found in local storage. You may need to register again on this device.';
          } else if (keyError.message && keyError.message.includes('key usages')) {
            errorMessage += 'Key format error. The stored keys may be corrupted. Try registering again.';
          } else if (keyError.message && keyError.message.includes('corrupted')) {
            errorMessage += 'Stored keys appear to be corrupted. Please register again.';
          } else {
            errorMessage += 'Error: ' + keyError.message;
          }
          
          errorMessage += '\n\nCheck browser console (F12) for detailed error information.';
          
          setError(errorMessage);
          setLoading(false);
          return;
        }
      } else {
        // Register
        // Generate key pairs
        const encryptionKeyPair = await generateECCKeyPair('P-256');
        const signingKeyPair = await generateECDSAKeyPair('P-256');

        // Export public keys (combine for storage)
        const encryptionPublicKey = await exportPublicKey(encryptionKeyPair.publicKey);
        const signingPublicKey = await exportPublicKey(signingKeyPair.publicKey);
        const combinedPublicKey = JSON.stringify({
          encryption: encryptionPublicKey,
          signing: signingPublicKey
        });

        // Register with server
        const response = await authAPI.register(username, password, combinedPublicKey);

        // Store private keys securely (derive encryption key from password)
        // Use user ID in key storage to make keys user-specific
        try {
          const passwordKey = await deriveKeyFromPassword(password);
          const userId = response.userId;
          
          console.log('Storing keys for user:', userId);
          
          // Export private keys
          const encryptionPrivateKeyBase64 = await exportPrivateKey(encryptionKeyPair.privateKey);
          const signingPrivateKeyBase64 = await exportPrivateKey(signingKeyPair.privateKey);
          
          console.log('Encryption key exported, length:', encryptionPrivateKeyBase64.length);
          console.log('Signing key exported, length:', signingPrivateKeyBase64.length);
          
          // Test that keys can be imported back (verify format is correct)
          try {
            const testEncryptionKey = await importECCPrivateKey(encryptionPrivateKeyBase64, 'P-256');
            console.log('✓ Encryption key can be imported (format is correct)');
          } catch (e) {
            console.error('✗ Encryption key import test failed:', e);
            throw new Error('Encryption key format is invalid: ' + e.message);
          }
          
          try {
            const testSigningKey = await importECDAPrivateKey(signingPrivateKeyBase64, 'P-256');
            console.log('✓ Signing key can be imported (format is correct)');
          } catch (e) {
            console.error('✗ Signing key import test failed:', e);
            throw new Error('Signing key format is invalid: ' + e.message);
          }
          
          // Store keys
          await storePrivateKey(`${userId}_encryption`, encryptionPrivateKeyBase64, passwordKey);
          console.log('Encryption key stored successfully');
          
          await storePrivateKey(`${userId}_signing`, signingPrivateKeyBase64, passwordKey);
          console.log('Signing key stored successfully');
          
          // Verify keys were stored
          const encryptionExists = await keyExists(`${userId}_encryption`);
          const signingExists = await keyExists(`${userId}_signing`);
          console.log('Key verification - Encryption exists:', encryptionExists, 'Signing exists:', signingExists);
          
          if (!encryptionExists || !signingExists) {
            throw new Error('Keys were not stored properly');
          }
          
          // Test retrieval immediately to verify storage works
          console.log('Testing key retrieval and import...');
          const testEncryptionKeyBase64 = await getPrivateKey(`${userId}_encryption`, passwordKey);
          const testSigningKeyBase64 = await getPrivateKey(`${userId}_signing`, passwordKey);
          console.log('Keys retrieved successfully, lengths:', testEncryptionKeyBase64.length, testSigningKeyBase64.length);
          
          // Test that retrieved keys can be imported
          try {
            const testEncryptionKey = await importECCPrivateKey(testEncryptionKeyBase64, 'P-256');
            console.log('✓ Retrieved encryption key can be imported');
          } catch (e) {
            console.error('✗ Retrieved encryption key import failed:', e);
            throw new Error('Retrieved encryption key is corrupted: ' + e.message);
          }
          
          try {
            const testSigningKey = await importECDAPrivateKey(testSigningKeyBase64, 'P-256');
            console.log('✓ Retrieved signing key can be imported');
          } catch (e) {
            console.error('✗ Retrieved signing key import failed:', e);
            throw new Error('Retrieved signing key is corrupted: ' + e.message);
          }
        } catch (storageError) {
          console.error('Error storing keys during registration:', storageError);
          // Still allow registration to complete, but warn user
          setError('Registration successful, but failed to store encryption keys locally. You may need to register again if you cannot login.');
          setLoading(false);
          return;
        }

        setAuthHeader(response.userId);
        onLogin({
          userId: response.userId,
          username: response.username,
          encryptionKeyPair,
          signingKeyPair
        });
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  // Derive key from password for encrypting private keys
  const deriveKeyFromPassword = async (password) => {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const salt = encoder.encode('e2ee-salt'); // In production, use unique salt per user
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordData,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
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
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '450px',
        backgroundColor: 'var(--background-white)',
        borderRadius: '16px',
        boxShadow: 'var(--shadow-xl)',
        padding: '40px',
        border: '1px solid var(--border-color)'
      }}>
        <div style={{
          textAlign: 'center',
          marginBottom: '32px'
        }}>
          <div style={{
            fontSize: '32px',
            fontWeight: '700',
            background: 'linear-gradient(135deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            marginBottom: '8px'
          }}>
            🔐 Secure E2EE
          </div>
          <p style={{
            color: 'var(--text-secondary)',
            fontSize: '14px'
          }}>
            End-to-End Encrypted Messaging
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              color: 'var(--text-primary)',
              fontWeight: '500',
              fontSize: '14px'
            }}>
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '12px 16px',
                border: '2px solid var(--border-color)',
                borderRadius: '8px',
                fontSize: '15px',
                transition: 'all 0.2s',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--primary-blue)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
              placeholder="Enter your username"
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              marginBottom: '8px',
              color: 'var(--text-primary)',
              fontWeight: '500',
              fontSize: '14px'
            }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '12px 16px',
                border: '2px solid var(--border-color)',
                borderRadius: '8px',
                fontSize: '15px',
                transition: 'all 0.2s',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--primary-blue)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-color)'}
              placeholder="Enter your password"
            />
          </div>

          {error && (
            <div style={{
              padding: '12px',
              backgroundColor: '#fef2f2',
              border: '1px solid #fecaca',
              borderRadius: '8px',
              marginBottom: '20px',
              color: 'var(--error-red)',
              fontSize: '14px'
            }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '14px',
              backgroundColor: loading ? 'var(--text-secondary)' : 'var(--primary-blue)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '16px',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s',
              boxShadow: loading ? 'none' : 'var(--shadow-md)',
              marginBottom: '20px'
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                e.target.style.backgroundColor = 'var(--primary-blue-dark)';
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = 'var(--shadow-lg)';
              }
            }}
            onMouseLeave={(e) => {
              if (!loading) {
                e.target.style.backgroundColor = 'var(--primary-blue)';
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = 'var(--shadow-md)';
              }
            }}
          >
            {loading ? (
              <span>⏳ {isLogin ? 'Logging in...' : 'Registering...'}</span>
            ) : (
              <span>{isLogin ? '🔓 Login' : '✨ Register'}</span>
            )}
          </button>
        </form>

        <div style={{
          textAlign: 'center',
          paddingTop: '20px',
          borderTop: '1px solid var(--border-color)'
        }}>
          <p style={{
            color: 'var(--text-secondary)',
            fontSize: '14px',
            marginBottom: '8px'
          }}>
            {isLogin ? "Don't have an account? " : "Already have an account? "}
          </p>
          <button
            type="button"
            onClick={() => {
              setIsLogin(!isLogin);
              setError('');
            }}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--primary-blue)',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '600',
              textDecoration: 'underline',
              transition: 'color 0.2s'
            }}
            onMouseEnter={(e) => e.target.style.color = 'var(--primary-blue-dark)'}
            onMouseLeave={(e) => e.target.style.color = 'var(--primary-blue)'}
          >
            {isLogin ? 'Create Account' : 'Sign In'}
          </button>
        </div>
      </div>
    </div>
  );
}

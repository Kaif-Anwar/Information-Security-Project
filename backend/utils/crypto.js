import crypto from 'crypto';

/**
 * Verify ECDSA signature using Node.js crypto
 * @param {string} data - The data that was signed (plain text)
 * @param {string} signatureBase64 - The signature in base64 format
 * @param {string} publicKeyBase64 - The public key in base64 SPKI format
 * @returns {boolean} - True if signature is valid
 */
export function verifyECDSASignature(data, signatureBase64, publicKeyBase64) {
  try {
    // Decode base64 signature (Web Crypto API returns raw r||s format)
    const signatureRaw = Buffer.from(signatureBase64, 'base64');
    
    // Web Crypto API ECDSA signatures are in raw format (r||s, each 32 bytes for P-256)
    // Node.js crypto expects DER-encoded format, so we need to convert
    // For P-256: r and s are each 32 bytes, total 64 bytes
    if (signatureRaw.length !== 64) {
      console.error('Invalid signature length:', signatureRaw.length, 'expected 64 for P-256');
      return false;
    }
    
    // Convert raw signature (r||s) to DER format
    const r = signatureRaw.slice(0, 32);
    const s = signatureRaw.slice(32, 64);
    
    // Remove leading zeros
    let rTrimmed = r;
    let sTrimmed = s;
    while (rTrimmed[0] === 0 && rTrimmed.length > 1) rTrimmed = rTrimmed.slice(1);
    while (sTrimmed[0] === 0 && sTrimmed.length > 1) sTrimmed = sTrimmed.slice(1);
    
    // DER encoding for ECDSA signature
    // SEQUENCE { INTEGER r, INTEGER s }
    const rLength = rTrimmed.length;
    const sLength = sTrimmed.length;
    
    // If first byte is >= 0x80, we need to add a leading zero
    const rNeedsPadding = rTrimmed[0] >= 0x80;
    const sNeedsPadding = sTrimmed[0] >= 0x80;
    
    const rPadded = rNeedsPadding ? Buffer.concat([Buffer.from([0]), rTrimmed]) : rTrimmed;
    const sPadded = sNeedsPadding ? Buffer.concat([Buffer.from([0]), sTrimmed]) : sTrimmed;
    
    const rPaddedLength = rPadded.length;
    const sPaddedLength = sPadded.length;
    
    // Build DER structure
    const derSignature = Buffer.allocUnsafe(6 + rPaddedLength + sPaddedLength);
    let offset = 0;
    
    // SEQUENCE
    derSignature[offset++] = 0x30;
    // Length of sequence
    const sequenceLength = 2 + rPaddedLength + 2 + sPaddedLength;
    if (sequenceLength < 128) {
      derSignature[offset++] = sequenceLength;
    } else {
      derSignature[offset++] = 0x81;
      derSignature[offset++] = sequenceLength;
    }
    
    // INTEGER r
    derSignature[offset++] = 0x02;
    derSignature[offset++] = rPaddedLength;
    rPadded.copy(derSignature, offset);
    offset += rPaddedLength;
    
    // INTEGER s
    derSignature[offset++] = 0x02;
    derSignature[offset++] = sPaddedLength;
    sPadded.copy(derSignature, offset);
    offset += sPaddedLength;
    
    // Decode base64 public key (SPKI format)
    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
    
    // Import public key - use 'spki' format, not 'der'
    const publicKey = crypto.createPublicKey({
      key: publicKeyBuffer,
      format: 'spki'  // Changed from 'der' to 'spki'
    });
    
    // Verify signature
    const verify = crypto.createVerify('SHA256');
    verify.update(data, 'utf8');
    verify.end();
    
    const isValid = verify.verify(publicKey, derSignature);
    
    if (!isValid) {
      console.error('Signature verification failed:', {
        dataLength: data.length,
        signatureLength: signatureRaw.length,
        publicKeyLength: publicKeyBuffer.length,
        derSignatureLength: derSignature.length
      });
    }
    
    return isValid;
  } catch (error) {
    console.error('Error verifying ECDSA signature:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack
    });
    return false;
  }
}

/**
 * Validate timestamp to prevent replay attacks
 * @param {number} timestamp - Timestamp in milliseconds
 * @param {number} maxAge - Maximum age in milliseconds (default: 5 minutes)
 * @param {number} clockSkew - Clock skew tolerance in milliseconds (default: 1 minute)
 * @returns {boolean} - True if timestamp is valid
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000, clockSkew = 60 * 1000) {
  const now = Date.now();
  const age = now - timestamp;
  
  // Check if timestamp is too old
  if (age > maxAge) {
    return false;
  }
  
  // Check if timestamp is too far in the future (clock skew)
  if (timestamp > now + clockSkew) {
    return false;
  }
  
  return true;
}


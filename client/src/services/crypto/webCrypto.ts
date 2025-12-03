import {
  bufferToBase64,
  base64ToBuffer,
  utf8ToBuffer,
  bufferToUtf8,
} from '../../utils/buffer';
import type { KeyAlgorithm } from '../../types/crypto';

const subtle = window.crypto.subtle;

const RSA_ALG = {
  name: 'RSA-PSS',
  modulusLength: 3072,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: 'SHA-256',
};

const ECC_ALG = {
  name: 'ECDSA',
  namedCurve: 'P-256',
};

export const generateKeyPair = async (algorithm: KeyAlgorithm = 'ECC') => {
  if (algorithm === 'RSA') {
    return subtle.generateKey(
      {
        ...RSA_ALG,
      },
      true,
      ['sign', 'verify'],
    );
  }
  return subtle.generateKey(
    {
      ...ECC_ALG,
    },
    true,
    ['sign', 'verify'],
  );
};

export const exportPublicKey = async (key: CryptoKey) => {
  const buffer = await subtle.exportKey('spki', key);
  return bufferToBase64(buffer);
};

export const importPublicKey = async (
  keyData: string,
  algorithm: KeyAlgorithm = 'ECC',
) => {
  const buffer = base64ToBuffer(keyData);
  if (algorithm === 'RSA') {
    return subtle.importKey(
      'spki',
      buffer,
      RSA_ALG,
      true,
      ['verify'],
    );
  }
  return subtle.importKey(
    'spki',
    buffer,
    ECC_ALG,
    true,
    ['verify'],
  );
};

export const deriveAesKey = async (sharedSecret: ArrayBuffer) =>
  subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);

export const importAesKey = async (rawKey: ArrayBuffer) =>
  subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);

export const hkdf = async (inputKeyingMaterial: ArrayBuffer, info: string) => {
  const salt = window.crypto.getRandomValues(new Uint8Array(32));
  const ikm = await subtle.importKey(
    'raw',
    inputKeyingMaterial,
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  );
  const key = await subtle.deriveKey(
    {
      name: 'HKDF',
      salt,
      info: utf8ToBuffer(info),
      hash: 'SHA-256',
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  return {
    key,
    salt,
  };
};

export const aesEncrypt = async (
  key: CryptoKey,
  plaintext: string | ArrayBuffer,
) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data =
    typeof plaintext === 'string' ? utf8ToBuffer(plaintext) : plaintext;
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data,
  );
  return { ciphertext, iv };
};

export const aesDecrypt = async (
  key: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
) => {
  const buffer = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return bufferToUtf8(buffer);
};

export const signPayload = async (
  privateKey: CryptoKey,
  payload: string,
  algorithm: KeyAlgorithm = 'ECC',
) => {
  const data = utf8ToBuffer(payload);
  if (algorithm === 'RSA') {
    const signature = await subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      privateKey,
      data,
    );
    return bufferToBase64(signature);
  }
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data,
  );
  return bufferToBase64(signature);
};

/**
 * Validate timestamp for signature verification
 */
export const validateTimestamp = (
  timestamp: number,
  maxAge: number = 5 * 60 * 1000, // 5 minutes
  clockSkew: number = 60 * 1000, // 1 minute
): boolean => {
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
};

export const verifySignature = async (
  publicKey: CryptoKey,
  payload: string,
  signature: string,
  algorithm: KeyAlgorithm = 'ECC',
  timestamp: number | null = null,
  maxAge: number = 5 * 60 * 1000,
) => {
  // Validate timestamp if provided
  if (timestamp !== null && !validateTimestamp(timestamp, maxAge)) {
    console.error('Signature timestamp validation failed');
    return false;
  }

  const data = utf8ToBuffer(payload);
  const sigBuffer = base64ToBuffer(signature);
  if (algorithm === 'RSA') {
    return subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      publicKey,
      sigBuffer,
      data,
    );
  }
  return subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    sigBuffer,
    data,
  );
};


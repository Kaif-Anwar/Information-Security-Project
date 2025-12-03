export type KeyAlgorithm = 'RSA' | 'ECC';

export interface KeyMetadata {
  userId: string;
  algorithm: KeyAlgorithm;
  publicKeyArmored: string;
  createdAt: string;
}

export interface StoredPrivateKey {
  userId: string;
  algorithm: KeyAlgorithm;
  publicKeyArmored: string;
  wrappedKey: string;
  iv: string;
  salt: string;
  createdAt: string;
}

export interface SessionMaterial {
  peerId: string;
  sessionId: string;
  hkdfInfo: string;
  salt: string;
  exportedKey: string;
  derivedKey?: CryptoKey;
  createdAt: string;
}

export interface EncryptedMessagePayload {
  sessionId: string;
  senderId: string;
  receiverId: string;
  ciphertext: ArrayBuffer;
  iv: Uint8Array;
  authTag: ArrayBuffer;
  nonce: string;
  timestamp: number;
  sequence: number;
  signature?: string;
}

export interface EncryptedFileChunk {
  chunkId: string;
  sessionId: string;
  order: number;
  iv: Uint8Array;
  ciphertext: ArrayBuffer;
  authTag: ArrayBuffer;
}


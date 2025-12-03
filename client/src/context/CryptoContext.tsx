import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react';
import type {
  KeyAlgorithm,
  SessionMaterial,
  StoredPrivateKey,
} from '../types/crypto';
import {
  generateKeyPair,
  exportPublicKey,
  aesEncrypt,
  aesDecrypt,
  importAesKey,
} from '../services/crypto/webCrypto';
import {
  getPrivateKey,
  savePrivateKey,
  getSessionMaterial,
  saveSessionMaterial,
} from '../services/storage/indexedDb';
import { bufferToBase64, base64ToBuffer } from '../utils/buffer';
import { useAuth } from './AuthContext';
import { wrapPrivateKey, unwrapPrivateKey } from '../services/crypto/vault';

interface CryptoContextValue {
  publicKey?: string;
  algorithm: KeyAlgorithm;
  identityKey?: CryptoKey;
  vaultStatus: 'missing' | 'locked' | 'unlocked';
  generateIdentityKeys: (params: {
    algorithm?: KeyAlgorithm;
    passphrase: string;
  }) => Promise<void>;
  unlockPrivateKey: (passphrase: string) => Promise<void>;
  lockVault: () => void;
  sessionMap: Record<string, SessionMaterial>;
  loadSession: (sessionId: string) => Promise<SessionMaterial | null>;
  storeSession: (material: SessionMaterial) => Promise<void>;
  encryptMessage: (sessionId: string, plaintext: string) => Promise<{
    ciphertext: string;
    iv: string;
  }>;
  decryptMessage: (
    sessionId: string,
    ciphertext: string,
    iv: string,
  ) => Promise<string>;
}

const CryptoContext = createContext<CryptoContextValue | undefined>(undefined);

export const CryptoProvider = ({ children }: PropsWithChildren) => {
  const { userId } = useAuth();
  const [publicKey, setPublicKey] = useState<string>();
  const [algorithm, setAlgorithm] = useState<KeyAlgorithm>('ECC');
  const [identityKey, setIdentityKey] = useState<CryptoKey>();
  const [vaultStatus, setVaultStatus] =
    useState<CryptoContextValue['vaultStatus']>('missing');
  const [keyRecord, setKeyRecord] = useState<StoredPrivateKey | null>(null);
  const [sessionMap, setSessionMap] = useState<Record<string, SessionMaterial>>(
    {},
  );

  useEffect(() => {
    if (!userId) return;
    (async () => {
      const record = await getPrivateKey(userId);
      if (!record) {
        setVaultStatus('missing');
        setIdentityKey(undefined);
        setKeyRecord(null);
        return;
      }
      setKeyRecord(record);
      setPublicKey(record.publicKeyArmored);
      setAlgorithm(record.algorithm);
      setVaultStatus('locked');
    })();
  }, [userId]);

  const generateIdentityKeys: CryptoContextValue['generateIdentityKeys'] = async (
    params,
  ) => {
    const alg = params.algorithm ?? 'ECC';
    if (!userId) {
      throw new Error('User must be authenticated before generating keys');
    }
    if (!params.passphrase) {
      throw new Error('Passphrase is required to wrap the private key');
    }
    const keyPair = await generateKeyPair(alg);
    const exportedPublic = await exportPublicKey(keyPair.publicKey);
    const { wrapped, iv, salt } = await wrapPrivateKey({
      privateKey: keyPair.privateKey,
      passphrase: params.passphrase,
    });
    const record: StoredPrivateKey = {
      userId,
      algorithm: alg,
      publicKeyArmored: exportedPublic,
      wrappedKey: bufferToBase64(wrapped),
      iv: bufferToBase64(iv.buffer),
      salt: bufferToBase64(salt.buffer),
      createdAt: new Date().toISOString(),
    };
    await savePrivateKey(record);
    setKeyRecord(record);
    setPublicKey(exportedPublic);
    setAlgorithm(alg);
    setIdentityKey(keyPair.privateKey);
    setVaultStatus('unlocked');
  };

  const unlockPrivateKey: CryptoContextValue['unlockPrivateKey'] = async (
    passphrase,
  ) => {
    if (!keyRecord) {
      throw new Error('No private key stored for this user');
    }
    const algorithmParams =
      keyRecord.algorithm === 'RSA'
        ? ({
            name: 'RSA-PSS',
            hash: 'SHA-256',
          } satisfies RsaHashedImportParams)
        : ({
            name: 'ECDSA',
            namedCurve: 'P-256',
          } satisfies EcKeyImportParams);
    const unwrapped = await unwrapPrivateKey({
      wrappedKey: base64ToBuffer(keyRecord.wrappedKey),
      passphrase,
      algorithm: algorithmParams,
      iv: new Uint8Array(base64ToBuffer(keyRecord.iv)),
      salt: new Uint8Array(base64ToBuffer(keyRecord.salt)),
    });
    setIdentityKey(unwrapped);
    setVaultStatus('unlocked');
  };

  const lockVault = () => {
    setIdentityKey(undefined);
    setVaultStatus(keyRecord ? 'locked' : 'missing');
  };

  const loadSession = async (sessionId: string) => {
    if (sessionMap[sessionId]) {
      return sessionMap[sessionId];
    }
    const stored = await getSessionMaterial(sessionId);
    if (stored?.exportedKey) {
      const derivedKey = await importAesKey(
        base64ToBuffer(stored.exportedKey),
      );
      const material: SessionMaterial = {
        ...stored,
        derivedKey,
      };
      setSessionMap((prev) => ({ ...prev, [sessionId]: material }));
      return material;
    }
    return null;
  };

  const storeSession = async (material: SessionMaterial) => {
    const { derivedKey, ...rest } = material;
    if (!derivedKey) {
      throw new Error('Derived session key missing');
    }
    const exported =
      material.exportedKey ||
      bufferToBase64(
        await window.crypto.subtle.exportKey('raw', derivedKey),
      );
    const record = {
      ...rest,
      exportedKey: exported,
    };
    await saveSessionMaterial(record);
    setSessionMap((prev) => ({
      ...prev,
      [record.sessionId]: { ...record, derivedKey },
    }));
  };

  const encryptMessage = async (sessionId: string, plaintext: string) => {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session key missing');
    }
    const { ciphertext, iv } = await aesEncrypt(session.derivedKey, plaintext);
    return {
      ciphertext: bufferToBase64(ciphertext),
      iv: bufferToBase64(iv.buffer),
    };
  };

  const decryptMessage = async (
    sessionId: string,
    ciphertext: string,
    iv: string,
  ) => {
    const session = await loadSession(sessionId);
    if (!session) {
      throw new Error('Session key missing');
    }
    return aesDecrypt(
      session.derivedKey,
      base64ToBuffer(ciphertext),
      new Uint8Array(base64ToBuffer(iv)),
    );
  };

  const value = useMemo(
    () => ({
      publicKey,
      algorithm,
      identityKey,
      vaultStatus,
      sessionMap,
      generateIdentityKeys,
      unlockPrivateKey,
      lockVault,
      loadSession,
      storeSession,
      encryptMessage,
      decryptMessage,
    }),
    [publicKey, algorithm, identityKey, vaultStatus, sessionMap],
  );

  return (
    <CryptoContext.Provider value={value}>{children}</CryptoContext.Provider>
  );
};

export const useCrypto = () => {
  const context = useContext(CryptoContext);
  if (!context) {
    throw new Error('useCrypto must be used within CryptoProvider');
  }
  return context;
};


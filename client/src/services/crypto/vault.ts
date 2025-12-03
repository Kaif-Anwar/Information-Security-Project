const subtle = window.crypto.subtle;

const getKeyMaterial = (passphrase: string) =>
  subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey'],
  );

const deriveWrappingKey = async (passphrase: string, salt: Uint8Array) =>
  subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 250_000,
      hash: 'SHA-256',
    },
    await getKeyMaterial(passphrase),
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );

export const wrapPrivateKey = async (params: {
  privateKey: CryptoKey;
  passphrase: string;
}) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const wrappingKey = await deriveWrappingKey(params.passphrase, salt);
  const wrapped = await subtle.wrapKey(
    'pkcs8',
    params.privateKey,
    wrappingKey,
    { name: 'AES-GCM', iv },
  );
  return { wrapped, iv, salt };
};

export const unwrapPrivateKey = async (params: {
  wrappedKey: ArrayBuffer;
  passphrase: string;
  algorithm: RsaHashedImportParams | EcKeyImportParams;
  iv: Uint8Array;
  salt: Uint8Array;
}) => {
  const wrappingKey = await deriveWrappingKey(params.passphrase, params.salt);
  return subtle.unwrapKey(
    'pkcs8',
    params.wrappedKey,
    wrappingKey,
    { name: 'AES-GCM', iv: params.iv },
    params.algorithm,
    true,
    ['sign'],
  );
};


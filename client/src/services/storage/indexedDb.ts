const DB_NAME = 'secure-comm-db';
const STORE_PRIVATE_KEYS = 'privateKeys';
const STORE_SESSIONS = 'sessionCache';
const DB_VERSION = 1;

let dbPromise: Promise<IDBDatabase> | null = null;

const openDb = (): Promise<IDBDatabase> => {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onerror = () => reject(request.error);
      request.onupgradeneeded = () => {
        const { result } = request;
        if (!result.objectStoreNames.contains(STORE_PRIVATE_KEYS)) {
          result.createObjectStore(STORE_PRIVATE_KEYS, { keyPath: 'userId' });
        }
        if (!result.objectStoreNames.contains(STORE_SESSIONS)) {
          result.createObjectStore(STORE_SESSIONS, { keyPath: 'sessionId' });
        }
      };
      request.onsuccess = () => resolve(request.result);
    });
  }
  return dbPromise;
};

const getStore = async (
  storeName: string,
  mode: IDBTransactionMode = 'readonly',
) => {
  const db = await openDb();
  const tx = db.transaction(storeName, mode);
  return tx.objectStore(storeName);
};

export const savePrivateKey = async (record: unknown) => {
  const store = await getStore(STORE_PRIVATE_KEYS, 'readwrite');
  return new Promise<void>((resolve, reject) => {
    const request = store.put(record);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
};

export const getPrivateKey = async (userId: string) => {
  const store = await getStore(STORE_PRIVATE_KEYS);
  return new Promise<any>((resolve, reject) => {
    const request = store.get(userId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
};

export const saveSessionMaterial = async (record: unknown) => {
  const store = await getStore(STORE_SESSIONS, 'readwrite');
  return new Promise<void>((resolve, reject) => {
    const request = store.put(record);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
};

export const getSessionMaterial = async (sessionId: string) => {
  const store = await getStore(STORE_SESSIONS);
  return new Promise<any>((resolve, reject) => {
    const request = store.get(sessionId);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
};


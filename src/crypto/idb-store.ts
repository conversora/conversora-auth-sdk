/**
 * IndexedDB storage abstraction for DPoP hardware keys and auth sessions
 * Includes in-memory fallback for SSR, React Native, or testing environments.
 */

const DB_NAME = 'conversora_auth_vault';
const DB_VERSION = 1;

export const STORE_KEYS = 'keys';
export const STORE_SESSIONS = 'sessions';

const memoryStore = new Map<string, any>();

function getMemoryKey(storeName: string, key: string): string {
  return `${storeName}:${key}`;
}

export function openAuthDatabase(): Promise<IDBDatabase | null> {
  if (typeof window === 'undefined' || typeof indexedDB === 'undefined') {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_KEYS)) {
          db.createObjectStore(STORE_KEYS, { keyPath: 'tenantId' });
        }
        if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
          db.createObjectStore(STORE_SESSIONS, { keyPath: 'tenantId' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function idbGet<T>(storeName: string, key: string): Promise<T | null> {
  const db = await openAuthDatabase();
  if (!db) {
    return memoryStore.get(getMemoryKey(storeName, key)) || null;
  }

  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(memoryStore.get(getMemoryKey(storeName, key)) || null);
    } catch {
      resolve(memoryStore.get(getMemoryKey(storeName, key)) || null);
    }
  });
}

export async function idbPut<T>(storeName: string, val: T & { tenantId: string }): Promise<void> {
  memoryStore.set(getMemoryKey(storeName, val.tenantId), val);

  const db = await openAuthDatabase();
  if (!db) return;

  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.put(val);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

export async function idbDelete(storeName: string, key: string): Promise<void> {
  memoryStore.delete(getMemoryKey(storeName, key));

  const db = await openAuthDatabase();
  if (!db) return;

  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

export async function idbClearAll(tenantId: string): Promise<void> {
  await Promise.all([
    idbDelete(STORE_KEYS, tenantId),
    idbDelete(STORE_SESSIONS, tenantId),
  ]);
}

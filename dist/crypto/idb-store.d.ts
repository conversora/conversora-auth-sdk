/**
 * IndexedDB storage abstraction for DPoP hardware keys and auth sessions
 * Includes in-memory fallback for SSR, React Native, or testing environments.
 */
export declare const STORE_KEYS = "keys";
export declare const STORE_SESSIONS = "sessions";
export declare function openAuthDatabase(): Promise<IDBDatabase | null>;
export declare function idbGet<T>(storeName: string, key: string): Promise<T | null>;
export declare function idbPut<T>(storeName: string, val: T & {
    tenantId: string;
}): Promise<void>;
export declare function idbDelete(storeName: string, key: string): Promise<void>;
export declare function idbClearAll(tenantId: string): Promise<void>;

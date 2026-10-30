/**
 * RFC 9449 DPoP Key Pair Management
 * Generates hardware/device-bound ECDSA P-256 cryptographic keys with non-extractable private keys
 * and computes RFC 7638 SHA-256 base64url JWK thumbprints (cnf.jkt).
 * Includes concurrency mutex to prevent race condition duplications.
 */
import type { StoredKeyPair } from '../types';
/**
 * Checks whether the current runtime environment supports Web Cryptography ECDSA P-256.
 */
export declare function isDPoPSupported(): boolean;
/**
 * Computes canonical RFC 7638 JWK Thumbprint for an EC P-256 public key.
 * Required member order in JSON: crv, kty, x, y.
 */
export declare function computeJwkThumbprint(jwk: JsonWebKey): Promise<string>;
/**
 * Retrieves existing or generates a new non-extractable ECDSA P-256 key pair scoped to tenantId.
 * Stored in IndexedDB so it persists across page reloads and browser sessions.
 * Concurrency-safe: Deduplicates multiple parallel callers for the same tenant.
 */
export declare function getOrCreateDPoPKeyPair(tenantId?: string): Promise<StoredKeyPair | null>;
/**
 * Purges the stored cryptographic DPoP key pair for this tenant
 */
export declare function purgeDPoPKeyPair(tenantId?: string): Promise<void>;

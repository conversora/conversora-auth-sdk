/**
 * RFC 9449 DPoP Key Pair Management
 * Generates hardware/device-bound ECDSA P-256 cryptographic keys with non-extractable private keys
 * and computes RFC 7638 SHA-256 base64url JWK thumbprints (cnf.jkt).
 * Includes concurrency mutex to prevent race condition duplications.
 */

import type { StoredKeyPair } from '../types';
import { base64UrlEncode } from './base64url';
import { idbGet, idbPut, idbDelete, STORE_KEYS } from './idb-store';

const inFlightKeyGenerations = new Map<string, Promise<StoredKeyPair | null>>();
const inMemoryKeyStore = new Map<string, StoredKeyPair>();

/**
 * Checks whether the current runtime environment supports Web Cryptography ECDSA P-256.
 */
export function isDPoPSupported(): boolean {
  try {
    const subtle = typeof crypto !== 'undefined' ? crypto.subtle : null;
    return !!subtle && typeof subtle.generateKey === 'function';
  } catch {
    return false;
  }
}

/**
 * Computes canonical RFC 7638 JWK Thumbprint for an EC P-256 public key.
 * Required member order in JSON: crv, kty, x, y.
 */
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return base64UrlEncode(hash);
}

/**
 * Retrieves existing or generates a new non-extractable ECDSA P-256 key pair scoped to tenantId.
 * Stored in IndexedDB so it persists across page reloads and browser sessions.
 * Concurrency-safe: Deduplicates multiple parallel callers for the same tenant.
 */
export async function getOrCreateDPoPKeyPair(tenantId = 'default'): Promise<StoredKeyPair | null> {
  if (!isDPoPSupported()) {
    return null;
  }

  // Deduplicate in-flight key generations for the same tenant
  const inFlight = inFlightKeyGenerations.get(tenantId);
  if (inFlight) {
    return inFlight;
  }

  const promise = (async (): Promise<StoredKeyPair | null> => {
    try {
      // 1. Try to read existing key pair from IndexedDB
      try {
        const existing = await idbGet<StoredKeyPair>(STORE_KEYS, tenantId);
        if (existing && existing.privateKey && existing.publicKey && existing.jwk && existing.jkt) {
          return existing;
        }
      } catch {
        // Fallback to in-memory store if IndexedDB throws (e.g. Safari private mode)
        const memExisting = inMemoryKeyStore.get(tenantId);
        if (memExisting) return memExisting;
      }

      // 2. Generate new hardware-bound ECDSA P-256 key pair
      const keyPair = (await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, // non-extractable: Private key cannot be exported/stolen via script!
        ['sign', 'verify']
      )) as CryptoKeyPair;

      // 3. Export public key to JWK format for proof generation
      const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
      const jkt = await computeJwkThumbprint(publicJwk);

      const record: StoredKeyPair = {
        tenantId,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        jwk: publicJwk,
        jkt,
        createdAt: Date.now(),
      };

      try {
        await idbPut(STORE_KEYS, record);
      } catch {
        // Store in memory if IndexedDB persistence is unavailable
        inMemoryKeyStore.set(tenantId, record);
      }

      return record;
    } catch {
      return null;
    } finally {
      inFlightKeyGenerations.delete(tenantId);
    }
  })();

  inFlightKeyGenerations.set(tenantId, promise);
  return promise;
}

/**
 * Purges the stored cryptographic DPoP key pair for this tenant
 */
export async function purgeDPoPKeyPair(tenantId = 'default'): Promise<void> {
  inFlightKeyGenerations.delete(tenantId);
  inMemoryKeyStore.delete(tenantId);
  try {
    await idbDelete(STORE_KEYS, tenantId);
  } catch {}
}

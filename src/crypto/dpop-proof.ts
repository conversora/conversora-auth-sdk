/**
 * RFC 9449 DPoP Proof Generator
 * Creates signed DPoP proof JWTs bound to HTTP method, target URI, and optional access token hash (ath).
 */

import type { StoredKeyPair } from '../types';
import { base64UrlEncode, stringToBase64Url } from './base64url';
import { getOrCreateDPoPKeyPair } from './dpop-keys';

export interface CreateDPoPProofOptions {
  method: string;
  url: string;
  accessToken?: string;
  keyPair?: StoredKeyPair;
  tenantId?: string;
}

/**
 * Normalizes HTTP URL to origin + pathname (stripping query parameters and hash fragments)
 */
export function normalizeDPoPHtu(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl, typeof window !== 'undefined' ? window.location.origin : 'https://auth.conversora.io');
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return rawUrl.split('?')[0]?.split('#')[0] || rawUrl;
  }
}

/**
 * Creates and signs an RFC 9449 DPoP proof JWT.
 * Returns null if DPoP key generation or signing is not supported in current environment.
 */
export async function createDPoPProof(options: CreateDPoPProofOptions): Promise<string | null> {
  const { method, url, accessToken, tenantId = 'default' } = options;

  let keyRecord = options.keyPair;
  if (!keyRecord) {
    const fetched = await getOrCreateDPoPKeyPair(tenantId);
    if (!fetched) return null;
    keyRecord = fetched;
  }

  try {
    const htu = normalizeDPoPHtu(url);

    const header = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: keyRecord.jwk.x,
        y: keyRecord.jwk.y,
      },
    };

    // Generate random 16-byte nonce for jti
    const randomBytes = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(randomBytes);
    } else {
      for (let i = 0; i < 16; i++) randomBytes[i] = Math.floor(Math.random() * 256);
    }

    const payload: Record<string, any> = {
      jti: 'dpop_' + base64UrlEncode(randomBytes),
      htm: method.toUpperCase(),
      htu,
      iat: Math.floor(Date.now() / 1000),
    };

    // If an access token is bound to this request, calculate its SHA-256 hash (ath)
    if (accessToken) {
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
      payload.ath = base64UrlEncode(hash);
    }

    const encodedHeader = stringToBase64Url(JSON.stringify(header));
    const encodedPayload = stringToBase64Url(JSON.stringify(payload));
    const message = `${encodedHeader}.${encodedPayload}`;

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyRecord.privateKey,
      new TextEncoder().encode(message)
    );

    return `${message}.${base64UrlEncode(signature)}`;
  } catch (err) {
    return null;
  }
}

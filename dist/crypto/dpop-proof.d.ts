/**
 * RFC 9449 DPoP Proof Generator
 * Creates signed DPoP proof JWTs bound to HTTP method, target URI, and optional access token hash (ath).
 */
import type { StoredKeyPair } from '../types';
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
export declare function normalizeDPoPHtu(rawUrl: string): string;
/**
 * Creates and signs an RFC 9449 DPoP proof JWT.
 * Returns null if DPoP key generation or signing is not supported in current environment.
 */
export declare function createDPoPProof(options: CreateDPoPProofOptions): Promise<string | null>;

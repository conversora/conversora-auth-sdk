/**
 * 4-Step Atomic Device Eviction Protocol
 * Guarantees zero residual tokens, zero stuck cookies, and zero cross-tab session locks
 * on shared mobile/desktop devices when switching accounts.
 */
import type { SignOutOptions } from '../types';
export interface AtomicSignOutParams extends SignOutOptions {
    authUrl: string;
    tenantId: string;
    storagePrefix?: string;
}
export declare function executeAtomicSignOut(params: AtomicSignOutParams): Promise<void>;

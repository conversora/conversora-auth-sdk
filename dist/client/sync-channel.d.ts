/**
 * Cross-Tab Synchronization Channel
 * Keeps authentication and sign-out state synchronized in real time across browser tabs and workers.
 */
import type { AuthSyncMessage } from '../types';
export declare class AuthSyncChannel {
    private channel;
    private listeners;
    constructor();
    subscribe(listener: (message: AuthSyncMessage) => void): () => void;
    broadcast(message: AuthSyncMessage): void;
    close(): void;
    private notifyListeners;
}
export declare function getAuthSyncChannel(): AuthSyncChannel;
export declare function resetAuthSyncChannel(): void;

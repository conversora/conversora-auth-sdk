/**
 * Cross-Tab Synchronization Channel
 * Keeps authentication and sign-out state synchronized in real time across browser tabs and workers.
 */

import type { AuthSyncMessage } from '../types';

const CHANNEL_NAME = 'conversora_auth_sync';

export class AuthSyncChannel {
  private channel: BroadcastChannel | null = null;
  private listeners = new Set<(message: AuthSyncMessage) => void>();

  constructor() {
    if (typeof BroadcastChannel !== 'undefined') {
      try {
        this.channel = new BroadcastChannel(CHANNEL_NAME);
        if (typeof (this.channel as any).unref === 'function') {
          (this.channel as any).unref();
        }
        this.channel.onmessage = (event) => {
          if (event.data && typeof event.data === 'object' && event.data.type) {
            this.notifyListeners(event.data as AuthSyncMessage);
          }
        };
      } catch {
        this.channel = null;
      }
    }

    // Fallback: Listen to window storage events if in browser
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', (event) => {
        if (event.key === CHANNEL_NAME && event.newValue) {
          try {
            const data = JSON.parse(event.newValue) as AuthSyncMessage;
            this.notifyListeners(data);
          } catch {}
        }
      });
    }
  }

  public subscribe(listener: (message: AuthSyncMessage) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public broadcast(message: AuthSyncMessage): void {
    // Notify in-process / same-tab listeners immediately
    this.notifyListeners(message);

    // Broadcast to other tabs / workers
    if (this.channel) {
      try {
        this.channel.postMessage(message);
      } catch {}
    }

    // Fallback via localStorage write to trigger storage event in other browser tabs
    if (typeof window !== 'undefined' && typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(CHANNEL_NAME, JSON.stringify(message));
      } catch {}
    }
  }

  public close(): void {
    if (this.channel) {
      try {
        this.channel.close();
      } catch {}
      this.channel = null;
    }
    this.listeners.clear();
  }

  private notifyListeners(message: AuthSyncMessage): void {
    for (const listener of this.listeners) {
      try {
        listener(message);
      } catch {}
    }
  }
}

let defaultSyncChannel: AuthSyncChannel | null = null;

export function getAuthSyncChannel(): AuthSyncChannel {
  if (!defaultSyncChannel) {
    defaultSyncChannel = new AuthSyncChannel();
  }
  return defaultSyncChannel;
}

export function resetAuthSyncChannel(): void {
  if (defaultSyncChannel) {
    defaultSyncChannel.close();
    defaultSyncChannel = null;
  }
}

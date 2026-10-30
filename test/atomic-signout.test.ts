import test from 'node:test';
import assert from 'node:assert/strict';
import { executeAtomicSignOut } from '../src/client/atomic-signout';
import { getAuthSyncChannel, resetAuthSyncChannel } from '../src/client/sync-channel';
import { getOrCreateDPoPKeyPair } from '../src/crypto/dpop-keys';
import { idbGet, idbPut, STORE_KEYS, STORE_SESSIONS } from '../src/crypto/idb-store';
import type { AuthSyncMessage } from '../src/types';

test('Atomic SignOut: executes 4-step device eviction cleanly', async () => {
  const tenantId = `test-signout-${Date.now()}`;

  // 1. Setup mock keys and session
  await getOrCreateDPoPKeyPair(tenantId);
  await idbPut(STORE_SESSIONS, {
    tenantId,
    tokenType: 'DPoP',
    accessToken: 'test-token',
    expiresAt: Date.now() + 100000,
    user: { id: 'usr_test', name: 'Tester' },
  });

  // Verify stored
  const beforeKey = await idbGet(STORE_KEYS, tenantId);
  const beforeSession = await idbGet(STORE_SESSIONS, tenantId);
  assert.ok(beforeKey);
  assert.ok(beforeSession);

  // Setup broadcast listener
  let broadcastReceived: AuthSyncMessage | null = null;
  const unsubscribe = getAuthSyncChannel().subscribe((msg) => {
    if (msg.tenantId === tenantId) {
      broadcastReceived = msg;
    }
  });

  // Mock global fetch for server cookie eviction call
  const originalFetch = globalThis.fetch;
  let serverSignOutCalled = false;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const urlStr = input.toString();
    if (urlStr.includes('/api/v1/auth/session/signout') || urlStr.includes('/api/auth/sign-out')) {
      serverSignOutCalled = true;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input, init);
  };

  try {
    await executeAtomicSignOut({
      authUrl: 'https://auth.conversora.io',
      tenantId,
      broadcast: true,
    });

    // Step 1: Server cookie eviction was called
    assert.equal(serverSignOutCalled, true, 'Server signout endpoint must be called');

    // Step 2: IndexedDB purge
    const afterKey = await idbGet(STORE_KEYS, tenantId);
    const afterSession = await idbGet(STORE_SESSIONS, tenantId);
    assert.equal(afterKey, null, 'DPoP key pair must be purged from storage');
    assert.equal(afterSession, null, 'Session must be purged from storage');

    // Step 4: Broadcast received
    assert.ok(broadcastReceived, 'Sync channel must receive eviction message');
    assert.equal((broadcastReceived as any)?.type, 'EVICT_SESSION');
    assert.equal((broadcastReceived as any)?.tenantId, tenantId);
  } finally {
    globalThis.fetch = originalFetch;
    unsubscribe();
    resetAuthSyncChannel();
  }
});

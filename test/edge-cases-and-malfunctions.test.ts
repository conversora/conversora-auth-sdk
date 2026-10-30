import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthClient } from '../src/client/auth-client';
import { executeAtomicSignOut } from '../src/client/atomic-signout';
import { getOrCreateDPoPKeyPair, purgeDPoPKeyPair } from '../src/crypto/dpop-keys';
import { createDPoPProof } from '../src/crypto/dpop-proof';
import { idbGet, idbPut, STORE_KEYS, STORE_SESSIONS } from '../src/crypto/idb-store';
import { resetAuthSyncChannel } from '../src/client/sync-channel';

test('Malfunction Protection: handleDirectToken with malformed / corrupt token fails gracefully', async () => {
  const client = createAuthClient({ tenantId: 'malform-test' });

  // 1. Completely invalid string
  const session1 = await client.handleDirectToken('invalid-garbage-token');
  assert.equal(session1.accessToken, 'invalid-garbage-token');
  assert.equal(session1.user.id, 'usr_unknown');

  // 2. Base64 that is not valid JSON
  const invalidJsonB64 = Buffer.from('{corrupted-json').toString('base64url');
  const session2 = await client.handleDirectToken(`header.${invalidJsonB64}.sig`);
  assert.equal(session2.user.id, 'usr_unknown');

  client.destroy();
});

test('Malfunction Protection: server 500 error during login returns clean error result without throwing', async () => {
  const originalFetch = globalThis.fetch;
  const client = createAuthClient({ authUrl: 'https://auth.conversora.io', tenantId: 'server-err-tenant' });

  globalThis.fetch = async (): Promise<Response> => {
    return new Response(JSON.stringify({ ok: false, error: 'internal_server_error', message: 'D1 timeout' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  try {
    const phoneRes = await client.phone.login({ phone: '+8801700000000', code: '000000' });
    assert.equal(phoneRes.ok, false);
    assert.equal(phoneRes.error, 'internal_server_error');
    assert.equal(phoneRes.message, 'D1 timeout');

    const credRes = await client.credentials.login({ email: 'err@example.com', password: '123' });
    assert.equal(credRes.ok, false);
    assert.equal(credRes.error, 'internal_server_error');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('Malfunction Protection: network connection drop handled cleanly without throwing', async () => {
  const originalFetch = globalThis.fetch;
  const client = createAuthClient({ authUrl: 'https://auth.conversora.io', tenantId: 'net-err-tenant' });

  globalThis.fetch = async (): Promise<Response> => {
    throw new Error('TypeError: Failed to fetch (connection refused)');
  };

  try {
    const res = await client.phone.sendOtp({ phone: '+8801700000000' });
    assert.equal(res.ok, false);
    assert.equal(res.error, 'network_error');
    assert.ok(res.message?.includes('connection refused'));

    const loginRes = await client.credentials.login({ email: 'a@b.com', password: 'pwd' });
    assert.equal(loginRes.ok, false);
    assert.equal(loginRes.error, 'network_error');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('Bug Prevention: expired session in storage is automatically purged on getSession()', async () => {
  const tenantId = `expired-tenant-${Date.now()}`;
  const client = createAuthClient({ tenantId });

  // Mock expired session (expired 10 seconds ago)
  await idbPut(STORE_SESSIONS, {
    tenantId,
    tokenType: 'DPoP',
    accessToken: 'expired-token',
    expiresAt: Date.now() - 10000,
    user: { id: 'usr_expired', name: 'Expired User' },
  });

  // Calling getSession should recognize expiration, trigger signout, and return null
  const session = await client.getSession();
  assert.equal(session, null);

  const user = await client.getUser();
  assert.equal(user, null);

  client.destroy();
});

test('Bug Prevention: cross-tenant isolation guarantees no session leak between merchants', async () => {
  const tenantA = `tenant-a-${Date.now()}`;
  const tenantB = `tenant-b-${Date.now()}`;

  const clientA = createAuthClient({ tenantId: tenantA });
  const clientB = createAuthClient({ tenantId: tenantB });

  // Store session for Tenant A
  await clientA.handleDirectToken('token-a-secret', 3600);

  // Store session for Tenant B
  await clientB.handleDirectToken('token-b-secret', 3600);

  // Verify A has A's session, B has B's session
  const sessionA = await clientA.getSession();
  const sessionB = await clientB.getSession();
  assert.equal(sessionA?.accessToken, 'token-a-secret');
  assert.equal(sessionB?.accessToken, 'token-b-secret');

  // Signing out of Tenant A MUST NOT evict Tenant B
  await clientA.signOut({ broadcast: false });

  const sessionAAfter = await clientA.getSession();
  const sessionBAfter = await clientB.getSession();
  assert.equal(sessionAAfter, null, 'Tenant A session must be evicted');
  assert.equal(sessionBAfter?.accessToken, 'token-b-secret', 'Tenant B session must remain active');

  clientA.destroy();
  clientB.destroy();
  resetAuthSyncChannel();
});

test('Malfunction Protection: atomicSignOut survives network failure during cookie eviction', async () => {
  const originalFetch = globalThis.fetch;
  const tenantId = `offline-signout-${Date.now()}`;

  // Make network throw error (e.g. offline device)
  globalThis.fetch = async (): Promise<Response> => {
    throw new Error('Network offline');
  };

  try {
    // Should NOT throw, but successfully purge local keys and storage
    await executeAtomicSignOut({
      authUrl: 'https://auth.conversora.io',
      tenantId,
      broadcast: false,
    });

    const key = await idbGet(STORE_KEYS, tenantId);
    assert.equal(key, null, 'Local cryptographic keys must be wiped even when offline');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Bug Prevention: concurrent getOrCreateDPoPKeyPair calls return identical keypair', async () => {
  const tenantId = `concurrent-tenant-${Date.now()}`;

  // Fire 5 simultaneous calls
  const results = await Promise.all([
    getOrCreateDPoPKeyPair(tenantId),
    getOrCreateDPoPKeyPair(tenantId),
    getOrCreateDPoPKeyPair(tenantId),
    getOrCreateDPoPKeyPair(tenantId),
    getOrCreateDPoPKeyPair(tenantId),
  ]);

  const firstJkt = results[0]?.jkt;
  assert.ok(firstJkt);
  for (const r of results) {
    assert.equal(r?.jkt, firstJkt, 'All concurrent calls must resolve to the identical DPoP thumbprint');
  }

  await purgeDPoPKeyPair(tenantId);
});

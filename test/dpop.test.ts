import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getOrCreateDPoPKeyPair,
  computeJwkThumbprint,
  purgeDPoPKeyPair,
  isDPoPSupported,
} from '../src/crypto/dpop-keys';
import { createDPoPProof, normalizeDPoPHtu } from '../src/crypto/dpop-proof';
import { base64UrlDecodeToString } from '../src/crypto/base64url';

test('DPoP: runtime support check', () => {
  assert.equal(isDPoPSupported(), true);
});

test('DPoP: normalizeDPoPHtu removes query strings and hashes', () => {
  const raw = 'https://auth.conversora.io/api/v1/auth/phone/login?param=123#fragment';
  const normalized = normalizeDPoPHtu(raw);
  assert.equal(normalized, 'https://auth.conversora.io/api/v1/auth/phone/login');
});

test('DPoP: keypair generation and RFC 7638 thumbprint calculation', async () => {
  const tenantId = `test-tenant-${Date.now()}`;
  const keyRecord = await getOrCreateDPoPKeyPair(tenantId);

  assert.ok(keyRecord, 'Key record should be created');
  assert.equal(keyRecord.tenantId, tenantId);
  assert.equal(keyRecord.jwk.kty, 'EC');
  assert.equal(keyRecord.jwk.crv, 'P-256');
  assert.ok(keyRecord.jwk.x, 'Public key x parameter required');
  assert.ok(keyRecord.jwk.y, 'Public key y parameter required');
  assert.ok(keyRecord.jkt, 'RFC 7638 thumbprint required');

  // Verify thumbprint calculation matches manual RFC 7638 calculation
  const calculatedThumbprint = await computeJwkThumbprint(keyRecord.jwk);
  assert.equal(keyRecord.jkt, calculatedThumbprint);

  // Cached key retrieval
  const cached = await getOrCreateDPoPKeyPair(tenantId);
  assert.equal(cached?.jkt, keyRecord.jkt);

  // Purge
  await purgeDPoPKeyPair(tenantId);
});

test('DPoP: creates valid RFC 9449 proof JWT and verifies cryptographic signature', async () => {
  const tenantId = `test-dpop-${Date.now()}`;
  const keyRecord = await getOrCreateDPoPKeyPair(tenantId);
  assert.ok(keyRecord);

  const targetUrl = 'https://auth.conversora.io/api/v1/checkout/orders';
  const token = 'sample-jwt-access-token';

  const proof = await createDPoPProof({
    method: 'POST',
    url: targetUrl,
    accessToken: token,
    keyPair: keyRecord,
  });

  assert.ok(proof, 'DPoP proof should be generated');
  const parts = proof.split('.');
  assert.equal(parts.length, 3, 'Proof must have header, payload, and signature');

  // Verify Header
  const header = JSON.parse(base64UrlDecodeToString(parts[0]));
  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'ES256');
  assert.equal(header.jwk.kty, 'EC');
  assert.equal(header.jwk.crv, 'P-256');
  assert.equal(header.jwk.x, keyRecord.jwk.x);
  assert.equal(header.jwk.y, keyRecord.jwk.y);

  // Verify Payload
  const payload = JSON.parse(base64UrlDecodeToString(parts[1]));
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, targetUrl);
  assert.ok(payload.jti.startsWith('dpop_'));
  assert.ok(typeof payload.iat === 'number');
  assert.ok(payload.ath, 'Access token hash (ath) should be present');

  // Cryptographically verify signature using Web Crypto
  const rawSig = parts[2].replace(/-/g, '+').replace(/_/g, '/');
  const paddedSig = rawSig + '='.repeat((4 - (rawSig.length % 4)) % 4);
  const sigBytes = Uint8Array.from(Buffer.from(paddedSig, 'base64'));
  const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

  const isValid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    keyRecord.publicKey,
    sigBytes,
    signedData
  );

  assert.equal(isValid, true, 'Cryptographic signature on DPoP proof must be valid');
});

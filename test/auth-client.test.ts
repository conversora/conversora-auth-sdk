import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthClient } from '../src/client/auth-client';
import { stringToBase64Url } from '../src/crypto/base64url';

test('ConversoraAuthClient: generates signin URL with dpop_jkt', async () => {
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId: 'test-store',
    redirectUri: 'https://store.conversora.io/auth/callback',
  });

  const url = await client.getSignInUrl({ storeName: 'My Fashion Store' });
  assert.ok(url.startsWith('https://auth.conversora.io/signin?'));
  assert.ok(url.includes('tenantId=test-store'));
  assert.ok(url.includes('dpop_jkt='));
});

test('ConversoraAuthClient: phone authentication flows', async () => {
  const originalFetch = globalThis.fetch;
  const tenantId = `tenant-phone-${Date.now()}`;
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId,
  });

  // Mock server responses
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();

    if (url.includes('/api/v1/auth/phone/send-otp')) {
      return new Response(JSON.stringify({ ok: true, message: 'OTP sent' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (url.includes('/api/v1/auth/phone/verify')) {
      return new Response(JSON.stringify({ ok: true, message: 'OTP verified' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (url.includes('/api/v1/auth/phone/login')) {
      // Mock JWT token
      const header = stringToBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const payload = stringToBase64Url(JSON.stringify({
        sub: 'usr_phone_123',
        u_name: 'Customer One',
        u_phone: '+8801700000000',
        u_tier: 'standard',
        tenant_id: tenantId,
      }));
      const mockJwt = `${header}.${payload}.mockSignature`;

      // Check for incoming DPoP header
      const dpopHeader = (init?.headers as Record<string, string>)?.[('DPoP')];
      assert.ok(dpopHeader, 'DPoP header should be attached by client');

      return new Response(JSON.stringify({
        ok: true,
        user: { id: 'usr_phone_123', name: 'Customer One', phone: '+8801700000000' },
        token: mockJwt,
        token_type: 'DPoP',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return originalFetch(input, init);
  };

  try {
    // 1. Send OTP
    const sendResult = await client.phone.sendOtp({ phone: '+8801700000000' });
    assert.equal(sendResult.ok, true);

    // 2. Verify OTP
    const verifyResult = await client.phone.verify({ phone: '+8801700000000', code: '123456' });
    assert.equal(verifyResult.ok, true);

    // 3. Login
    const loginResult = await client.phone.login({ phone: '+8801700000000', code: '123456' });
    assert.equal(loginResult.ok, true);
    assert.equal(loginResult.user?.id, 'usr_phone_123');
    assert.equal(loginResult.tokenType, 'DPoP');

    // 4. Session state in client
    const session = await client.getSession();
    assert.ok(session);
    assert.equal(session.user.id, 'usr_phone_123');

    const user = await client.getUser();
    assert.equal(user?.name, 'Customer One');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('ConversoraAuthClient: credentials authentication flow', async () => {
  const originalFetch = globalThis.fetch;
  const tenantId = `tenant-cred-${Date.now()}`;
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId,
  });

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();

    if (url.includes('/api/v1/auth/credential/login')) {
      const header = stringToBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const payload = stringToBase64Url(JSON.stringify({
        sub: 'usr_cred_456',
        u_name: 'Jane Doe',
        u_email: 'jane@example.com',
        tenant_id: tenantId,
      }));
      const mockJwt = `${header}.${payload}.mockSignature`;

      return new Response(JSON.stringify({
        ok: true,
        user: { id: 'usr_cred_456', name: 'Jane Doe', email: 'jane@example.com' },
        token: mockJwt,
        token_type: 'DPoP',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return originalFetch(input, init);
  };

  try {
    const result = await client.credentials.login({ email: 'jane@example.com', password: 'password123' });
    assert.equal(result.ok, true);
    assert.equal(result.user?.email, 'jane@example.com');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('ConversoraAuthClient: authenticated fetch injects DPoP proof and auto signs out on 401', async () => {
  const originalFetch = globalThis.fetch;
  const tenantId = `tenant-fetch-${Date.now()}`;
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId,
  });

  // Hydrate fake token
  await client.handleDirectToken('header.e30.signature', 3600);

  let capturedHeaders: Headers | null = null;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();
    if (url.includes('/api/v1/checkout/cart')) {
      capturedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ cart: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.includes('/api/v1/restricted')) {
      return new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.includes('/api/v1/auth/session/signout') || url.includes('/api/auth/sign-out')) {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    return originalFetch(input, init);
  };

  try {
    const res = await client.fetch('https://auth.conversora.io/api/v1/checkout/cart');
    assert.equal(res.status, 200);
    assert.ok(capturedHeaders);
    assert.ok((capturedHeaders as Headers).get('Authorization')?.includes('Bearer') || (capturedHeaders as Headers).get('Authorization')?.includes('DPoP'));

    // Trigger 401
    const res401 = await client.fetch('https://auth.conversora.io/api/v1/restricted');
    assert.equal(res401.status, 401);

    // Should have automatically signed out
    const session = await client.getSession();
    assert.equal(session, null, 'Session must be evicted on 401 Unauthorized');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('ConversoraAuthClient: password recovery flows & URL generator', async () => {
  const originalFetch = globalThis.fetch;
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId: 'test-store',
    redirectUri: 'https://store.conversora.io/account',
  });

  const forgotUrl = client.getForgotPasswordUrl({ method: 'phone' });
  assert.ok(forgotUrl.includes('/forgot-password?method=phone'));
  assert.ok(forgotUrl.includes('tenantId=test-store'));

  // Test urlMode: 'path'
  const pathClient = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId: 'velvet-boutique',
    redirectUri: 'https://velvetboutique.com/account',
    urlMode: 'path',
  });

  const pathSignInUrl = await pathClient.getSignInUrl();
  assert.ok(pathSignInUrl.startsWith('https://auth.conversora.io/s/velvet-boutique/signin?callbackURL='));
  assert.ok(pathSignInUrl.includes('callbackURL=https%3A%2F%2Fvelvetboutique.com%2Faccount'));

  const pathForgotUrl = pathClient.getForgotPasswordUrl({ method: 'email' });
  assert.ok(pathForgotUrl.startsWith('https://auth.conversora.io/s/velvet-boutique/forgot-password?method=email'));
  assert.ok(pathForgotUrl.includes('callbackURL=https%3A%2F%2Fvelvetboutique.com%2Faccount'));

  // Test per-call override
  const querySignInUrl = await pathClient.getSignInUrl({ urlMode: 'query' });
  assert.ok(querySignInUrl.startsWith('https://auth.conversora.io/signin?'));
  assert.ok(querySignInUrl.includes('tenantId=velvet-boutique'));

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();

    if (url.includes('/api/v1/auth/password/forgot')) {
      const body = JSON.parse((init?.body as string) || '{}');
      if (body.email === 'user@example.com') {
        return new Response(JSON.stringify({ ok: true, channel: 'email', message: 'Reset link sent' }), { status: 200 });
      }
      if (body.phone === '+8801700000000') {
        return new Response(JSON.stringify({ ok: true, channel: 'phone', message: 'SMS OTP sent' }), { status: 200 });
      }
    }

    if (url.includes('/api/v1/auth/password/reset')) {
      const body = JSON.parse((init?.body as string) || '{}');
      if (body.newPassword && (body.token || body.code)) {
        return new Response(JSON.stringify({ ok: true, message: 'Password reset successfully' }), { status: 200 });
      }
    }

    return originalFetch(input, init);
  };

  try {
    // 1. Forgot with email
    const emailRes = await client.password.forgot({ email: 'user@example.com' });
    assert.equal(emailRes.ok, true);
    assert.equal(emailRes.data?.channel, 'email');

    // 2. Forgot with phone
    const phoneRes = await client.password.forgot({ phone: '+8801700000000' });
    assert.equal(phoneRes.ok, true);
    assert.equal(phoneRes.data?.channel, 'phone');

    // 3. Reset password
    const resetRes = await client.password.reset({
      phone: '+8801700000000',
      code: '123456',
      newPassword: 'NewPassword123!',
    });
    assert.equal(resetRes.ok, true);
    assert.equal(resetRes.message, 'Password reset successfully');
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('ConversoraAuthClient: account profile and address book methods', async () => {
  const originalFetch = globalThis.fetch;
  const tenantId = `tenant-account-${Date.now()}`;
  const client = createAuthClient({
    authUrl: 'https://auth.conversora.io',
    tenantId,
  });

  const mockAddress = {
    id: 'addr_123',
    recipientName: 'Solaman Shuvo',
    phoneNumber: '+8801700000000',
    division: 'Dhaka',
    district: 'Dhaka',
    thana: 'Dhanmondi',
    addressLine1: 'Road 9/A',
    postalCode: '1209',
    country: 'Bangladesh',
    isDefault: true,
  };

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();

    if (url.includes('/api/v1/account/profile')) {
      if (init?.method === 'PUT') {
        const body = JSON.parse((init.body as string) || '{}');
        return new Response(JSON.stringify({ ok: true, profile: { id: 'usr_123', name: body.name } }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: 'usr_123', name: 'Solaman Shuvo', email: 'shuvo@conversora.io' }), { status: 200 });
    }

    if (url.includes('/api/v1/account/addresses')) {
      if (init?.method === 'POST') {
        const body = JSON.parse((init.body as string) || '{}');
        return new Response(JSON.stringify({ ok: true, address: { id: 'addr_new', ...body } }), { status: 200 });
      }
      return new Response(JSON.stringify([mockAddress]), { status: 200 });
    }

    if (url.includes('/api/v1/store/auth-config')) {
      return new Response(
        JSON.stringify({
          storeSlug: 'booksmuggler',
          methods: { phoneOtp: { enabled: true }, emailPassword: { enabled: true } },
        }),
        { status: 200 }
      );
    }

    return originalFetch(input, init);
  };

  try {
    // 1. Get profile
    const profile = await client.account.getProfile();
    assert.ok(profile);
    assert.equal(profile.name, 'Solaman Shuvo');

    // 2. Update profile
    const updateRes = await client.account.updateProfile({ name: 'Solaman Updated' });
    assert.equal(updateRes.ok, true);

    // 3. List addresses
    const addresses = await client.account.listAddresses();
    assert.equal(addresses.length, 1);
    assert.equal(addresses[0].division, 'Dhaka');

    // 4. Create address
    const createRes = await client.account.createAddress({
      recipientName: 'Solaman Shuvo',
      phoneNumber: '+8801700000000',
      division: 'Dhaka',
      district: 'Dhaka',
      thana: 'Gulshan',
      addressLine1: 'Road 11',
    });
    assert.equal(createRes.ok, true);

    // 5. Store config
    const config = await client.store.getConfig('booksmuggler');
    assert.ok(config);
    assert.equal(config.methods.phoneOtp.enabled, true);
  } finally {
    globalThis.fetch = originalFetch;
    client.destroy();
  }
});

test('ConversoraAuthClient: offline mockMode for template cloning', async () => {
  const mockClient = createAuthClient({
    mockMode: true,
    tenantId: 'booksmuggler',
  });

  try {
    const profile = await mockClient.account.getProfile();
    assert.ok(profile);
    assert.equal(profile.id, 'usr_mock_shopper');

    const addresses = await mockClient.account.listAddresses();
    assert.ok(addresses.length >= 2);
    assert.equal(addresses[0].country, 'Bangladesh');

    const config = await mockClient.store.getConfig('booksmuggler');
    assert.ok(config);
    assert.equal(config.methods.phoneOtp.enabled, true);
  } finally {
    mockClient.destroy();
  }
});

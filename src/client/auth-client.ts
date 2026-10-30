/**
 * Conversora Universal Stateless Authentication Client
 * Pure TypeScript, zero-dependency, hardware-bound DPoP authentication with 4-step atomic wipe.
 */

import type {
  User,
  AuthSession,
  AuthClientOptions,
  AuthResult,
  PhoneSendOtpOptions,
  PhoneVerifyOtpOptions,
  PhoneLoginOptions,
  CredentialLoginOptions,
  CredentialRegisterOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  SignOutOptions,
  StoredKeyPair,
  CustomerProfile,
  UpdateProfileInput,
  CustomerAddress,
  CreateAddressInput,
  UpdateAddressInput,
  StoreAuthConfig,
} from '../types';
import { base64UrlEncode, base64UrlDecodeToString } from '../crypto/base64url';
import { getOrCreateDPoPKeyPair, isDPoPSupported } from '../crypto/dpop-keys';
import { createDPoPProof } from '../crypto/dpop-proof';
import { idbGet, idbPut, STORE_SESSIONS } from '../crypto/idb-store';
import { executeAtomicSignOut } from './atomic-signout';
import { getAuthSyncChannel } from './sync-channel';

export class ConversoraAuthClient {
  public readonly authUrl: string;
  public readonly tenantId: string;
  public readonly redirectUri: string;
  public readonly dpopEnabled: boolean;
  public readonly storagePrefix: string;
  public readonly urlMode: 'query' | 'path';
  public readonly mockMode: boolean;
  private readonly listeners = new Set<(user: User | null, session: AuthSession | null) => void>();
  private currentSession: AuthSession | null = null;
  private syncUnsubscribe: (() => void) | null = null;

  constructor(options: AuthClientOptions = {}) {
    this.authUrl = (options.authUrl || (typeof window !== 'undefined' ? window.location.origin : 'https://auth.conversora.io')).replace(/\/+$/, '');
    this.tenantId = options.tenantId || 'default';
    this.redirectUri = options.redirectUri || (typeof window !== 'undefined' ? `${window.location.origin}/auth/callback` : '');
    this.dpopEnabled = options.dpopEnabled ?? true;
    this.storagePrefix = options.storagePrefix || 'conversora_auth';
    this.urlMode = options.urlMode || 'query';
    this.mockMode = options.mockMode ?? false;

    if (options.onAuthStateChange) {
      this.listeners.add(options.onAuthStateChange);
    }

    if (options.autoSyncAcrossTabs !== false) {
      this.setupSyncListener();
    }

    // Hydrate cached session if in browser
    if (typeof window !== 'undefined') {
      this.getSession().catch(() => {});
    }
  }

  /**
   * Phone Authentication Subsystem
   */
  public phone = {
    sendOtp: async (opts: PhoneSendOtpOptions): Promise<AuthResult> => {
      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        const res = await fetch(`${this.authUrl}/api/v1/auth/phone/send-otp`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            phone: opts.phone,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    verify: async (opts: PhoneVerifyOtpOptions): Promise<AuthResult> => {
      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        const res = await fetch(`${this.authUrl}/api/v1/auth/phone/verify`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            ...opts,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    login: async (opts: PhoneLoginOptions): Promise<AuthResult> => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/phone/login`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: 'POST', url: targetUrl, tenantId: this.tenantId });
          if (proof) headers['DPoP'] = proof;
        }

        const res = await fetch(targetUrl, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({
            ...opts,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || 'auth_failed',
            message: data.message || 'Phone verification failed',
          };
        }

        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },
  };

  /**
   * Credentials (Email & Password) Authentication Subsystem
   */
  public credentials = {
    login: async (opts: CredentialLoginOptions): Promise<AuthResult> => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/credential/login`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: 'POST', url: targetUrl, tenantId: this.tenantId });
          if (proof) headers['DPoP'] = proof;
        }

        const res = await fetch(targetUrl, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({
            ...opts,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || 'login_failed',
            message: data.message || 'Invalid email or password',
          };
        }

        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    register: async (opts: CredentialRegisterOptions): Promise<AuthResult> => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/credential/register`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: 'POST', url: targetUrl, tenantId: this.tenantId });
          if (proof) headers['DPoP'] = proof;
        }

        const res = await fetch(targetUrl, {
          method: 'POST',
          headers,
          credentials: 'include',
          body: JSON.stringify({
            ...opts,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || 'registration_failed',
            message: data.message || 'Could not register account',
          };
        }

        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },
  };

  /**
   * Password Recovery Subsystem
   */
  public password = {
    forgot: async (opts: ForgotPasswordOptions): Promise<AuthResult> => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/password/forgot`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        const res = await fetch(targetUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            ...(opts.email ? { email: opts.email } : {}),
            ...(opts.phone ? { phone: opts.phone } : {}),
            ...(opts.callbackURL ? { callbackURL: opts.callbackURL } : {}),
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    reset: async (opts: ResetPasswordOptions): Promise<AuthResult> => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/password/reset`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };
        if (opts.turnstileToken) {
          headers['cf-turnstile-response'] = opts.turnstileToken;
        }

        const res = await fetch(targetUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            ...(opts.token ? { token: opts.token } : {}),
            ...(opts.phone ? { phone: opts.phone } : {}),
            ...(opts.code ? { code: opts.code } : {}),
            newPassword: opts.newPassword,
            ...(opts.turnstileToken ? { 'cf-turnstile-response': opts.turnstileToken } : {}),
          }),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },
  };

  /**
   * Customer Account & Profile Subsystem (RFC 9449 DPoP Authenticated)
   */
  public account = {
    getProfile: async (): Promise<CustomerProfile | null> => {
      if (this.mockMode) {
        return {
          id: 'usr_mock_shopper',
          name: 'Solaman Shuvo',
          email: 'shopper@conversora.io',
          phone: '+8801700000000',
          points: 320,
          tier: 'Gold Patron',
          addresses: await this.account.listAddresses(),
        };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/profile`);
        if (!res.ok) return null;
        const data = await res.json().catch(() => null);
        return data;
      } catch {
        return null;
      }
    },

    updateProfile: async (input: UpdateProfileInput): Promise<AuthResult<CustomerProfile>> => {
      if (this.mockMode) {
        return {
          ok: true,
          data: {
            id: 'usr_mock_shopper',
            name: input.name || 'Solaman Shuvo',
            email: input.email || 'shopper@conversora.io',
            phone: input.phone || '+8801700000000',
            avatarUrl: input.avatarUrl,
          },
        };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/profile`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    listAddresses: async (): Promise<CustomerAddress[]> => {
      if (this.mockMode) {
        return [
          {
            id: 'addr_mock_1',
            recipientName: 'Solaman Shuvo',
            phoneNumber: '+8801700000000',
            division: 'Dhaka',
            district: 'Dhaka',
            thana: 'Dhanmondi',
            addressLine1: 'House 42, Road 9/A',
            postalCode: '1209',
            country: 'Bangladesh',
            isDefault: true,
            createdAt: Date.now(),
          },
          {
            id: 'addr_mock_2',
            recipientName: 'Solaman Shuvo',
            phoneNumber: '+8801700000000',
            division: 'Dhaka',
            district: 'Dhaka',
            thana: 'Gulshan',
            addressLine1: 'Avenue 2, Block D',
            postalCode: '1212',
            country: 'Bangladesh',
            isDefault: false,
            createdAt: Date.now() - 86400000,
          },
        ];
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses`);
        if (!res.ok) return [];
        const data = await res.json().catch(() => []);
        return Array.isArray(data) ? data : data.addresses || [];
      } catch {
        return [];
      }
    },

    createAddress: async (input: CreateAddressInput): Promise<AuthResult<CustomerAddress>> => {
      if (this.mockMode) {
        const newAddress: CustomerAddress = {
          id: `addr_mock_${Date.now()}`,
          recipientName: input.recipientName,
          phoneNumber: input.phoneNumber,
          division: input.division,
          district: input.district,
          thana: input.thana,
          addressLine1: input.addressLine1,
          addressLine2: input.addressLine2,
          postalCode: input.postalCode || '',
          country: input.country || 'Bangladesh',
          isDefault: input.isDefault ?? false,
          createdAt: Date.now(),
        };
        return { ok: true, data: newAddress };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    updateAddress: async (id: string, input: UpdateAddressInput): Promise<AuthResult<CustomerAddress>> => {
      if (this.mockMode) {
        return {
          ok: true,
          data: {
            id,
            recipientName: input.recipientName || 'Solaman Shuvo',
            phoneNumber: input.phoneNumber || '+8801700000000',
            division: input.division || 'Dhaka',
            district: input.district || 'Dhaka',
            thana: input.thana || 'Dhanmondi',
            addressLine1: input.addressLine1 || 'House 42, Road 9/A',
            addressLine2: input.addressLine2,
            postalCode: input.postalCode || '1209',
            country: input.country || 'Bangladesh',
            isDefault: input.isDefault ?? false,
          },
        };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    deleteAddress: async (id: string): Promise<AuthResult> => {
      if (this.mockMode) {
        return { ok: true, message: 'Address removed successfully' };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}`, {
          method: 'DELETE',
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    setDefaultAddress: async (id: string): Promise<AuthResult> => {
      if (this.mockMode) {
        return { ok: true, message: 'Default address updated' };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}/default`, {
          method: 'POST',
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },

    changePassword: async (currentPassword: string, newPassword: string): Promise<AuthResult> => {
      if (this.mockMode) {
        return { ok: true, message: 'Password updated successfully' };
      }

      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ currentPassword, newPassword }),
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data,
        };
      } catch (err: any) {
        return { ok: false, error: 'network_error', message: err.message };
      }
    },
  };

  /**
   * Merchant Store Auth Configuration Subsystem
   */
  public store = {
    getConfig: async (storeSlug?: string): Promise<StoreAuthConfig | null> => {
      const slug = storeSlug || this.tenantId;
      if (this.mockMode) {
        return {
          storeSlug: slug,
          methods: {
            phoneOtp: { enabled: true, autoRegister: true },
            emailPassword: { enabled: true, allowRegistration: true },
          },
        };
      }

      try {
        const res = await fetch(`${this.authUrl}/api/v1/store/auth-config?store=${encodeURIComponent(slug)}`);
        if (!res.ok) return null;
        return await res.json().catch(() => null);
      } catch {
        return null;
      }
    },
  };

  /**
   * Alias for fetch() which automatically signs and attaches RFC 9449 DPoP proofs
   */
  public fetchWithDPoP = this.fetch.bind(this);

  /**
   * Retrieves active session from memory or IndexedDB
   */
  public async getSession(): Promise<AuthSession | null> {
    if (this.currentSession) {
      if (Date.now() < this.currentSession.expiresAt) {
        return this.currentSession;
      }
      // Expired
      await this.signOut({ broadcast: true });
      return null;
    }

    try {
      const stored = await idbGet<AuthSession & { tenantId: string }>(STORE_SESSIONS, this.tenantId);
      if (stored) {
        if (Date.now() < stored.expiresAt) {
          this.currentSession = stored;
          this.notifyListeners(stored.user, stored);
          return stored;
        }
        await this.signOut({ broadcast: true });
      }
    } catch {}

    return null;
  }

  /**
   * Retrieves authenticated user or null
   */
  public async getUser(): Promise<User | null> {
    const session = await this.getSession();
    return session ? session.user : null;
  }

  /**
   * Generates central signin redirect URL with hardware dpop_jkt thumbprint
   */
  public async getSignInUrl(options: {
    returnPath?: string;
    storeName?: string;
    urlMode?: 'query' | 'path';
  } = {}): Promise<string> {
    const rawStore = options.storeName || this.tenantId;
    const mode = options.urlMode || this.urlMode || 'query';
    const callbackUrl = encodeURIComponent(this.redirectUri);
    const store = encodeURIComponent(rawStore);
    const origin = typeof window !== 'undefined' ? encodeURIComponent(window.location.origin) : '';

    let dpopJkt = '';
    if (this.dpopEnabled && isDPoPSupported()) {
      const keyRecord = await getOrCreateDPoPKeyPair(this.tenantId);
      if (keyRecord) dpopJkt = keyRecord.jkt;
    }

    let url = '';
    if (mode === 'path' && rawStore && rawStore !== 'default' && rawStore !== 'conversora') {
      url = `${this.authUrl}/s/${store}/signin?callbackURL=${callbackUrl}`;
      if (origin) url += `&origin=${origin}`;
    } else {
      url = `${this.authUrl}/signin?origin=${origin}&callbackURL=${callbackUrl}&store=${store}&tenantId=${encodeURIComponent(this.tenantId)}`;
    }

    if (dpopJkt) {
      url += `&dpop_jkt=${encodeURIComponent(dpopJkt)}`;
    }
    if (options.returnPath) {
      url += `&returnPath=${encodeURIComponent(options.returnPath)}`;
    }
    return url;
  }

  /**
   * Generates central forgot-password redirect URL
   */
  public getForgotPasswordUrl(options: {
    method?: 'email' | 'phone';
    callbackURL?: string;
    storeName?: string;
    urlMode?: 'query' | 'path';
  } = {}): string {
    const rawStore = options.storeName || this.tenantId;
    const mode = options.urlMode || this.urlMode || 'query';
    const callbackUrl = encodeURIComponent(options.callbackURL || this.redirectUri);
    const method = options.method || 'email';

    if (mode === 'path' && rawStore && rawStore !== 'default' && rawStore !== 'conversora') {
      return `${this.authUrl}/s/${encodeURIComponent(rawStore)}/forgot-password?method=${method}&callbackURL=${callbackUrl}`;
    }

    return `${this.authUrl}/forgot-password?method=${method}&callbackURL=${callbackUrl}&tenantId=${encodeURIComponent(this.tenantId)}`;
  }

  /**
   * Generates OAuth 2.1 PKCE authorization code URL
   */
  public async createAuthorizationUrl(options: { returnPath?: string } = {}): Promise<string> {
    let dpopJkt = '';
    if (this.dpopEnabled && isDPoPSupported()) {
      const keyRecord = await getOrCreateDPoPKeyPair(this.tenantId);
      if (keyRecord) dpopJkt = keyRecord.jkt;
    }

    // Generate PKCE code verifier and challenge
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const codeVerifier = base64UrlEncode(verifierBytes);

    const challengeBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = base64UrlEncode(challengeBuffer);

    const stateObj = {
      csrf: base64UrlEncode(crypto.getRandomValues(new Uint8Array(16))),
      returnPath: options.returnPath || '/',
    };
    const state = base64UrlEncode(new TextEncoder().encode(JSON.stringify(stateObj)));

    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(`${this.storagePrefix}_pkce_${this.tenantId}`, JSON.stringify({
        codeVerifier,
        state,
        createdAt: Date.now(),
      }));
    }

    const url = new URL(`${this.authUrl}/authorize`);
    url.searchParams.set('client_id', this.tenantId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('state', state);
    if (dpopJkt) url.searchParams.set('dpop_jkt', dpopJkt);

    return url.toString();
  }

  /**
   * Ingests direct token (e.g. from redirect hash fragment #access_token=...)
   */
  public async handleDirectToken(accessToken: string, expiresIn = 2592000): Promise<AuthSession> {
    const claims = this.decodeJwtClaims(accessToken);
    const isDPoP = claims.cnf && claims.cnf.jkt;

    const user: User = {
      id: claims.sub || 'usr_unknown',
      name: claims.u_name || claims.name || 'Patron',
      email: claims.email || claims.u_email || claims.u_email_masked || null,
      phone: claims.phone || claims.u_phone || null,
      tier: claims.u_tier || 'standard',
      currency: claims.u_curr || 'BDT',
      tenantId: claims.tenant_id || this.tenantId,
      points: claims.u_pts || 0,
    };

    const session: AuthSession = {
      tokenType: isDPoP ? 'DPoP' : 'Bearer',
      accessToken,
      expiresAt: Date.now() + expiresIn * 1000,
      scope: claims.scope || 'default',
      user,
      dpopJkt: claims.cnf?.jkt,
    };

    this.currentSession = session;
    await idbPut(STORE_SESSIONS, {
      ...session,
      tenantId: this.tenantId,
    });

    getAuthSyncChannel().broadcast({
      type: 'SIGN_IN',
      tenantId: this.tenantId,
      user,
      timestamp: Date.now(),
    });

    this.notifyListeners(user, session);
    return session;
  }

  /**
   * Exchanges an authorization code for 30-day DPoP token
   */
  public async handleCallback(code: string, state?: string | null): Promise<AuthSession> {
    let codeVerifier = '';
    if (state && typeof sessionStorage !== 'undefined') {
      const saved = sessionStorage.getItem(`${this.storagePrefix}_pkce_${this.tenantId}`);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed.state === state) codeVerifier = parsed.codeVerifier;
        } catch {}
        sessionStorage.removeItem(`${this.storagePrefix}_pkce_${this.tenantId}`);
      }
    }

    const tokenUrl = `${this.authUrl}/oauth/token`;
    const cleanCode = code.split('.')[0] || '';

    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: cleanCode,
      redirect_uri: this.redirectUri,
      client_id: this.tenantId,
    });
    if (codeVerifier) bodyParams.set('code_verifier', codeVerifier);

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };

    if (this.dpopEnabled && isDPoPSupported()) {
      const proof = await createDPoPProof({ method: 'POST', url: tokenUrl, tenantId: this.tenantId });
      if (proof) headers['DPoP'] = proof;
    }

    const res = await fetch(tokenUrl, {
      method: 'POST',
      headers,
      body: bodyParams.toString(),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Token exchange failed (${res.status}): ${err}`);
    }

    const data = await res.json();
    return this.saveSessionFromResponse(data);
  }

  /**
   * Authenticated fetch helper: Automatically attaches Authorization and RFC 9449 DPoP proof
   * Automatically executes atomic device eviction on 401 Unauthorized responses.
   */
  public async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const session = await this.getSession();
    const headers = new Headers(init.headers || {});

    if (session) {
      const method = (init.method || 'GET').toUpperCase();
      if (session.tokenType === 'DPoP' && this.dpopEnabled && isDPoPSupported()) {
        headers.set('Authorization', `DPoP ${session.accessToken}`);
        const proof = await createDPoPProof({
          method,
          url,
          accessToken: session.accessToken,
          tenantId: this.tenantId,
        });
        if (proof) headers.set('DPoP', proof);
      } else {
        headers.set('Authorization', `Bearer ${session.accessToken}`);
      }
    }

    const res = await fetch(url, {
      ...init,
      headers,
    });

    if (res.status === 401) {
      await this.signOut({ broadcast: true });
    }

    return res;
  }

  /**
   * Executes 4-Step Atomic Device Eviction
   */
  public async signOut(options: SignOutOptions = {}): Promise<void> {
    this.currentSession = null;
    this.notifyListeners(null, null);

    await executeAtomicSignOut({
      authUrl: this.authUrl,
      tenantId: this.tenantId,
      storagePrefix: this.storagePrefix,
      redirectUrl: options.redirectUrl,
      broadcast: options.broadcast ?? true,
    });
  }

  /**
   * Subscribe to authentication state changes
   */
  public onAuthStateChange(listener: (user: User | null, session: AuthSession | null) => void): () => void {
    this.listeners.add(listener);
    // Send immediate snapshot
    if (this.currentSession) {
      listener(this.currentSession.user, this.currentSession);
    }
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Disposes background event listeners
   */
  public destroy(): void {
    if (this.syncUnsubscribe) {
      this.syncUnsubscribe();
      this.syncUnsubscribe = null;
    }
    this.listeners.clear();
  }

  // --- Private Helpers ---

  private setupSyncListener(): void {
    const channel = getAuthSyncChannel();
    this.syncUnsubscribe = channel.subscribe((msg) => {
      if (msg.tenantId !== this.tenantId) return;

      if (msg.type === 'EVICT_SESSION') {
        this.currentSession = null;
        this.notifyListeners(null, null);
      } else if (msg.type === 'SIGN_IN') {
        // Re-read fresh session from storage
        this.getSession().catch(() => {});
      }
    });
  }

  private notifyListeners(user: User | null, session: AuthSession | null): void {
    for (const listener of this.listeners) {
      try {
        listener(user, session);
      } catch {}
    }
  }

  private async saveSessionFromResponse(data: any): Promise<AuthSession> {
    const accessToken = data.token || data.access_token || '';
    const claims = accessToken ? this.decodeJwtClaims(accessToken) : {};
    const tokenType = data.token_type === 'DPoP' || claims.cnf?.jkt ? 'DPoP' : 'Bearer';
    const expiresIn = data.expires_in || 2592000; // 30 days default

    const user: User = {
      id: data.user?.id || claims.sub || 'usr_unknown',
      name: data.user?.name || claims.u_name || claims.name || 'Patron',
      email: data.user?.email || claims.email || claims.u_email || null,
      phone: data.user?.phone || claims.phone || claims.u_phone || null,
      role: data.user?.role || claims.role,
      image: data.user?.image || claims.image || null,
      emailVerified: data.user?.emailVerified ?? false,
      phoneVerified: data.user?.phoneVerified ?? false,
      tier: claims.u_tier || 'standard',
      currency: claims.u_curr || 'BDT',
      tenantId: this.tenantId,
      points: claims.u_pts || 0,
    };

    const session: AuthSession = {
      tokenType,
      accessToken,
      expiresAt: Date.now() + expiresIn * 1000,
      scope: data.scope || claims.scope || 'default',
      user,
      dpopJkt: claims.cnf?.jkt,
    };

    this.currentSession = session;
    await idbPut(STORE_SESSIONS, {
      ...session,
      tenantId: this.tenantId,
    });

    getAuthSyncChannel().broadcast({
      type: 'SIGN_IN',
      tenantId: this.tenantId,
      user,
      timestamp: Date.now(),
    });

    this.notifyListeners(user, session);
    return session;
  }

  private decodeJwtClaims(jwt: string): Record<string, any> {
    try {
      const parts = jwt.split('.');
      if (parts.length >= 2 && parts[1]) {
        return JSON.parse(base64UrlDecodeToString(parts[1]));
      }
    } catch {}
    return {};
  }
}

/**
 * Factory helper for initializing client instance
 */
export function createAuthClient(options: AuthClientOptions = {}): ConversoraAuthClient {
  return new ConversoraAuthClient(options);
}

/**
 * Core types for conversora-auth-sdk
 */

export interface User {
  id: string;
  name?: string | null;
  email?: string | null;
  phone?: string | null;
  role?: string;
  image?: string | null;
  emailVerified?: boolean;
  phoneVerified?: boolean;
  tier?: string;
  currency?: string;
  tenantId?: string;
  points?: number;
  createdAt?: string | number;
  updatedAt?: string | number;
}

export interface TenantContext {
  tenantId?: string;
  storeId?: string;
  domain?: string;
}

export interface AuthSession {
  tokenType: 'DPoP' | 'Bearer';
  accessToken: string;
  expiresAt: number; // Epoch ms
  scope?: string;
  user: User;
  dpopJkt?: string;
}

export interface StoredKeyPair {
  tenantId: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: JsonWebKey;
  jkt: string; // RFC 7638 SHA-256 base64url thumbprint
  createdAt: number;
}

export interface AuthClientOptions {
  /**
   * Central Auth Server URL.
   * Defaults to 'https://auth.conversora.io' (or window.location.origin if self-hosted)
   */
  authUrl?: string;

  /**
   * Tenant/Merchant ID (e.g., 'store-123', 'maison')
   * Scopes cryptographic DPoP keypairs and storage isolation.
   */
  tenantId?: string;

  /**
   * OAuth Callback URL (defaults to window.location.origin + '/auth/callback')
   */
  redirectUri?: string;

  /**
   * Whether to enable RFC 9449 DPoP key generation.
   * If true (default), attempts Web Crypto ECDSA P-256 key generation.
   * Falls back gracefully to Bearer if unsupported.
   */
  dpopEnabled?: boolean;

  /**
   * Custom storage key prefix (defaults to 'conversora_auth')
   */
  storagePrefix?: string;

  /**
   * Whether to synchronize sign-in / sign-out across browser tabs via BroadcastChannel.
   * Defaults to true.
   */
  autoSyncAcrossTabs?: boolean;

  /**
   * Callback fired when authentication state changes.
   */
  onAuthStateChange?: (user: User | null, session: AuthSession | null) => void;

  /**
   * URL Generation Mode:
   * - 'query' (Default): Emits /signin?shop=:tenantId (100% backward compatible)
   * - 'path' (Opt-In): Emits /s/:tenantId/signin (Canonical branded clean URLs)
   */
  urlMode?: 'query' | 'path';

  /**
   * Offline Zero-Database Preview Mock Mode.
   * If true, auth.account and auth.phone return realistic fixtures with zero network calls.
   * Perfect for rapid template cloning and offline frontend development.
   */
  mockMode?: boolean;
}

export interface CustomerAddress {
  id: string;
  recipientName: string;
  phoneNumber: string;
  division: string;
  district: string;
  thana: string;
  addressLine1: string;
  addressLine2?: string;
  postalCode?: string;
  country: string;
  isDefault: boolean;
  createdAt?: string | number;
}

export interface CreateAddressInput {
  recipientName: string;
  phoneNumber: string;
  division: string;
  district: string;
  thana: string;
  addressLine1: string;
  addressLine2?: string;
  postalCode?: string;
  country?: string;
  isDefault?: boolean;
}

export type UpdateAddressInput = Partial<CreateAddressInput>;

export interface CustomerProfile {
  id: string;
  name?: string;
  email?: string;
  phone?: string;
  avatarUrl?: string;
  points?: number;
  tier?: string;
  addresses?: CustomerAddress[];
}

export interface UpdateProfileInput {
  name?: string;
  email?: string;
  phone?: string;
  avatarUrl?: string;
}

export interface StoreAuthConfig {
  storeSlug: string;
  methods: {
    phoneOtp: {
      enabled: boolean;
      autoRegister?: boolean;
    };
    emailPassword: {
      enabled: boolean;
      allowRegistration?: boolean;
    };
    social?: Record<string, boolean>;
  };
}

export interface AuthResult<T = any> {
  ok: boolean;
  user?: User | null;
  token?: string | null;
  tokenType?: 'DPoP' | 'Bearer';
  error?: string;
  message?: string;
  data?: T;
}

export interface PhoneSendOtpOptions {
  phone: string;
  turnstileToken?: string;
}

export interface PhoneVerifyOtpOptions {
  phone?: string;
  code: string;
  turnstileToken?: string;
}

export interface PhoneLoginOptions {
  phone: string;
  code: string;
  turnstileToken?: string;
}

export interface CredentialLoginOptions {
  email: string;
  password: string;
  turnstileToken?: string;
}

export interface CredentialRegisterOptions {
  email: string;
  password: string;
  name?: string;
  turnstileToken?: string;
}

export interface ForgotPasswordOptions {
  email?: string;
  phone?: string;
  turnstileToken?: string;
  callbackURL?: string;
}

export interface ResetPasswordOptions {
  token?: string;
  phone?: string;
  code?: string;
  newPassword: string;
  turnstileToken?: string;
}

export interface SignOutOptions {
  /**
   * Optional URL to redirect to after complete atomic eviction
   */
  redirectUrl?: string;

  /**
   * Whether to broadcast eviction across all open browser tabs
   * Defaults to true.
   */
  broadcast?: boolean;
}

export type AuthSyncMessage =
  | { type: 'SIGN_IN'; tenantId: string; user: User; timestamp: number }
  | { type: 'EVICT_SESSION'; tenantId: string; timestamp: number };

/**
 * conversora-auth-sdk
 * Universal, zero-dependency stateless DPoP authentication client with atomic multi-account wipe.
 */
export { ConversoraAuthClient, createAuthClient } from './client/auth-client';
export { executeAtomicSignOut, type AtomicSignOutParams } from './client/atomic-signout';
export { getAuthSyncChannel, AuthSyncChannel } from './client/sync-channel';
export { getOrCreateDPoPKeyPair, purgeDPoPKeyPair, isDPoPSupported, computeJwkThumbprint, } from './crypto/dpop-keys';
export { createDPoPProof, normalizeDPoPHtu, type CreateDPoPProofOptions, } from './crypto/dpop-proof';
export { base64UrlEncode, stringToBase64Url, base64UrlDecodeToString, } from './crypto/base64url';
export { openAuthDatabase, idbGet, idbPut, idbDelete, idbClearAll, } from './crypto/idb-store';
export type { User, TenantContext, AuthSession, StoredKeyPair, AuthClientOptions, AuthResult, PhoneSendOtpOptions, PhoneVerifyOtpOptions, PhoneLoginOptions, CredentialLoginOptions, CredentialRegisterOptions, ForgotPasswordOptions, ResetPasswordOptions, SignOutOptions, AuthSyncMessage, CustomerAddress, CreateAddressInput, UpdateAddressInput, CustomerProfile, UpdateProfileInput, StoreAuthConfig, } from './types';

/**
 * Conversora Universal Stateless Authentication Client
 * Pure TypeScript, zero-dependency, hardware-bound DPoP authentication with 4-step atomic wipe.
 */
import type { User, AuthSession, AuthClientOptions, AuthResult, PhoneSendOtpOptions, PhoneVerifyOtpOptions, PhoneLoginOptions, CredentialLoginOptions, CredentialRegisterOptions, ForgotPasswordOptions, ResetPasswordOptions, SignOutOptions, CustomerProfile, UpdateProfileInput, CustomerAddress, CreateAddressInput, UpdateAddressInput, StoreAuthConfig } from '../types';
export declare class ConversoraAuthClient {
    readonly authUrl: string;
    readonly tenantId: string;
    readonly redirectUri: string;
    readonly dpopEnabled: boolean;
    readonly storagePrefix: string;
    readonly urlMode: 'query' | 'path';
    readonly mockMode: boolean;
    private readonly listeners;
    private currentSession;
    private syncUnsubscribe;
    constructor(options?: AuthClientOptions);
    /**
     * Phone Authentication Subsystem
     */
    phone: {
        sendOtp: (opts: PhoneSendOtpOptions) => Promise<AuthResult>;
        verify: (opts: PhoneVerifyOtpOptions) => Promise<AuthResult>;
        login: (opts: PhoneLoginOptions) => Promise<AuthResult>;
    };
    /**
     * Credentials (Email & Password) Authentication Subsystem
     */
    credentials: {
        login: (opts: CredentialLoginOptions) => Promise<AuthResult>;
        register: (opts: CredentialRegisterOptions) => Promise<AuthResult>;
    };
    /**
     * Password Recovery Subsystem
     */
    password: {
        forgot: (opts: ForgotPasswordOptions) => Promise<AuthResult>;
        reset: (opts: ResetPasswordOptions) => Promise<AuthResult>;
    };
    /**
     * Customer Account & Profile Subsystem (RFC 9449 DPoP Authenticated)
     */
    account: {
        getProfile: () => Promise<CustomerProfile | null>;
        updateProfile: (input: UpdateProfileInput) => Promise<AuthResult<CustomerProfile>>;
        listAddresses: () => Promise<CustomerAddress[]>;
        createAddress: (input: CreateAddressInput) => Promise<AuthResult<CustomerAddress>>;
        updateAddress: (id: string, input: UpdateAddressInput) => Promise<AuthResult<CustomerAddress>>;
        deleteAddress: (id: string) => Promise<AuthResult>;
        setDefaultAddress: (id: string) => Promise<AuthResult>;
        changePassword: (currentPassword: string, newPassword: string) => Promise<AuthResult>;
    };
    /**
     * Merchant Store Auth Configuration Subsystem
     */
    store: {
        getConfig: (storeSlug?: string) => Promise<StoreAuthConfig | null>;
    };
    /**
     * Alias for fetch() which automatically signs and attaches RFC 9449 DPoP proofs
     */
    fetchWithDPoP: (url: string, init?: RequestInit) => Promise<Response>;
    /**
     * Retrieves active session from memory or IndexedDB
     */
    getSession(): Promise<AuthSession | null>;
    /**
     * Retrieves authenticated user or null
     */
    getUser(): Promise<User | null>;
    /**
     * Generates central signin redirect URL with hardware dpop_jkt thumbprint
     */
    getSignInUrl(options?: {
        returnPath?: string;
        storeName?: string;
        urlMode?: 'query' | 'path';
    }): Promise<string>;
    /**
     * Generates central forgot-password redirect URL
     */
    getForgotPasswordUrl(options?: {
        method?: 'email' | 'phone';
        callbackURL?: string;
        storeName?: string;
        urlMode?: 'query' | 'path';
    }): string;
    /**
     * Generates OAuth 2.1 PKCE authorization code URL
     */
    createAuthorizationUrl(options?: {
        returnPath?: string;
    }): Promise<string>;
    /**
     * Ingests direct token (e.g. from redirect hash fragment #access_token=...)
     */
    handleDirectToken(accessToken: string, expiresIn?: number): Promise<AuthSession>;
    /**
     * Exchanges an authorization code for 30-day DPoP token
     */
    handleCallback(code: string, state?: string | null): Promise<AuthSession>;
    /**
     * Authenticated fetch helper: Automatically attaches Authorization and RFC 9449 DPoP proof
     * Automatically executes atomic device eviction on 401 Unauthorized responses.
     */
    fetch(url: string, init?: RequestInit): Promise<Response>;
    /**
     * Executes 4-Step Atomic Device Eviction
     */
    signOut(options?: SignOutOptions): Promise<void>;
    /**
     * Subscribe to authentication state changes
     */
    onAuthStateChange(listener: (user: User | null, session: AuthSession | null) => void): () => void;
    /**
     * Disposes background event listeners
     */
    destroy(): void;
    private setupSyncListener;
    private notifyListeners;
    private saveSessionFromResponse;
    private decodeJwtClaims;
}
/**
 * Factory helper for initializing client instance
 */
export declare function createAuthClient(options?: AuthClientOptions): ConversoraAuthClient;

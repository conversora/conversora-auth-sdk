import { createContext } from 'react';
import type {
  User,
  AuthSession,
  AuthResult,
  PhoneVerifyOtpOptions,
  PhoneLoginOptions,
  CredentialLoginOptions,
  CredentialRegisterOptions,
  SignOutOptions,
} from '../types';
import type { ConversoraAuthClient } from '../client/auth-client';

export interface AuthContextValue {
  client: ConversoraAuthClient;
  user: User | null;
  session: AuthSession | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  isDPoPBound: boolean;
  sendOtp: (phone: string) => Promise<AuthResult>;
  verifyOtp: (opts: PhoneVerifyOtpOptions) => Promise<AuthResult>;
  loginWithPhone: (opts: PhoneLoginOptions) => Promise<AuthResult>;
  loginWithCredentials: (opts: CredentialLoginOptions) => Promise<AuthResult>;
  registerWithCredentials: (opts: CredentialRegisterOptions) => Promise<AuthResult>;
  signOut: (options?: SignOutOptions) => Promise<void>;
  fetchWithAuth: (url: string, init?: RequestInit) => Promise<Response>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

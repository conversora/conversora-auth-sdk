import React, { useEffect, useMemo, useState, type ReactNode } from 'react';
import type {
  User,
  AuthSession,
  AuthClientOptions,
  PhoneVerifyOtpOptions,
  PhoneLoginOptions,
  CredentialLoginOptions,
  CredentialRegisterOptions,
  SignOutOptions,
} from '../types';
import { ConversoraAuthClient, createAuthClient } from '../client/auth-client';
import { AuthContext, type AuthContextValue } from './AuthContext';

export interface AuthProviderProps {
  children: ReactNode;
  client?: ConversoraAuthClient;
  clientOptions?: AuthClientOptions;
}

export function AuthProvider({ children, client, clientOptions }: AuthProviderProps) {
  const authClient = useMemo(() => {
    return client || createAuthClient(clientOptions || {});
  }, [client, clientOptions]);

  const [session, setSession] = useState<AuthSession | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;

    // Initial session hydration
    authClient.getSession().then((initialSession) => {
      if (mounted) {
        setSession(initialSession);
        setUser(initialSession ? initialSession.user : null);
        setIsLoading(false);
      }
    }).catch(() => {
      if (mounted) {
        setIsLoading(false);
      }
    });

    // Subscribe to runtime changes (including cross-tab events)
    const unsubscribe = authClient.onAuthStateChange((newUser, newSession) => {
      if (mounted) {
        setUser(newUser);
        setSession(newSession);
        setIsLoading(false);
      }
    });

    return () => {
      mounted = false;
      unsubscribe();
    };
  }, [authClient]);

  const contextValue: AuthContextValue = useMemo(() => {
    return {
      client: authClient,
      user,
      session,
      isLoading,
      isAuthenticated: !!user,
      isDPoPBound: session?.tokenType === 'DPoP',

      sendOtp: (phone: string) => authClient.phone.sendOtp({ phone }),
      verifyOtp: (opts: PhoneVerifyOtpOptions) => authClient.phone.verify(opts),
      loginWithPhone: (opts: PhoneLoginOptions) => authClient.phone.login(opts),
      loginWithCredentials: (opts: CredentialLoginOptions) => authClient.credentials.login(opts),
      registerWithCredentials: (opts: CredentialRegisterOptions) => authClient.credentials.register(opts),
      signOut: (options?: SignOutOptions) => authClient.signOut(options),
      fetchWithAuth: (url: string, init?: RequestInit) => authClient.fetch(url, init),
    };
  }, [authClient, user, session, isLoading]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

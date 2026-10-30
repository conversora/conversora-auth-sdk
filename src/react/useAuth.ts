import { useContext } from 'react';
import { AuthContext, type AuthContextValue } from './AuthContext';
import type { User } from '../types';

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return context;
}

export interface UseUserResult {
  user: User | null;
  isLoaded: boolean;
  isSignedIn: boolean;
}

export function useUser(): UseUserResult {
  const { user, isLoading } = useAuth();
  return {
    user,
    isLoaded: !isLoading,
    isSignedIn: !!user,
  };
}

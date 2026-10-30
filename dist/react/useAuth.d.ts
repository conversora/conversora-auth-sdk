import { type AuthContextValue } from './AuthContext';
import type { User } from '../types';
export declare function useAuth(): AuthContextValue;
export interface UseUserResult {
    user: User | null;
    isLoaded: boolean;
    isSignedIn: boolean;
}
export declare function useUser(): UseUserResult;

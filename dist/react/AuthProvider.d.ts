import React, { type ReactNode } from 'react';
import type { AuthClientOptions } from '../types';
import { ConversoraAuthClient } from '../client/auth-client';
export interface AuthProviderProps {
    children: ReactNode;
    client?: ConversoraAuthClient;
    clientOptions?: AuthClientOptions;
}
export declare function AuthProvider({ children, client, clientOptions }: AuthProviderProps): React.JSX.Element;

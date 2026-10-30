import React, { type ReactNode } from 'react';
export interface SignedInProps {
    children: ReactNode;
}
export declare function SignedIn({ children }: SignedInProps): React.JSX.Element | null;
export interface SignedOutProps {
    children: ReactNode;
}
export declare function SignedOut({ children }: SignedOutProps): React.JSX.Element | null;
export interface UserButtonProps {
    showName?: boolean;
    avatarSize?: number;
    onSignOut?: () => void;
    className?: string;
}
export declare function UserButton({ showName, avatarSize, onSignOut, className, }: UserButtonProps): React.JSX.Element | null;

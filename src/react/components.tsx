import React, { useState, useRef, useEffect, type ReactNode } from 'react';
import { useAuth, useUser } from './useAuth';

export interface SignedInProps {
  children: ReactNode;
}

export function SignedIn({ children }: SignedInProps) {
  const { isSignedIn, isLoaded } = useUser();
  if (!isLoaded || !isSignedIn) return null;
  return <>{children}</>;
}

export interface SignedOutProps {
  children: ReactNode;
}

export function SignedOut({ children }: SignedOutProps) {
  const { isSignedIn, isLoaded } = useUser();
  if (!isLoaded || isSignedIn) return null;
  return <>{children}</>;
}

export interface UserButtonProps {
  showName?: boolean;
  avatarSize?: number;
  onSignOut?: () => void;
  className?: string;
}

export function UserButton({
  showName = false,
  avatarSize = 36,
  onSignOut,
  className = '',
}: UserButtonProps) {
  const { user, isLoaded, isSignedIn } = useUser();
  const { signOut, isDPoPBound } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  if (!isLoaded || !isSignedIn || !user) return null;

  const displayName = user.name || user.email || user.phone || 'User';
  const initial = displayName.charAt(0).toUpperCase();

  const handleSignOut = async () => {
    setIsOpen(false);
    if (onSignOut) onSignOut();
    await signOut();
  };

  return (
    <div
      ref={dropdownRef}
      className={`conversora-user-button-root ${className}`}
      style={{ position: 'relative', display: 'inline-block', fontFamily: 'inherit' }}
    >
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px 8px',
          background: 'transparent',
          border: '1px solid rgba(0, 0, 0, 0.1)',
          borderRadius: '9999px',
          cursor: 'pointer',
          outline: 'none',
          transition: 'all 0.15s ease',
        }}
      >
        {user.image ? (
          <img
            src={user.image}
            alt={displayName}
            style={{
              width: avatarSize,
              height: avatarSize,
              borderRadius: '9999px',
              objectFit: 'cover',
            }}
          />
        ) : (
          <div
            style={{
              width: avatarSize,
              height: avatarSize,
              borderRadius: '9999px',
              background: '#0f172a',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 600,
              fontSize: `${Math.round(avatarSize * 0.45)}px`,
            }}
          >
            {initial}
          </div>
        )}

        {showName && (
          <span style={{ fontSize: '14px', fontWeight: 500, color: '#1e293b' }}>
            {displayName}
          </span>
        )}
      </button>

      {isOpen && (
        <div
          role="menu"
          style={{
            position: 'absolute',
            right: 0,
            marginTop: '8px',
            width: '240px',
            background: '#ffffff',
            borderRadius: '12px',
            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
            border: '1px solid rgba(0, 0, 0, 0.08)',
            padding: '12px',
            zIndex: 9999,
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          {/* Header */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', borderBottom: '1px solid #f1f5f9', paddingBottom: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: '#0f172a', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {displayName}
            </span>
            {user.email && (
              <span style={{ fontSize: '12px', color: '#64748b', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {user.email}
              </span>
            )}
            {user.phone && (
              <span style={{ fontSize: '12px', color: '#64748b' }}>
                {user.phone}
              </span>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }}>
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: '#f1f5f9',
                  color: '#475569',
                }}
              >
                {user.tier || 'Customer'}
              </span>
              {isDPoPBound && (
                <span
                  title="Hardware-bound DPoP RFC 9449 token active"
                  style={{
                    fontSize: '10px',
                    fontWeight: 600,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: '#ecfdf5',
                    color: '#059669',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '2px',
                  }}
                >
                  🔒 DPoP Bound
                </span>
              )}
            </div>
          </div>

          {/* Sign Out Action */}
          <button
            type="button"
            onClick={handleSignOut}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '100%',
              padding: '8px 12px',
              fontSize: '13px',
              fontWeight: 500,
              color: '#dc2626',
              background: '#fef2f2',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              transition: 'background 0.15s ease',
            }}
            onMouseOver={(e) => (e.currentTarget.style.background = '#fee2e2')}
            onMouseOut={(e) => (e.currentTarget.style.background = '#fef2f2')}
          >
            Sign out of device
          </button>
        </div>
      )}
    </div>
  );
}

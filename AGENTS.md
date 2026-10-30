# 🤖 AI Agent Integration Guide — `conversora-auth-sdk`

> **Quick Context for AI Agents:** `conversora-auth-sdk` is a zero-dependency, universal authentication client for Conversora headless e-commerce storefronts (Astro, Next.js, Remix, Vite, React, Vanilla). It provides Clerk-style developer ergonomics with hardware-bound RFC 9449 DPoP security.

---

## ⚡ 1-Command Installation

No npm registry or tokens needed. Install directly via GitHub:

```bash
# Using pnpm (Recommended)
pnpm add github:conversora/conversora-auth-sdk

# Using npm
npm install github:conversora/conversora-auth-sdk

# Using yarn
yarn add github:conversora/conversora-auth-sdk

# Using bun
bun add github:conversora/conversora-auth-sdk
```

---

## 🎯 Architecture Summary for Agents

1. **Authentication Server**: `https://auth.conversora.io` (or `https://auth.dev.conversora.io` in development).
2. **Commerce Resource Server**: `https://api.conversora.io/:tenant/*`.
3. **Stateless Hardware Binding (RFC 9449)**:
   - Client generates a non-extractable `ECDSA P-256` keypair stored in IndexedDB.
   - When calling `auth.fetch(url)` or `auth.fetchWithDPoP(url)`, the SDK automatically generates a 60-second DPoP proof and injects:
     ```http
     Authorization: DPoP <jwt_token>
     DPoP: <dpop_proof_jwt>
     ```
   - If DPoP is unsupported (e.g., node / server-side), it falls back to standard `Authorization: Bearer <jwt_token>`.
4. **Mock Mode for Local Development / Offline Testing**:
   - Pass `mockMode: true` to test full UI states without external backend networks:
     ```ts
     const auth = createAuthClient({ mockMode: true });
     ```

---

## 🛠️ Canonical Patterns for AI Agents

### Pattern 1: Initializing the Client (`src/lib/auth.ts`)
```ts
import { createAuthClient } from 'conversora-auth-sdk';

export const auth = createAuthClient({
  authUrl: import.meta.env.PUBLIC_AUTH_URL || 'https://auth.conversora.io',
  tenantId: 'booksmuggler', // Replace with store tenant slug
  redirectUri: typeof window !== 'undefined' ? `${window.location.origin}/auth/callback` : '',
});
```

### Pattern 2: Astro 4/5/7 Storefront Integration
In Astro pages or client scripts:
```astro
---
// src/pages/account/index.astro
---
<div id="account-portal">
  <p id="user-greeting">Loading patron profile...</p>
</div>

<script>
  import { auth } from '../../lib/auth';

  async function init() {
    const session = await auth.getSession();
    if (!session) {
      window.location.href = await auth.getSignInUrl({ returnPath: '/account' });
      return;
    }

    const profile = await auth.account.getProfile();
    const addresses = await auth.account.listAddresses();
    
    document.getElementById('user-greeting')!.innerText = `Welcome back, ${profile?.name || session.user.name}!`;
  }

  init();
</script>
```

### Pattern 3: React / Next.js Client Components
```tsx
'use client';

import {
  AuthProvider,
  SignedIn,
  SignedOut,
  UserButton,
  useUser,
  useAuth,
} from 'conversora-auth-sdk/react';

export function NavigationBar() {
  return (
    <AuthProvider clientOptions={{ tenantId: 'booksmuggler' }}>
      <nav className="flex items-center justify-between p-4 border-b">
        <span className="font-bold text-lg">Storefront</span>
        
        <SignedIn>
          <div className="flex items-center gap-3">
            <a href="/account" className="text-sm">My Account</a>
            <UserButton showName />
          </div>
        </SignedIn>

        <SignedOut>
          <a href="/signin" className="px-4 py-2 bg-black text-white rounded">
            Sign In
          </a>
        </SignedOut>
      </nav>
    </AuthProvider>
  );
}
```

### Pattern 4: Bangladeshi Mobile Phone OTP Login
```ts
// 1. Dispatch 6-digit SMS OTP
const sendResult = await auth.phone.sendOtp({
  phone: '+8801700000000',
  turnstileToken: captchaToken, // Optional Cloudflare Turnstile token
});

// 2. Complete instant login and mint 30-day session
const loginResult = await auth.phone.login({
  phone: '+8801700000000',
  code: '849201',
});

if (loginResult.ok) {
  console.log('Logged in patron:', loginResult.user);
}
```

### Pattern 5: Bangladeshi Logistics Address Book CRUD
```ts
// List all delivery addresses
const addresses = await auth.account.listAddresses();

// Add new delivery address
const newAddress = await auth.account.createAddress({
  recipientName: 'Solaman Shuvo',
  phoneNumber: '+8801700000000',
  division: 'Dhaka',
  district: 'Dhaka',
  thana: 'Dhanmondi',
  addressLine1: 'House 42, Road 9/A',
  addressLine2: 'Flat 4B',
  postalCode: '1209',
  country: 'Bangladesh',
  isDefault: true,
});

// Update default
await auth.account.setDefaultAddress(newAddress.data!.id);

// Remove address
await auth.account.deleteAddress('addr_id_123');
```

### Pattern 6: Authenticated Fetch to Commerce API
```ts
// Automatically binds RFC 9449 DPoP proof and auto signs-out if token expires
const res = await auth.fetch('https://api.conversora.io/booksmuggler/customer/orders');
const orders = await res.json();
```

---

## 🔒 Error Handling Standard for Agents
All async methods on `auth.phone`, `auth.credentials`, `auth.password`, and `auth.account` return an `AuthResult<T>`:
```ts
interface AuthResult<T> {
  ok: boolean;
  user?: User | null;
  token?: string | null;
  tokenType?: 'DPoP' | 'Bearer';
  error?: string;
  message?: string;
  data?: T;
}
```
Always check `if (result.ok)` before accessing `result.data`.

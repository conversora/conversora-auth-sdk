// src/crypto/base64url.ts
function base64UrlEncode(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    const b = bytes[i];
    if (b !== void 0) {
      binary += String.fromCharCode(b);
    }
  }
  const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function stringToBase64Url(str) {
  const bytes = new TextEncoder().encode(str);
  return base64UrlEncode(bytes);
}
function base64UrlDecodeToString(base64url) {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  if (typeof atob === "function") {
    return atob(base64);
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}

// src/crypto/idb-store.ts
var DB_NAME = "conversora_auth_vault";
var DB_VERSION = 1;
var STORE_KEYS = "keys";
var STORE_SESSIONS = "sessions";
var memoryStore = /* @__PURE__ */ new Map();
function getMemoryKey(storeName, key) {
  return `${storeName}:${key}`;
}
function openAuthDatabase() {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_KEYS)) {
          db.createObjectStore(STORE_KEYS, { keyPath: "tenantId" });
        }
        if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
          db.createObjectStore(STORE_SESSIONS, { keyPath: "tenantId" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}
async function idbGet(storeName, key) {
  const db = await openAuthDatabase();
  if (!db) {
    return memoryStore.get(getMemoryKey(storeName, key)) || null;
  }
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, "readonly");
      const store = tx.objectStore(storeName);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(memoryStore.get(getMemoryKey(storeName, key)) || null);
    } catch {
      resolve(memoryStore.get(getMemoryKey(storeName, key)) || null);
    }
  });
}
async function idbPut(storeName, val) {
  memoryStore.set(getMemoryKey(storeName, val.tenantId), val);
  const db = await openAuthDatabase();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, "readwrite");
      const store = tx.objectStore(storeName);
      const req = store.put(val);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}
async function idbDelete(storeName, key) {
  memoryStore.delete(getMemoryKey(storeName, key));
  const db = await openAuthDatabase();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(storeName, "readwrite");
      const store = tx.objectStore(storeName);
      const req = store.delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}
async function idbClearAll(tenantId) {
  await Promise.all([
    idbDelete(STORE_KEYS, tenantId),
    idbDelete(STORE_SESSIONS, tenantId)
  ]);
}

// src/crypto/dpop-keys.ts
var inFlightKeyGenerations = /* @__PURE__ */ new Map();
var inMemoryKeyStore = /* @__PURE__ */ new Map();
function isDPoPSupported() {
  try {
    const subtle = typeof crypto !== "undefined" ? crypto.subtle : null;
    return !!subtle && typeof subtle.generateKey === "function";
  } catch {
    return false;
  }
}
async function computeJwkThumbprint(jwk) {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64UrlEncode(hash);
}
async function getOrCreateDPoPKeyPair(tenantId = "default") {
  if (!isDPoPSupported()) {
    return null;
  }
  const inFlight = inFlightKeyGenerations.get(tenantId);
  if (inFlight) {
    return inFlight;
  }
  const promise = (async () => {
    try {
      try {
        const existing = await idbGet(STORE_KEYS, tenantId);
        if (existing && existing.privateKey && existing.publicKey && existing.jwk && existing.jkt) {
          return existing;
        }
      } catch {
        const memExisting = inMemoryKeyStore.get(tenantId);
        if (memExisting) return memExisting;
      }
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        // non-extractable: Private key cannot be exported/stolen via script!
        ["sign", "verify"]
      );
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const jkt = await computeJwkThumbprint(publicJwk);
      const record = {
        tenantId,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        jwk: publicJwk,
        jkt,
        createdAt: Date.now()
      };
      try {
        await idbPut(STORE_KEYS, record);
      } catch {
        inMemoryKeyStore.set(tenantId, record);
      }
      return record;
    } catch {
      return null;
    } finally {
      inFlightKeyGenerations.delete(tenantId);
    }
  })();
  inFlightKeyGenerations.set(tenantId, promise);
  return promise;
}
async function purgeDPoPKeyPair(tenantId = "default") {
  inFlightKeyGenerations.delete(tenantId);
  inMemoryKeyStore.delete(tenantId);
  try {
    await idbDelete(STORE_KEYS, tenantId);
  } catch {
  }
}

// src/crypto/dpop-proof.ts
function normalizeDPoPHtu(rawUrl) {
  try {
    const parsed = new URL(rawUrl, typeof window !== "undefined" ? window.location.origin : "https://auth.conversora.io");
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return rawUrl.split("?")[0]?.split("#")[0] || rawUrl;
  }
}
async function createDPoPProof(options) {
  const { method, url, accessToken, tenantId = "default" } = options;
  let keyRecord = options.keyPair;
  if (!keyRecord) {
    const fetched = await getOrCreateDPoPKeyPair(tenantId);
    if (!fetched) return null;
    keyRecord = fetched;
  }
  try {
    const htu = normalizeDPoPHtu(url);
    const header = {
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: keyRecord.jwk.x,
        y: keyRecord.jwk.y
      }
    };
    const randomBytes = new Uint8Array(16);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      crypto.getRandomValues(randomBytes);
    } else {
      for (let i = 0; i < 16; i++) randomBytes[i] = Math.floor(Math.random() * 256);
    }
    const payload = {
      jti: "dpop_" + base64UrlEncode(randomBytes),
      htm: method.toUpperCase(),
      htu,
      iat: Math.floor(Date.now() / 1e3)
    };
    if (accessToken) {
      const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
      payload.ath = base64UrlEncode(hash);
    }
    const encodedHeader = stringToBase64Url(JSON.stringify(header));
    const encodedPayload = stringToBase64Url(JSON.stringify(payload));
    const message = `${encodedHeader}.${encodedPayload}`;
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      keyRecord.privateKey,
      new TextEncoder().encode(message)
    );
    return `${message}.${base64UrlEncode(signature)}`;
  } catch (err) {
    return null;
  }
}

// src/client/sync-channel.ts
var CHANNEL_NAME = "conversora_auth_sync";
var AuthSyncChannel = class {
  channel = null;
  listeners = /* @__PURE__ */ new Set();
  constructor() {
    if (typeof BroadcastChannel !== "undefined") {
      try {
        this.channel = new BroadcastChannel(CHANNEL_NAME);
        if (typeof this.channel.unref === "function") {
          this.channel.unref();
        }
        this.channel.onmessage = (event) => {
          if (event.data && typeof event.data === "object" && event.data.type) {
            this.notifyListeners(event.data);
          }
        };
      } catch {
        this.channel = null;
      }
    }
    if (typeof window !== "undefined") {
      window.addEventListener("storage", (event) => {
        if (event.key === CHANNEL_NAME && event.newValue) {
          try {
            const data = JSON.parse(event.newValue);
            this.notifyListeners(data);
          } catch {
          }
        }
      });
    }
  }
  subscribe(listener) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
  broadcast(message) {
    this.notifyListeners(message);
    if (this.channel) {
      try {
        this.channel.postMessage(message);
      } catch {
      }
    }
    if (typeof window !== "undefined" && typeof localStorage !== "undefined") {
      try {
        localStorage.setItem(CHANNEL_NAME, JSON.stringify(message));
      } catch {
      }
    }
  }
  close() {
    if (this.channel) {
      try {
        this.channel.close();
      } catch {
      }
      this.channel = null;
    }
    this.listeners.clear();
  }
  notifyListeners(message) {
    for (const listener of this.listeners) {
      try {
        listener(message);
      } catch {
      }
    }
  }
};
var defaultSyncChannel = null;
function getAuthSyncChannel() {
  if (!defaultSyncChannel) {
    defaultSyncChannel = new AuthSyncChannel();
  }
  return defaultSyncChannel;
}

// src/client/atomic-signout.ts
async function executeAtomicSignOut(params) {
  const { authUrl, tenantId, storagePrefix = "conversora_auth", redirectUrl, broadcast = true } = params;
  try {
    const cleanAuthUrl = authUrl.replace(/\/+$/, "");
    await fetch(`${cleanAuthUrl}/api/v1/auth/session/signout`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({ tenantId })
    }).catch(() => {
      return fetch(`${cleanAuthUrl}/api/auth/sign-out`, {
        method: "POST",
        credentials: "include"
      });
    });
  } catch {
  }
  try {
    await Promise.all([
      purgeDPoPKeyPair(tenantId),
      idbDelete(STORE_SESSIONS, tenantId)
    ]);
  } catch {
  }
  try {
    if (typeof localStorage !== "undefined") {
      const keysToRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.startsWith("conversora_") || key.startsWith("conv_") || key.startsWith(storagePrefix) || key.includes("better-auth"))) {
          keysToRemove.push(key);
        }
      }
      for (const k of keysToRemove) localStorage.removeItem(k);
    }
    if (typeof sessionStorage !== "undefined") {
      const sessionKeysToRemove = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && (key.startsWith("conversora_") || key.startsWith("conv_") || key.startsWith(storagePrefix))) {
          sessionKeysToRemove.push(key);
        }
      }
      for (const k of sessionKeysToRemove) sessionStorage.removeItem(k);
    }
  } catch {
  }
  if (broadcast) {
    try {
      getAuthSyncChannel().broadcast({
        type: "EVICT_SESSION",
        tenantId,
        timestamp: Date.now()
      });
    } catch {
    }
  }
  if (redirectUrl && typeof window !== "undefined") {
    window.location.href = redirectUrl;
  }
}

// src/client/auth-client.ts
var ConversoraAuthClient = class {
  authUrl;
  tenantId;
  redirectUri;
  dpopEnabled;
  storagePrefix;
  urlMode;
  mockMode;
  listeners = /* @__PURE__ */ new Set();
  currentSession = null;
  syncUnsubscribe = null;
  constructor(options = {}) {
    this.authUrl = (options.authUrl || (typeof window !== "undefined" ? window.location.origin : "https://auth.conversora.io")).replace(/\/+$/, "");
    this.tenantId = options.tenantId || "default";
    this.redirectUri = options.redirectUri || (typeof window !== "undefined" ? `${window.location.origin}/auth/callback` : "");
    this.dpopEnabled = options.dpopEnabled ?? true;
    this.storagePrefix = options.storagePrefix || "conversora_auth";
    this.urlMode = options.urlMode || "query";
    this.mockMode = options.mockMode ?? false;
    if (options.onAuthStateChange) {
      this.listeners.add(options.onAuthStateChange);
    }
    if (options.autoSyncAcrossTabs !== false) {
      this.setupSyncListener();
    }
    if (typeof window !== "undefined") {
      this.getSession().catch(() => {
      });
    }
  }
  /**
   * Phone Authentication Subsystem
   */
  phone = {
    sendOtp: async (opts) => {
      try {
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        const res = await fetch(`${this.authUrl}/api/v1/auth/phone/send-otp`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            phone: opts.phone,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    verify: async (opts) => {
      try {
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        const res = await fetch(`${this.authUrl}/api/v1/auth/phone/verify`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            ...opts,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    login: async (opts) => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/phone/login`;
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: "POST", url: targetUrl, tenantId: this.tenantId });
          if (proof) headers["DPoP"] = proof;
        }
        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          credentials: "include",
          body: JSON.stringify({
            ...opts,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || "auth_failed",
            message: data.message || "Phone verification failed"
          };
        }
        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    }
  };
  /**
   * Credentials (Email & Password) Authentication Subsystem
   */
  credentials = {
    login: async (opts) => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/credential/login`;
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: "POST", url: targetUrl, tenantId: this.tenantId });
          if (proof) headers["DPoP"] = proof;
        }
        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          credentials: "include",
          body: JSON.stringify({
            ...opts,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || "login_failed",
            message: data.message || "Invalid email or password"
          };
        }
        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    register: async (opts) => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/credential/register`;
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        if (this.dpopEnabled && isDPoPSupported()) {
          const proof = await createDPoPProof({ method: "POST", url: targetUrl, tenantId: this.tenantId });
          if (proof) headers["DPoP"] = proof;
        }
        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          credentials: "include",
          body: JSON.stringify({
            ...opts,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          return {
            ok: false,
            error: data.error || "registration_failed",
            message: data.message || "Could not register account"
          };
        }
        const session = await this.saveSessionFromResponse(data);
        return {
          ok: true,
          user: session.user,
          token: session.accessToken,
          tokenType: session.tokenType,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    }
  };
  /**
   * Password Recovery Subsystem
   */
  password = {
    forgot: async (opts) => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/password/forgot`;
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          body: JSON.stringify({
            ...opts.email ? { email: opts.email } : {},
            ...opts.phone ? { phone: opts.phone } : {},
            ...opts.callbackURL ? { callbackURL: opts.callbackURL } : {},
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    reset: async (opts) => {
      try {
        const targetUrl = `${this.authUrl}/api/v1/auth/password/reset`;
        const headers = {
          "Content-Type": "application/json",
          Accept: "application/json"
        };
        if (opts.turnstileToken) {
          headers["cf-turnstile-response"] = opts.turnstileToken;
        }
        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          body: JSON.stringify({
            ...opts.token ? { token: opts.token } : {},
            ...opts.phone ? { phone: opts.phone } : {},
            ...opts.code ? { code: opts.code } : {},
            newPassword: opts.newPassword,
            ...opts.turnstileToken ? { "cf-turnstile-response": opts.turnstileToken } : {}
          })
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    }
  };
  /**
   * Customer Account & Profile Subsystem (RFC 9449 DPoP Authenticated)
   */
  account = {
    getProfile: async () => {
      if (this.mockMode) {
        return {
          id: "usr_mock_shopper",
          name: "Solaman Shuvo",
          email: "shopper@conversora.io",
          phone: "+8801700000000",
          points: 320,
          tier: "Gold Patron",
          addresses: await this.account.listAddresses()
        };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/profile`);
        if (!res.ok) return null;
        const data = await res.json().catch(() => null);
        return data;
      } catch {
        return null;
      }
    },
    updateProfile: async (input) => {
      if (this.mockMode) {
        return {
          ok: true,
          data: {
            id: "usr_mock_shopper",
            name: input.name || "Solaman Shuvo",
            email: input.email || "shopper@conversora.io",
            phone: input.phone || "+8801700000000",
            avatarUrl: input.avatarUrl
          }
        };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/profile`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input)
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    listAddresses: async () => {
      if (this.mockMode) {
        return [
          {
            id: "addr_mock_1",
            recipientName: "Solaman Shuvo",
            phoneNumber: "+8801700000000",
            division: "Dhaka",
            district: "Dhaka",
            thana: "Dhanmondi",
            addressLine1: "House 42, Road 9/A",
            postalCode: "1209",
            country: "Bangladesh",
            isDefault: true,
            createdAt: Date.now()
          },
          {
            id: "addr_mock_2",
            recipientName: "Solaman Shuvo",
            phoneNumber: "+8801700000000",
            division: "Dhaka",
            district: "Dhaka",
            thana: "Gulshan",
            addressLine1: "Avenue 2, Block D",
            postalCode: "1212",
            country: "Bangladesh",
            isDefault: false,
            createdAt: Date.now() - 864e5
          }
        ];
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses`);
        if (!res.ok) return [];
        const data = await res.json().catch(() => []);
        return Array.isArray(data) ? data : data.addresses || [];
      } catch {
        return [];
      }
    },
    createAddress: async (input) => {
      if (this.mockMode) {
        const newAddress = {
          id: `addr_mock_${Date.now()}`,
          recipientName: input.recipientName,
          phoneNumber: input.phoneNumber,
          division: input.division,
          district: input.district,
          thana: input.thana,
          addressLine1: input.addressLine1,
          addressLine2: input.addressLine2,
          postalCode: input.postalCode || "",
          country: input.country || "Bangladesh",
          isDefault: input.isDefault ?? false,
          createdAt: Date.now()
        };
        return { ok: true, data: newAddress };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input)
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    updateAddress: async (id, input) => {
      if (this.mockMode) {
        return {
          ok: true,
          data: {
            id,
            recipientName: input.recipientName || "Solaman Shuvo",
            phoneNumber: input.phoneNumber || "+8801700000000",
            division: input.division || "Dhaka",
            district: input.district || "Dhaka",
            thana: input.thana || "Dhanmondi",
            addressLine1: input.addressLine1 || "House 42, Road 9/A",
            addressLine2: input.addressLine2,
            postalCode: input.postalCode || "1209",
            country: input.country || "Bangladesh",
            isDefault: input.isDefault ?? false
          }
        };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input)
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    deleteAddress: async (id) => {
      if (this.mockMode) {
        return { ok: true, message: "Address removed successfully" };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}`, {
          method: "DELETE"
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    setDefaultAddress: async (id) => {
      if (this.mockMode) {
        return { ok: true, message: "Default address updated" };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/addresses/${encodeURIComponent(id)}/default`, {
          method: "POST"
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    },
    changePassword: async (currentPassword, newPassword) => {
      if (this.mockMode) {
        return { ok: true, message: "Password updated successfully" };
      }
      try {
        const res = await this.fetch(`${this.authUrl}/api/v1/account/password`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ currentPassword, newPassword })
        });
        const data = await res.json().catch(() => ({}));
        return {
          ok: res.ok && data.ok !== false,
          error: data.error,
          message: data.message,
          data
        };
      } catch (err) {
        return { ok: false, error: "network_error", message: err.message };
      }
    }
  };
  /**
   * Merchant Store Auth Configuration Subsystem
   */
  store = {
    getConfig: async (storeSlug) => {
      const slug = storeSlug || this.tenantId;
      if (this.mockMode) {
        return {
          storeSlug: slug,
          methods: {
            phoneOtp: { enabled: true, autoRegister: true },
            emailPassword: { enabled: true, allowRegistration: true }
          }
        };
      }
      try {
        const res = await fetch(`${this.authUrl}/api/v1/store/auth-config?store=${encodeURIComponent(slug)}`);
        if (!res.ok) return null;
        return await res.json().catch(() => null);
      } catch {
        return null;
      }
    }
  };
  /**
   * Alias for fetch() which automatically signs and attaches RFC 9449 DPoP proofs
   */
  fetchWithDPoP = this.fetch.bind(this);
  /**
   * Retrieves active session from memory or IndexedDB
   */
  async getSession() {
    if (this.currentSession) {
      if (Date.now() < this.currentSession.expiresAt) {
        return this.currentSession;
      }
      await this.signOut({ broadcast: true });
      return null;
    }
    try {
      const stored = await idbGet(STORE_SESSIONS, this.tenantId);
      if (stored) {
        if (Date.now() < stored.expiresAt) {
          this.currentSession = stored;
          this.notifyListeners(stored.user, stored);
          return stored;
        }
        await this.signOut({ broadcast: true });
      }
    } catch {
    }
    return null;
  }
  /**
   * Retrieves authenticated user or null
   */
  async getUser() {
    const session = await this.getSession();
    return session ? session.user : null;
  }
  /**
   * Generates central signin redirect URL with hardware dpop_jkt thumbprint
   */
  async getSignInUrl(options = {}) {
    const rawStore = options.storeName || this.tenantId;
    const mode = options.urlMode || this.urlMode || "query";
    const callbackUrl = encodeURIComponent(this.redirectUri);
    const store = encodeURIComponent(rawStore);
    const origin = typeof window !== "undefined" ? encodeURIComponent(window.location.origin) : "";
    let dpopJkt = "";
    if (this.dpopEnabled && isDPoPSupported()) {
      const keyRecord = await getOrCreateDPoPKeyPair(this.tenantId);
      if (keyRecord) dpopJkt = keyRecord.jkt;
    }
    let url = "";
    if (mode === "path" && rawStore && rawStore !== "default" && rawStore !== "conversora") {
      url = `${this.authUrl}/s/${store}/signin?callbackURL=${callbackUrl}`;
      if (origin) url += `&origin=${origin}`;
    } else {
      url = `${this.authUrl}/signin?origin=${origin}&callbackURL=${callbackUrl}&store=${store}&tenantId=${encodeURIComponent(this.tenantId)}`;
    }
    if (dpopJkt) {
      url += `&dpop_jkt=${encodeURIComponent(dpopJkt)}`;
    }
    if (options.returnPath) {
      url += `&returnPath=${encodeURIComponent(options.returnPath)}`;
    }
    return url;
  }
  /**
   * Generates central forgot-password redirect URL
   */
  getForgotPasswordUrl(options = {}) {
    const rawStore = options.storeName || this.tenantId;
    const mode = options.urlMode || this.urlMode || "query";
    const callbackUrl = encodeURIComponent(options.callbackURL || this.redirectUri);
    const method = options.method || "email";
    if (mode === "path" && rawStore && rawStore !== "default" && rawStore !== "conversora") {
      return `${this.authUrl}/s/${encodeURIComponent(rawStore)}/forgot-password?method=${method}&callbackURL=${callbackUrl}`;
    }
    return `${this.authUrl}/forgot-password?method=${method}&callbackURL=${callbackUrl}&tenantId=${encodeURIComponent(this.tenantId)}`;
  }
  /**
   * Generates OAuth 2.1 PKCE authorization code URL
   */
  async createAuthorizationUrl(options = {}) {
    let dpopJkt = "";
    if (this.dpopEnabled && isDPoPSupported()) {
      const keyRecord = await getOrCreateDPoPKeyPair(this.tenantId);
      if (keyRecord) dpopJkt = keyRecord.jkt;
    }
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const codeVerifier = base64UrlEncode(verifierBytes);
    const challengeBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
    const codeChallenge = base64UrlEncode(challengeBuffer);
    const stateObj = {
      csrf: base64UrlEncode(crypto.getRandomValues(new Uint8Array(16))),
      returnPath: options.returnPath || "/"
    };
    const state = base64UrlEncode(new TextEncoder().encode(JSON.stringify(stateObj)));
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.setItem(`${this.storagePrefix}_pkce_${this.tenantId}`, JSON.stringify({
        codeVerifier,
        state,
        createdAt: Date.now()
      }));
    }
    const url = new URL(`${this.authUrl}/authorize`);
    url.searchParams.set("client_id", this.tenantId);
    url.searchParams.set("redirect_uri", this.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", state);
    if (dpopJkt) url.searchParams.set("dpop_jkt", dpopJkt);
    return url.toString();
  }
  /**
   * Ingests direct token (e.g. from redirect hash fragment #access_token=...)
   */
  async handleDirectToken(accessToken, expiresIn = 2592e3) {
    const claims = this.decodeJwtClaims(accessToken);
    const isDPoP = claims.cnf && claims.cnf.jkt;
    const user = {
      id: claims.sub || "usr_unknown",
      name: claims.u_name || claims.name || "Patron",
      email: claims.email || claims.u_email || claims.u_email_masked || null,
      phone: claims.phone || claims.u_phone || null,
      tier: claims.u_tier || "standard",
      currency: claims.u_curr || "BDT",
      tenantId: claims.tenant_id || this.tenantId,
      points: claims.u_pts || 0
    };
    const session = {
      tokenType: isDPoP ? "DPoP" : "Bearer",
      accessToken,
      expiresAt: Date.now() + expiresIn * 1e3,
      scope: claims.scope || "default",
      user,
      dpopJkt: claims.cnf?.jkt
    };
    this.currentSession = session;
    await idbPut(STORE_SESSIONS, {
      ...session,
      tenantId: this.tenantId
    });
    getAuthSyncChannel().broadcast({
      type: "SIGN_IN",
      tenantId: this.tenantId,
      user,
      timestamp: Date.now()
    });
    this.notifyListeners(user, session);
    return session;
  }
  /**
   * Exchanges an authorization code for 30-day DPoP token
   */
  async handleCallback(code, state) {
    let codeVerifier = "";
    if (state && typeof sessionStorage !== "undefined") {
      const saved = sessionStorage.getItem(`${this.storagePrefix}_pkce_${this.tenantId}`);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed.state === state) codeVerifier = parsed.codeVerifier;
        } catch {
        }
        sessionStorage.removeItem(`${this.storagePrefix}_pkce_${this.tenantId}`);
      }
    }
    const tokenUrl = `${this.authUrl}/oauth/token`;
    const cleanCode = code.split(".")[0] || "";
    const bodyParams = new URLSearchParams({
      grant_type: "authorization_code",
      code: cleanCode,
      redirect_uri: this.redirectUri,
      client_id: this.tenantId
    });
    if (codeVerifier) bodyParams.set("code_verifier", codeVerifier);
    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    };
    if (this.dpopEnabled && isDPoPSupported()) {
      const proof = await createDPoPProof({ method: "POST", url: tokenUrl, tenantId: this.tenantId });
      if (proof) headers["DPoP"] = proof;
    }
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers,
      body: bodyParams.toString()
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Token exchange failed (${res.status}): ${err}`);
    }
    const data = await res.json();
    return this.saveSessionFromResponse(data);
  }
  /**
   * Authenticated fetch helper: Automatically attaches Authorization and RFC 9449 DPoP proof
   * Automatically executes atomic device eviction on 401 Unauthorized responses.
   */
  async fetch(url, init = {}) {
    const session = await this.getSession();
    const headers = new Headers(init.headers || {});
    if (session) {
      const method = (init.method || "GET").toUpperCase();
      if (session.tokenType === "DPoP" && this.dpopEnabled && isDPoPSupported()) {
        headers.set("Authorization", `DPoP ${session.accessToken}`);
        const proof = await createDPoPProof({
          method,
          url,
          accessToken: session.accessToken,
          tenantId: this.tenantId
        });
        if (proof) headers.set("DPoP", proof);
      } else {
        headers.set("Authorization", `Bearer ${session.accessToken}`);
      }
    }
    const res = await fetch(url, {
      ...init,
      headers
    });
    if (res.status === 401) {
      await this.signOut({ broadcast: true });
    }
    return res;
  }
  /**
   * Executes 4-Step Atomic Device Eviction
   */
  async signOut(options = {}) {
    this.currentSession = null;
    this.notifyListeners(null, null);
    await executeAtomicSignOut({
      authUrl: this.authUrl,
      tenantId: this.tenantId,
      storagePrefix: this.storagePrefix,
      redirectUrl: options.redirectUrl,
      broadcast: options.broadcast ?? true
    });
  }
  /**
   * Subscribe to authentication state changes
   */
  onAuthStateChange(listener) {
    this.listeners.add(listener);
    if (this.currentSession) {
      listener(this.currentSession.user, this.currentSession);
    }
    return () => {
      this.listeners.delete(listener);
    };
  }
  /**
   * Disposes background event listeners
   */
  destroy() {
    if (this.syncUnsubscribe) {
      this.syncUnsubscribe();
      this.syncUnsubscribe = null;
    }
    this.listeners.clear();
  }
  // --- Private Helpers ---
  setupSyncListener() {
    const channel = getAuthSyncChannel();
    this.syncUnsubscribe = channel.subscribe((msg) => {
      if (msg.tenantId !== this.tenantId) return;
      if (msg.type === "EVICT_SESSION") {
        this.currentSession = null;
        this.notifyListeners(null, null);
      } else if (msg.type === "SIGN_IN") {
        this.getSession().catch(() => {
        });
      }
    });
  }
  notifyListeners(user, session) {
    for (const listener of this.listeners) {
      try {
        listener(user, session);
      } catch {
      }
    }
  }
  async saveSessionFromResponse(data) {
    const accessToken = data.token || data.access_token || "";
    const claims = accessToken ? this.decodeJwtClaims(accessToken) : {};
    const tokenType = data.token_type === "DPoP" || claims.cnf?.jkt ? "DPoP" : "Bearer";
    const expiresIn = data.expires_in || 2592e3;
    const user = {
      id: data.user?.id || claims.sub || "usr_unknown",
      name: data.user?.name || claims.u_name || claims.name || "Patron",
      email: data.user?.email || claims.email || claims.u_email || null,
      phone: data.user?.phone || claims.phone || claims.u_phone || null,
      role: data.user?.role || claims.role,
      image: data.user?.image || claims.image || null,
      emailVerified: data.user?.emailVerified ?? false,
      phoneVerified: data.user?.phoneVerified ?? false,
      tier: claims.u_tier || "standard",
      currency: claims.u_curr || "BDT",
      tenantId: this.tenantId,
      points: claims.u_pts || 0
    };
    const session = {
      tokenType,
      accessToken,
      expiresAt: Date.now() + expiresIn * 1e3,
      scope: data.scope || claims.scope || "default",
      user,
      dpopJkt: claims.cnf?.jkt
    };
    this.currentSession = session;
    await idbPut(STORE_SESSIONS, {
      ...session,
      tenantId: this.tenantId
    });
    getAuthSyncChannel().broadcast({
      type: "SIGN_IN",
      tenantId: this.tenantId,
      user,
      timestamp: Date.now()
    });
    this.notifyListeners(user, session);
    return session;
  }
  decodeJwtClaims(jwt) {
    try {
      const parts = jwt.split(".");
      if (parts.length >= 2 && parts[1]) {
        return JSON.parse(base64UrlDecodeToString(parts[1]));
      }
    } catch {
    }
    return {};
  }
};
function createAuthClient(options = {}) {
  return new ConversoraAuthClient(options);
}
export {
  AuthSyncChannel,
  ConversoraAuthClient,
  base64UrlDecodeToString,
  base64UrlEncode,
  computeJwkThumbprint,
  createAuthClient,
  createDPoPProof,
  executeAtomicSignOut,
  getAuthSyncChannel,
  getOrCreateDPoPKeyPair,
  idbClearAll,
  idbDelete,
  idbGet,
  idbPut,
  isDPoPSupported,
  normalizeDPoPHtu,
  openAuthDatabase,
  purgeDPoPKeyPair,
  stringToBase64Url
};
//# sourceMappingURL=index.mjs.map

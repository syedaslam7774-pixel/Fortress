// ============================================================
// e2eCrypto.js
// Client-side crypto for Fortress's E2E encrypted chat.
// Nothing in this file ever sends a private key to the server —
// only the two public keys (auth + encryption) leave the browser.
// ============================================================

// --- Step 1: generate BOTH keypairs at registration time ---
// authKeyPair: ECDSA, used to prove identity on login (unchanged from before)
// encryptionKeyPair: ECDH, used only to derive shared secrets for chat
export async function generateKeyPairs() {
  const authKeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true, // extractable — we need to export the public half to send to the server
    ["sign", "verify"]
  );

  const encryptionKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );

  return { authKeyPair, encryptionKeyPair };
}

// --- Step 2: export public keys as base64 to send to /api/register ---
export async function exportPublicKeyBase64(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// --- Step 3: persist private keys across page reloads ---
// Private CryptoKey objects can be stored directly in IndexedDB
// (structured clone) WITHOUT being exported, so the raw key material
// never touches JS-readable memory or localStorage. Never store these
// keys in localStorage/sessionStorage — those are plain strings and
// readable by any script on the page (e.g. via an XSS bug).
const DB_NAME = "fortress-keys";
const STORE_NAME = "keys";

function openKeyDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveKeyPair(username, authKeyPair, encryptionKeyPair) {
  const db = await openKeyDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).put(
    { authKeyPair, encryptionKeyPair },
    username
  );
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadKeyPair(username) {
  const db = await openKeyDB();
  const tx = db.transaction(STORE_NAME, "readonly");
  const req = tx.objectStore(STORE_NAME).get(username);
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result || null); // null if this browser has never registered this user
    req.onerror = () => reject(req.error);
  });
}

// --- Step 4: derive the shared AES key with a chat partner ---
// Call this with YOUR encryptionKeyPair.privateKey and the PEER's
// encryptionPublicKey (fetched from GET /api/users/{username}/key).
// Both sides independently compute the same AES key — this is the
// core of the E2E property: the server never sees it.
export async function deriveSharedKey(myPrivateKey, peerPublicKeyBase64) {
  const raw = Uint8Array.from(atob(peerPublicKeyBase64), (c) => c.charCodeAt(0));
  const peerPublicKey = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false, // not extractable — the derived key stays inside WebCrypto
    ["encrypt", "decrypt"]
  );
}

// --- Step 5: encrypt a message before POSTing to /api/messages ---
export async function encryptMessage(sharedKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    encoded
  );
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

// --- Step 6: decrypt a message received from GET /api/messages/{user} ---
export async function decryptMessage(sharedKey, ciphertextBase64, ivBase64) {
  const ciphertext = Uint8Array.from(atob(ciphertextBase64), (c) => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    ciphertext
  );
  return new TextDecoder().decode(plaintextBuf);
}
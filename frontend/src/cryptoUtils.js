// cryptoUtils.js
// All key generation, encryption, and signing happens here, entirely client-side
// using the browser's native Web Crypto API (no external crypto library needed).

const LOCAL_KEY_PREFIX = "fortress_identity_";

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

// Derive an AES-GCM key from the user's password using PBKDF2
async function deriveKeyFromPassword(password, saltBuf) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Generate a fresh ECDSA (P-256) key pair
export async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

// Register a new local identity: generate keys, encrypt private key with password,
// store the encrypted blob locally, and return the public key to send to the server.
export async function createIdentity(username, password) {
  const { publicKey, privateKey } = await generateKeyPair();

  const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", privateKey);
  const publicKeyRaw = await crypto.subtle.exportKey("raw", publicKey);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveKeyFromPassword(password, salt);

  const encryptedPrivateKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    privateKeyRaw
  );

  const record = {
    encryptedPrivateKey: bufToBase64(encryptedPrivateKey),
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
  };

  // Private key material never leaves this browser.
  localStorage.setItem(LOCAL_KEY_PREFIX + username, JSON.stringify(record));

  return { publicKey: bufToBase64(publicKeyRaw) };
}

// Attempt to decrypt the locally-stored private key using the given password.
// Throws if the password is wrong (AES-GCM auth tag fails) or no identity exists.
export async function unlockPrivateKey(username, password) {
  const raw = localStorage.getItem(LOCAL_KEY_PREFIX + username);
  if (!raw) throw new Error("No local identity found for this username on this device.");

  const record = JSON.parse(raw);
  const salt = base64ToBuf(record.salt);
  const iv = base64ToBuf(record.iv);
  const aesKey = await deriveKeyFromPassword(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    base64ToBuf(record.encryptedPrivateKey)
  ); // throws if password is wrong

  return crypto.subtle.importKey(
    "pkcs8",
    decrypted,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

// Sign a server-issued challenge string with the unlocked private key.
export async function signChallenge(privateKey, challenge) {
  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    enc.encode(challenge)
  );
  return bufToBase64(signature);
}

export function hasLocalIdentity(username) {
  return !!localStorage.getItem(LOCAL_KEY_PREFIX + username);
}
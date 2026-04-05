import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

export const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});

// ─── Helpers ───────────────────────────────────────────────

const arrayBufferToBase64 = (buffer: ArrayBuffer): string =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)));

const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

// ─── Key Management ────────────────────────────────────────

export async function generateKeyPair() {
  return await suite.kem.generateKeyPair();
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<JsonWebKey> {
  return await crypto.subtle.exportKey("jwk", publicKey);
}

/** Convert JWK to compact base64 string */
export function publicKeyToString(jwk: JsonWebKey): string {
  return btoa(JSON.stringify(jwk));
}

/** Convert compact base64 string back to JWK */
export function publicKeyFromString(str: string): JsonWebKey {
  return JSON.parse(atob(str));
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

// ─── Encrypt / Decrypt ─────────────────────────────────────

export interface HpkeEncryptedData {
  ciphertext: string; // base64
  enc: string; // base64
  encrypted?: string; // combined base64 string (optional, for convenience)
}

/**
 * Encrypt data using recipient's public key
 */
export async function hpkeEncrypt(
  data: string,
  recipientPublicKey: JsonWebKey
): Promise<HpkeEncryptedData> {
  const publicKey = await importPublicKey(recipientPublicKey);

  const sender = await suite.createSenderContext({ recipientPublicKey: publicKey });
  const ct = await sender.seal(new TextEncoder().encode(data));

  const ciphertextB64 = arrayBufferToBase64(ct);
  const encB64 = arrayBufferToBase64(sender.enc);

  return {
    ciphertext: ciphertextB64,
    enc: encB64,
    // Combined string for easy copy-paste
    encrypted: btoa(JSON.stringify({ ciphertext: ciphertextB64, enc: encB64 })),
  };
}

/**
 * Decrypt data using your private key
 */
export async function hpkeDecrypt(
  encrypted: HpkeEncryptedData,
  privateKey: CryptoKey
): Promise<string> {
  // Handle combined string format
  let ciphertext: string
  let enc: string

  if (encrypted.encrypted) {
    const parsed = JSON.parse(atob(encrypted.encrypted))
    ciphertext = parsed.ciphertext
    enc = parsed.enc
  } else {
    ciphertext = encrypted.ciphertext
    enc = encrypted.enc
  }

  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: base64ToArrayBuffer(enc),
  })
  const pt = await recipient.open(base64ToArrayBuffer(ciphertext))

  return new TextDecoder().decode(pt)
}

// ─── Server API Helpers ────────────────────────────────────

const SERVER_URL = "http://localhost:9002";

export async function getServerPublicKey(): Promise<JsonWebKey> {
  const res = await fetch(`${SERVER_URL}/api/public-key`);
  const data = await res.json();
  return publicKeyFromString(data.publicKeyString);
}

export async function getServerPublicKeyString(): Promise<string> {
  const res = await fetch(`${SERVER_URL}/api/public-key`);
  const data = await res.json();
  return data.publicKeyString;
}

export async function serverEncrypt(
  data: string,
  serverPublicKey: JsonWebKey
): Promise<HpkeEncryptedData> {
  const res = await fetch(`${SERVER_URL}/api/encrypt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      data,
      recipientPublicKey: serverPublicKey,
    }),
  });
  return await res.json();
}

export async function serverDecrypt(encrypted: HpkeEncryptedData): Promise<string> {
  const res = await fetch(`${SERVER_URL}/api/decrypt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ encrypted: encrypted.encrypted }),
  });
  const data = await res.json();
  return data.data;
}

export async function serverEncryptForClient(
  data: string,
  clientPublicKeyString: string,
  serverPublicKey: JsonWebKey
): Promise<HpkeEncryptedData> {
  // 1. Encrypt data with server public key first
  const encryptedForServer = await hpkeEncrypt(data, serverPublicKey);

  // 2. Send encrypted data + client public key to server
  const res = await fetch(`${SERVER_URL}/api/server-encrypt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      encryptedData: encryptedForServer.encrypted,
      clientPublicKey: clientPublicKeyString,
    }),
  });
  return await res.json();
}

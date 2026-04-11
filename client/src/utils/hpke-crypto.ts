import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import {
  concatUint8Arrays,
  uint8ArrayToBase64,
  base64ToUint8Array,
  stringToUint8Array,
  uint8ArrayToString,
} from "uint8array-extras";

// ─── Seal/Unseal Wrapper Functions (from operation.ts) ─────

// Min 3, Max 9
const WRAPPER_LENGTH = 5

// Taken and modified from
// https://github.com/validatorjs/validator.js/blob/master/src/lib/isBase64.js
const isBase64String = (str: string) => {
  const notBase64 = /[^A-Z0-9+/=]/i
  const len = str.length

  if (len % 4 !== 0 || notBase64.test(str)) {
    return false
  }

  const firstPaddingChar = str.indexOf('=')

  return (
    firstPaddingChar === -1 || firstPaddingChar === len - 1 || (firstPaddingChar === len - 2 && str[len - 1] === '=')
  )
}

// Use native crypto (available in both browser and Node.js 19+)
const getRandomValues = (array: Uint32Array): Uint32Array => {
  const crypto = typeof globalThis.crypto !== 'undefined' && globalThis.crypto
    ? globalThis.crypto
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    : ((globalThis as any).require('crypto') as { webcrypto: Crypto }).webcrypto

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  crypto.getRandomValues(array as any)
  return array
}

// Advices from https://github.com/gkouziik/eslint-plugin-security-node/blob/master/docs/rules/detect-insecure-randomness.md
// Divide a random UInt32 by the maximum value (2^32 -1) to get a result between 0 and 1
const secureMathRandom = () => getRandomValues(new Uint32Array(1))[0] / 4294967295

// Taken from https://www.programiz.com/javascript/examples/generate-random-strings
const generateWrapperString = () =>
  secureMathRandom()
    .toString(36)
    .substring(2, 2 + WRAPPER_LENGTH)

const wrapBase64 = (base64: string) => {
  const prefix = generateWrapperString()
  const suffix = prefix

  // Count padding
  const paddingMatch = base64.match(/=+$/)
  const paddingCount = paddingMatch ? paddingMatch[0].length : 0

  // Remove padding from base64
  const base64WithoutPadding = base64.replace(/=+$/, '')

  // Format: prefix + base64WithoutPadding + suffix + paddingCount
  return `${prefix}${base64WithoutPadding}${suffix}${paddingCount}`
}

const unwrapBase64 = (str: string) => {
  const strLength = str.length

  // Extract prefix (first 5 chars)
  const prefix = str.substring(0, WRAPPER_LENGTH)

  // Extract suffix (5 chars before the last digit)
  const suffix = str.substring(strLength - WRAPPER_LENGTH - 1, strLength - 1)

  // Extract padding count (last digit)
  const paddingCount = parseInt(str.substring(strLength - 1), 10)

  // Validate prefix matches suffix
  if (prefix === suffix) {
    // Extract base64 (between prefix and suffix)
    const base64WithoutPadding = str.substring(WRAPPER_LENGTH, strLength - WRAPPER_LENGTH - 1)

    // Add padding back
    const padding = '='.repeat(paddingCount)
    const result = base64WithoutPadding + padding

    return result
  }

  return str
}

/**
 * Seal data using recipient's public key
 * Returns a wrapped base64 string containing ciphertext + encapsulated key
 */
export const seal = async (suite: CipherSuite, publicKeyB64: string, plainText: string) => {
  const publicKey = base64ToArrayBuffer(publicKeyB64)
  const { ct: cipherText, enc: encapsulatedKey } = await suite.seal(
    {
      recipientPublicKey: await suite.kem.importKey('raw', publicKey),
    },
    new TextEncoder().encode(plainText),
  )

  const header = stringToUint8Array(`${cipherText.byteLength}`)

  const base64Result = uint8ArrayToBase64(
    concatUint8Arrays([
      // index 0 --> index 1
      new Uint8Array([header.byteLength]),
      // index 1 --> index (header.byteLength + 1)
      header,
      // index (header.byteLength + 1) --> (header.byteLength + 1) + parseInt(header)
      new Uint8Array(cipherText),
      // (header.byteLength + 1) + parseInt(header) --> end
      new Uint8Array(encapsulatedKey),
    ]),
  )

  const wrappedResult = wrapBase64(base64Result)

  return wrappedResult
}

/**
 * Unseal data using your private key
 * Accepts a wrapped base64 string and returns the decrypted plaintext
 */
export const unseal = async (suite: CipherSuite, privateKey: CryptoKey, cipher: string) => {
  const unwrappedCipher = unwrapBase64(cipher)

  if (isBase64String(unwrappedCipher)) {
    try {
      const data = base64ToUint8Array(unwrappedCipher)

      const headerSize = data[0] ?? 0
      const cipherSize = parseInt(uint8ArrayToString(data.subarray(1, headerSize + 1)), 10)
      const cipherStart = headerSize + 1
      const cipherEnd = headerSize + 1 + cipherSize
      const cipherText = data.subarray(cipherStart, cipherEnd)
      const encapsulatedKey = data.subarray(cipherEnd)

      return new TextDecoder().decode(
        await suite.open(
          {
            recipientKey: privateKey,
            enc: encapsulatedKey,
          },
          cipherText,
        ),
      )
    } catch (error) {
      console.error('unseal error:', error)
      throw error
    }
  }

  return cipher
}

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
  ciphertext?: string; // base64
  enc?: string; // base64
  encrypted?: string; // combined base64 string (old format)
  sealed?: string; // sealed wrapped string (new format)
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
  // Handle sealed format first
  if (encrypted.sealed) {
    return await unseal(suite, privateKey, encrypted.sealed)
  }

  // Handle combined string format (old)
  let ciphertext: string
  let enc: string

  if (encrypted.encrypted) {
    const parsed = JSON.parse(atob(encrypted.encrypted))
    ciphertext = parsed.ciphertext
    enc = parsed.enc
  } else {
    ciphertext = encrypted.ciphertext!
    enc = encrypted.enc!
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

export async function getServerPublicKeyRaw(): Promise<string> {
  const res = await fetch(`${SERVER_URL}/api/server-public-key`);
  const data = await res.json();
  return data.data;
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
  const result = await res.json();

  // Server now returns { sealed: "..." } format
  if (result.sealed) {
    return { sealed: result.sealed };
  }

  // Fallback to old format
  return result;
}

// ─── Server Seal/Unseal API Helpers ──────────────────────────

export async function serverSeal(
  data: string,
  serverPublicKey: JsonWebKey
): Promise<{ sealed: string }> {
  const res = await fetch(`${SERVER_URL}/api/seal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      data,
      recipientPublicKey: publicKeyToString(serverPublicKey),
    }),
  });
  return await res.json();
}

export async function serverUnseal(sealed: string): Promise<string> {
  const res = await fetch(`${SERVER_URL}/api/unseal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sealed }),
  });
  const data = await res.json();
  return data.data;
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

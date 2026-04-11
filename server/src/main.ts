import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { seal, unseal } from "./seal-unseal";

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});

const app = express();
app.use(
  bodyParser.json({
    limit: "50mb",
  })
);
app.use(
  cors({
    origin: "http://localhost:5173",
    exposedHeaders: ["*"],
  })
);

// ─── Helpers ───────────────────────────────────────────────

const arrayBufferToBase64 = (buffer: ArrayBuffer): string =>
  Buffer.from(buffer).toString("base64");

const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  // Handle base64url encoding (JWK uses - and _ instead of + and /)
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const buf = Buffer.from(normalized + padding, "base64");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
};

// ─── Key Storage ─────────────────────────────────────────────

interface KeyPair {
  publicKeyRaw: ArrayBuffer;  // Raw uncompressed EC point
  privateKeyJwk: JsonWebKey;   // JWK for private key (easier to persist)
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

let serverKeyPair: KeyPair | null = null;

const KEY_FILE = join(__dirname, "server-keys-hpke.json");

async function loadKeyPair(): Promise<KeyPair | null> {
  try {
    if (!existsSync(KEY_FILE)) return null;
    const raw = readFileSync(KEY_FILE, "utf-8");
    const data = JSON.parse(raw);

    // Import keys
    const [publicKey, privateKey] = await Promise.all([
      crypto.subtle.importKey(
        "raw",
        new Uint8Array(data.publicKeyRaw),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      ),

      crypto.subtle.importKey(
        "jwk",
        data.privateKeyJwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      ),
    ]);

    return {
      publicKeyRaw: new Uint8Array(data.publicKeyRaw).buffer,
      privateKeyJwk: data.privateKeyJwk,
      publicKey: publicKey as CryptoKey,
      privateKey: privateKey as CryptoKey,
    };
  } catch {
    return null;
  }
}

function saveKeyPair(kp: KeyPair) {
  // Convert ArrayBuffer to array for JSON serialization
  const publicKeyRawArray = Array.from(new Uint8Array(kp.publicKeyRaw));

  writeFileSync(KEY_FILE, JSON.stringify({
    publicKeyRaw: publicKeyRawArray,
    privateKeyJwk: kp.privateKeyJwk,
  }, null, 2));
}

async function generateKeyPair(): Promise<KeyPair> {
  const kp = await suite.kem.generateKeyPair();

  // Export public key as raw uncompressed point (0x04 || x || y)
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", kp.publicKey as CryptoKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", kp.privateKey as CryptoKey);

  // Build uncompressed point from JWK
  const x = base64ToArrayBuffer(publicKeyJwk.x as string);
  const y = base64ToArrayBuffer(publicKeyJwk.y as string);

  const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
  uncompressed[0] = 0x04; // Uncompressed point marker
  uncompressed.set(new Uint8Array(x), 1);
  uncompressed.set(new Uint8Array(y), 1 + x.byteLength);

  const keyPair: KeyPair = {
    publicKeyRaw: uncompressed.buffer,
    privateKeyJwk: privateKeyJwk as JsonWebKey,
    publicKey: kp.publicKey as CryptoKey,
    privateKey: kp.privateKey as CryptoKey,
  };

  saveKeyPair(keyPair);
  return keyPair;
}

async function initKeyPair() {
  const fromFile = await loadKeyPair();
  if (fromFile) {
    serverKeyPair = fromFile;
    console.log("✅ Loaded existing HPKE key pair from disk");
  } else {
    serverKeyPair = await generateKeyPair();
    console.log("✅ Generated new HPKE key pair and saved to disk");
  }
}

// Import raw public key bytes to CryptoKey
async function importPublicKey(rawBytes: ArrayBuffer): Promise<CryptoKey> {
  return await suite.kem.importKey("raw", rawBytes) as CryptoKey;
}

// ─── Request/Response Types ───────────────────────────────────

interface ApiRequest {
  data?: string;
  recipientPublicKey?: string;
  clientPublicKey?: string;
  encryptedData?: string;
  sealed?: string;
}

// ─── HTTP Handlers ────────────────────────────────────────────

app.get("/", (_, res) => {
  res.json({ message: "HPKE Encryption Server" });
});

// Get server public key (raw bytes, base64 encoded)
app.get("/api/server-public-key", async (_req, res) => {
  if (!serverKeyPair) await initKeyPair();

  // Export public key as raw uncompressed point
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", serverKeyPair!.publicKey);
  const x = base64ToArrayBuffer(publicKeyJwk.x as string);
  const y = base64ToArrayBuffer(publicKeyJwk.y as string);

  const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
  uncompressed[0] = 0x04; // Uncompressed point marker
  uncompressed.set(new Uint8Array(x), 1);
  uncompressed.set(new Uint8Array(y), 1 + x.byteLength);

  const publicKeyB64 = arrayBufferToBase64(uncompressed.buffer);

  res.json({
    data: publicKeyB64,
  });
});

// Encrypt: client encrypt pakai public key server → server decrypt
app.post("/api/encrypt", async (req, res) => {
  try {
    const { data, recipientPublicKey } = req.body as ApiRequest;

    if (!data || !recipientPublicKey) {
      res.status(400).json({ error: "Missing 'data' or 'recipientPublicKey'" });
      return;
    }

    // Parse public key from base64 string or JWK
    let publicKeyBytes: ArrayBuffer;
    if (typeof recipientPublicKey === "string") {
      publicKeyBytes = base64ToArrayBuffer(recipientPublicKey);
    } else {
      res.status(400).json({ error: "recipientPublicKey must be a base64 string" });
      return;
    }

    const publicKey = await importPublicKey(publicKeyBytes);

    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey });
    const ct = await sender.seal(new TextEncoder().encode(data));

    const ciphertextB64 = arrayBufferToBase64(ct);
    const encB64 = arrayBufferToBase64(sender.enc);

    res.json({
      data: btoa(JSON.stringify({ ciphertext: ciphertextB64, enc: encB64 })),
    });
  } catch (error) {
    console.error("Encrypt error:", error);
    res.status(500).json({
      error: "Encryption failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Decrypt: server decrypt pakai private key (using seal/unseal format)
app.post("/api/decrypt", async (req, res) => {
  try {
    const { data } = req.body as ApiRequest;

    if (!data) {
      res.status(400).json({ error: "Missing 'data'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    const plaintext = await unseal(suite, serverKeyPair.privateKey, data);

    res.json({ data: plaintext });
  } catch (error) {
    console.error("Decrypt error:", error);
    res.status(400).json({
      error: "Decryption failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Server encrypt → client decrypt (unseal → re-seal)
app.post("/api/server-encrypt", async (req, res) => {
  try {
    const { data, clientPublicKey } = req.body as ApiRequest;

    if (!clientPublicKey || !data) {
      res.status(400).json({ error: "Missing 'data' or 'clientPublicKey'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    // Unseal the data with server private key
    const plaintext = await unseal(suite, serverKeyPair.privateKey, data);

    // Seal with client public key (could be JWK or raw base64)
    let publicKeyB64: string;
    if (typeof clientPublicKey === "string") {
      publicKeyB64 = clientPublicKey;

      // If it's a JWK base64, decode and convert to raw bytes
      try {
        const jwkJSON = JSON.parse(Buffer.from(clientPublicKey, 'base64').toString());
        if (jwkJSON.x && jwkJSON.y) {
          const x = base64ToArrayBuffer(jwkJSON.x);
          const y = base64ToArrayBuffer(jwkJSON.y);
          const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
          uncompressed[0] = 0x04;
          uncompressed.set(new Uint8Array(x), 1);
          uncompressed.set(new Uint8Array(y), 1 + x.byteLength);
          publicKeyB64 = arrayBufferToBase64(uncompressed.buffer);
        }
      } catch {
        // Not a JWK, assume it's already raw bytes base64
      }
    } else {
      res.status(400).json({ error: "clientPublicKey must be a base64 string" });
      return;
    }

    const sealed = await seal(suite, publicKeyB64, plaintext);

    res.json({ data: sealed });
  } catch (error) {
    console.error("Server encrypt error:", error);
    res.status(500).json({
      error: "Encryption failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Seal: server seal data with recipient public key using seal operation
// OR: unseal incoming sealed data + re-seal with client public key
app.post("/api/seal", async (req, res) => {
  try {
    const { data, recipientPublicKey } = req.body as ApiRequest;

    if (!data) {
      res.status(400).json({ error: "Missing 'data'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    // If only data is provided (sealed payload), unseal it and re-seal with client public key
    if (!recipientPublicKey) {
      // Unseal the incoming sealed data
      const combinedPayload = await unseal(suite, serverKeyPair.privateKey, data);

      // Parse combined JSON: { "data": "...", "publicKey": "..." }
      let payload: { data: string; publicKey: string };
      try {
        payload = JSON.parse(combinedPayload);
      } catch {
        res.status(400).json({ error: "Invalid payload format" });
        return;
      }

      if (!payload.data) {
        res.status(400).json({ error: "Missing 'data' in payload" });
        return;
      }

      if (!payload.publicKey) {
        res.status(400).json({ error: "Missing 'publicKey' in payload" });
        return;
      }

      // Re-seal with client's public key (could be JWK or raw base64)
      let publicKeyB64 = payload.publicKey;

      // If it's a JWK base64, decode and convert to raw bytes
      try {
        const jwkJSON = JSON.parse(Buffer.from(payload.publicKey, 'base64').toString());
        const x = base64ToArrayBuffer(jwkJSON.x);
        const y = base64ToArrayBuffer(jwkJSON.y);
        const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
        uncompressed[0] = 0x04;
        uncompressed.set(new Uint8Array(x), 1);
        uncompressed.set(new Uint8Array(y), 1 + x.byteLength);
        publicKeyB64 = arrayBufferToBase64(uncompressed.buffer);
      } catch {
        // Not a JWK, assume it's already raw bytes base64
      }

      const sealed = await seal(suite, publicKeyB64, payload.data);

      res.json({ data: sealed });
      return;
    }

    // If recipientPublicKey is provided, seal data directly
    let publicKeyB64: string;
    if (typeof recipientPublicKey === "string") {
      publicKeyB64 = recipientPublicKey;

      // If it's a JWK base64, decode and convert to raw bytes
      try {
        const jwkJSON = JSON.parse(Buffer.from(recipientPublicKey, 'base64').toString());
        if (jwkJSON.x && jwkJSON.y) {
          const x = base64ToArrayBuffer(jwkJSON.x);
          const y = base64ToArrayBuffer(jwkJSON.y);
          const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
          uncompressed[0] = 0x04;
          uncompressed.set(new Uint8Array(x), 1);
          uncompressed.set(new Uint8Array(y), 1 + x.byteLength);
          publicKeyB64 = arrayBufferToBase64(uncompressed.buffer);
        }
      } catch {
        // Not a JWK, assume it's already raw bytes base64
      }
    } else {
      res.status(400).json({ error: "recipientPublicKey must be a base64 string" });
      return;
    }

    const sealed = await seal(suite, publicKeyB64, data);

    res.json({ data: sealed });
  } catch (error) {
    console.error("Seal error:", error);
    res.status(500).json({
      error: "Sealing failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Unseal: server unseal data with server private key
app.post("/api/unseal", async (req, res) => {
  try {
    const { data } = req.body as ApiRequest;

    if (!data) {
      res.status(400).json({ error: "Missing 'data'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    const plaintext = await unseal(suite, serverKeyPair.privateKey, data);

    res.json({ data: plaintext });
  } catch (error) {
    console.error("Unseal error:", error);
    res.status(400).json({
      error: "Unsealing failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// External API Proxy: Seal → BE → jsonplaceholder → Seal
app.post("/api/external-api", async (req, res) => {
  try {
    const { data } = req.body as ApiRequest;

    if (!data) {
      res.status(400).json({ error: "Missing 'data'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    // 1. Unseal client data (contains { data, publicKey })
    const combinedPayload = await unseal(suite, serverKeyPair.privateKey, data);

    // 2. Parse combined JSON: { "data": "...", "publicKey": "..." }
    let payload: { data: string; publicKey: string };
    try {
      payload = JSON.parse(combinedPayload);
    } catch {
      res.status(400).json({ error: "Invalid payload format" });
      return;
    }

    if (!payload.data) {
      res.status(400).json({ error: "Missing 'data' in payload" });
      return;
    }

    if (!payload.publicKey) {
      res.status(400).json({ error: "Missing 'publicKey' in payload" });
      return;
    }

    // 3. Parse client public key (could be JWK or raw base64)
    let clientPublicKeyB64 = payload.publicKey;

    // If it's a JWK base64, decode and convert to raw bytes
    try {
      const jwkJSON = JSON.parse(Buffer.from(payload.publicKey, 'base64').toString());
      if (jwkJSON.x && jwkJSON.y) {
        const x = base64ToArrayBuffer(jwkJSON.x);
        const y = base64ToArrayBuffer(jwkJSON.y);
        const uncompressed = new Uint8Array(1 + x.byteLength + y.byteLength);
        uncompressed[0] = 0x04;
        uncompressed.set(new Uint8Array(x), 1);
        uncompressed.set(new Uint8Array(y), 1 + x.byteLength);
        clientPublicKeyB64 = arrayBufferToBase64(uncompressed.buffer);
      }
    } catch {
      // Not a JWK, assume it's already raw bytes base64
    }

    // 4. Send data to jsonplaceholder
    let jsonPayload: any;
    try {
      jsonPayload = JSON.parse(payload.data);
    } catch {
      // Not JSON, wrap it
      jsonPayload = {
        title: payload.data,
        body: payload.data,
        userId: 1,
      };
    }

    const jpRes = await fetch("https://jsonplaceholder.typicode.com/posts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(jsonPayload),
    });

    const jpResBody = await jpRes.text();

    // 5. Seal jsonplaceholder response with client public key
    const sealedResponse = await seal(suite, clientPublicKeyB64, jpResBody);

    res.json({ data: sealedResponse });
  } catch (error) {
    console.error("External API error:", error);
    res.status(500).json({
      error: "External API call failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// ─── Start ─────────────────────────────────────────────────

initKeyPair().then(() => {
  console.log("Server ready");
});

app.listen(9002, () => {
  console.log("HPKE Server is running on http://localhost:9002");
});

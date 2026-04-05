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
  const buf = Buffer.from(base64, "base64");
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
};

// Persisted key pair (saved to disk so it survives restarts)
const KEY_FILE = join(__dirname, "server-keys-hpke.json");

let serverKeyPair: {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
} | null = null;

async function exportKeyPair(
  publicKey: CryptoKey,
  privateKey: CryptoKey
): Promise<{ publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }> {
  return {
    publicKeyJwk: await crypto.subtle.exportKey("jwk", publicKey),
    privateKeyJwk: await crypto.subtle.exportKey("jwk", privateKey),
  };
}

async function importKeyPair(
  publicKeyJwk: JsonWebKey,
  privateKeyJwk: JsonWebKey
): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  return { publicKey, privateKey };
}

function loadKeyPair(): { publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey } | null {
  try {
    if (!existsSync(KEY_FILE)) return null;
    const raw = readFileSync(KEY_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function saveKeyPair(keys: { publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }) {
  writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
}

async function generateKeyPair() {
  const kp = await suite.kem.generateKeyPair();
  const { publicKeyJwk, privateKeyJwk } = await exportKeyPair(kp.publicKey, kp.privateKey);

  serverKeyPair = { publicKey: kp.publicKey, privateKey: kp.privateKey };
  saveKeyPair({ publicKeyJwk, privateKeyJwk });
  return { publicKey: kp.publicKey, publicKeyJwk };
}

async function initKeyPair() {
  const fromFile = loadKeyPair();
  if (fromFile) {
    const keys = await importKeyPair(fromFile.publicKeyJwk, fromFile.privateKeyJwk);
    serverKeyPair = keys;
    console.log("✅ Loaded existing HPKE key pair from disk");
  } else {
    await generateKeyPair();
    console.log("✅ Generated new HPKE key pair and saved to disk");
  }
}

// ─── Routes ────────────────────────────────────────────────

app.get("/", (_, res) => {
  res.json({ message: "HPKE Encryption Server" });
});

// Get server public key
app.get("/api/public-key", async (_req, res) => {
  if (!serverKeyPair) await initKeyPair();
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", serverKeyPair!.publicKey);
  res.json({
    // publicKey: publicKeyJwk,
    publicKeyString: Buffer.from(JSON.stringify(publicKeyJwk)).toString("base64"),
  });
});

// Encrypt: client encrypt pakai public key server → server decrypt
app.post("/api/encrypt", async (req, res) => {
  try {
    const { data, recipientPublicKey } = req.body;
    if (!data || !recipientPublicKey) {
      res.status(400).json({ error: "Missing 'data' or 'recipientPublicKey'" });
      return;
    }

    // Handle JWK object or base64 string
    let jwk: JsonWebKey;
    if (typeof recipientPublicKey === "string") {
      jwk = JSON.parse(Buffer.from(recipientPublicKey, "base64").toString());
    } else if (recipientPublicKey.kty) {
      jwk = recipientPublicKey;
    } else if (recipientPublicKey.publicKey?.kty) {
      jwk = recipientPublicKey.publicKey;
    } else {
      res.status(400).json({ error: "recipientPublicKey must be a valid JWK object or base64 string" });
      return;
    }

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );

    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey });
    const ct = await sender.seal(new TextEncoder().encode(data));

    const ciphertextB64 = arrayBufferToBase64(ct);
    const encB64 = arrayBufferToBase64(sender.enc);

    res.json({
      encrypted: btoa(JSON.stringify({ ciphertext: ciphertextB64, enc: encB64 })),
    });
  } catch (error) {
    console.error("Encrypt error:", error);
    res.status(500).json({
      error: "Encryption failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Decrypt: server decrypt pakai private key
app.post("/api/decrypt", async (req, res) => {
  try {
    let { ciphertext, enc, encrypted } = req.body;

    // Handle combined encrypted string
    if (encrypted && (!ciphertext || !enc)) {
      const parsed = JSON.parse(atob(encrypted));
      ciphertext = parsed.ciphertext;
      enc = parsed.enc;
    }

    if (!ciphertext || !enc) {
      res.status(400).json({ error: "Missing 'ciphertext', 'enc', or 'encrypted'" });
      return;
    }

    if (!serverKeyPair) {
      res.status(400).json({ error: "Server key pair not initialized" });
      return;
    }

    const recipient = await suite.createRecipientContext({
      recipientKey: serverKeyPair.privateKey,
      enc: base64ToArrayBuffer(enc),
    });
    const pt = await recipient.open(base64ToArrayBuffer(ciphertext));

    res.json({ data: new TextDecoder().decode(pt) });
  } catch (error) {
    console.error("Decrypt error:", error);
    res.status(400).json({
      error: "Decryption failed",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

// Server encrypt → client decrypt
// Supports: plaintext data OR encrypted data (encrypted with server public key)
app.post("/api/server-encrypt", async (req, res) => {
  try {
    let { data, encryptedData, clientPublicKey } = req.body;
    if (!clientPublicKey) {
      res.status(400).json({ error: "Missing 'clientPublicKey'" });
      return;
    }

    // If encryptedData provided, decrypt it first with server private key
    let plaintext: string;
    if (encryptedData) {
      if (!serverKeyPair) {
        res.status(400).json({ error: "Server key pair not initialized" });
        return;
      }

      // Parse encryptedData
      let parsed: { ciphertext: string; enc: string };
      if (typeof encryptedData === "string") {
        parsed = JSON.parse(atob(encryptedData));
      } else {
        parsed = encryptedData;
      }

      const recipient = await suite.createRecipientContext({
        recipientKey: serverKeyPair.privateKey,
        enc: base64ToArrayBuffer(parsed.enc),
      });
      const pt = await recipient.open(base64ToArrayBuffer(parsed.ciphertext));
      plaintext = new TextDecoder().decode(pt);
    } else if (data) {
      plaintext = data;
    } else {
      res.status(400).json({ error: "Missing 'data' or 'encryptedData'" });
      return;
    }

    // Handle clientPublicKey
    let jwk: JsonWebKey;
    if (typeof clientPublicKey === "string") {
      jwk = JSON.parse(Buffer.from(clientPublicKey, "base64").toString());
    } else if (clientPublicKey.kty) {
      jwk = clientPublicKey;
    } else if (clientPublicKey.publicKey?.kty) {
      jwk = clientPublicKey.publicKey;
    } else {
      res.status(400).json({ error: "clientPublicKey must be a valid JWK object or base64 string" });
      return;
    }

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );

    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey });
    const ct = await sender.seal(new TextEncoder().encode(plaintext));

    const ciphertextB64 = arrayBufferToBase64(ct);
    const encB64 = arrayBufferToBase64(sender.enc);

    res.json({
      encrypted: btoa(JSON.stringify({ ciphertext: ciphertextB64, enc: encB64 })),
    });
  } catch (error) {
    console.error("Server encrypt error:", error);
    res.status(500).json({
      error: "Encryption failed",
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

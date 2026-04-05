# HPKE Encryption Server

Server enkripsi menggunakan **HPKE** (Hybrid Public Key Encryption) — standar [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).

## Tech Stack

| Komponen | Library |
|---|---|
| Runtime | Node.js + Express |
| HPKE | `@hpke/core` |
| KEM | ECDH P-256 (`DhkemP256HkdfSha256`) |
| KDF | HKDF-SHA-256 |
| AEAD | AES-128-GCM |

## Cara Menjalankan

```bash
cd server
npm install
npm run start:hpke
```

Server berjalan di **`http://localhost:9002`**.

---

## Key Management

### Persistensi Key Pair

Server menyimpan RSA key pair di file `server-keys-hpke.json` (otomatis dibuat saat pertama kali start). Key pair **tidak berubah** walau server di-restart.

```
server/
├── server-keys-hpke.json    ← ECDH key pair (persisted)
└── src/hpke-server.ts
```

---

## API Endpoints

### 1. `GET /api/public-key`

Ambil public key server dalam format JWK dan base64 string.

**Response:**
```json
{
  "publicKey": {
    "key_ops": [],
    "ext": true,
    "kty": "EC",
    "x": "JhFvqwMAn5DHeAifWz_eQlsbV3gI840CAm-bLKJjd4A",
    "y": "omwNMaNbA5gEA-EdWDMaM6PH4k0NqXd7c0Cuf94mEMU",
    "crv": "P-256"
  },
  "publicKeyString": "eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVlLCJrdHkiOiJFQyIs..."
}
```

---

### 2. `POST /api/encrypt` — Client Encrypt → Server Decrypt

Client mengenkripsi data menggunakan **server public key**. Server bisa mendekripsi hasilnya.

**Request:**
```json
{
  "data": "rahasia dari client",
  "recipientPublicKey": "<base64 string atau JWK object>"
}
```

`recipientPublicKey` bisa dalam 3 format:
- **Base64 string**: `"eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVl..."`
- **JWK object**: `{ "kty": "EC", "x": "...", "y": "...", "crv": "P-256" }`
- **Wrapped JWK**: `{ "publicKey": { "kty": "EC", ... } }`

**Response:**
```json
{
  "encrypted": "eyJjaXBoZXJ0ZXh0IjoiUUJUcGEwS2NLS3JQc21m..."
}
```

**Flow:**
```
┌────────┐  encrypt(serverPublicKey)   ┌────────┐
│ Client │ ──────────────────────────→ │ Server │
│        │   { encrypted: "..." }      │        │
└────────┘                             └────────┘
```

**Contoh curl:**
```bash
# 1. Ambil public key
curl http://localhost:9002/api/public-key

# 2. Encrypt
curl -X POST http://localhost:9002/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "data": "rahasia",
    "recipientPublicKey": "eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVl..."
  }'
```

---

### 3. `POST /api/decrypt` — Server Decrypt

Server mendekripsi data yang dienkripsi dengan **server public key**.

**Request (format 1 — combined string):**
```json
{
  "encrypted": "eyJjaXBoZXJ0ZXh0IjoiUUJUcGEwS2NLS3JQc21m..."
}
```

**Request (format 2 — separate fields):**
```json
{
  "ciphertext": "QBTpa0KcKKrPsmfLDhZTLELChJr7gm+KpP0s7A==",
  "enc": "BOVpLaHVtbqPf0CNHN00dn++KDFOGuqbS/euGDgfSyvFlj3K..."
}
```

**Response:**
```json
{
  "data": "rahasia dari client"
}
```

---

### 4. `POST /api/server-encrypt` — Server Encrypt → Client Decrypt

Server mengenkripsi data menggunakan **client public key**. Hanya client yang bisa mendekripsi.

**Request (plaintext):**
```json
{
  "data": "balasan dari server",
  "clientPublicKey": "<base64 string atau JWK object>"
}
```

**Request (encrypted data — double encryption):**
```json
{
  "encryptedData": "eyJjaXBoZXJ0ZXh0IjoiUUJUcGEwS2NLS3JQc21m...",
  "clientPublicKey": "<base64 string atau JWK object>"
}
```

Ketika `encryptedData` dikirim:
1. Server **decrypt** dulu pakai server private key
2. Hasil decrypt **di-encrypt ulang** pakai client public key
3. Return hasil encrypt

**Response:**
```json
{
  "encrypted": "eyJjaXBoZXJ0ZXh0IjoiUUJUcGEwS2NLS3JQc21m..."
}
```

**Flow (plaintext):**
```
┌────────┐  data + clientPublicKey     ┌────────┐
│ Client │ ──────────────────────────→ │ Server │
│        │                             │ encrypt(clientPublicKey)
│        │ ←────────────────────────── │        │
│        │   { encrypted: "..." }      │        │
└────────┘                             └────────┘
```

**Flow (encrypted data — double encryption):**
```
┌────────┐  encrypt(serverPublicKey)   ┌────────┐
│ Client │ ──────────────────────────→ │ Server │
│        │   { encryptedData,          │ decrypt → encrypt(clientPublicKey)
│        │     clientPublicKey }       │        │
│        │ ←────────────────────────── │        │
│        │   { encrypted: "..." }      │        │
└────────┘                             └────────┘
```

---

## Format Data

### Public Key

| Format | Contoh |
|---|---|
| JWK Object | `{ "kty": "EC", "x": "...", "y": "...", "crv": "P-256" }` |
| Base64 String | `eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVl...` |

### Encrypted Data

| Format | Contoh |
|---|---|
| Combined string | `eyJjaXBoZXJ0ZXh0IjoiUUJUcGEwS2NLS3JQc21m...` |
| JSON Object | `{ "ciphertext": "...", "enc": "..." }` |

Combined string = `btoa(JSON.stringify({ ciphertext, enc }))`

---

## 3 Skenario Penggunaan

| Skenario | Encrypt Pakai | Decrypt Pakai |
|---|---|---|
| **Client → Server** | Server public key | Server private key |
| **Server → Client** | Client public key | Client private key |
| **Client → Server → Client** (double) | Server public key → Client public key | Server private key → Client private key |

---

## Client Integration

### Install
```bash
npm install @hpke/core
```

### Basic Usage
```typescript
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});

// Generate key pair
const keyPair = await suite.kem.generateKeyPair();

// Export public key ke JWK
const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

// Encrypt
const sender = await suite.createSenderContext({ recipientPublicKey: serverPublicKey });
const ciphertext = await sender.seal(new TextEncoder().encode("rahasia"));

// Decrypt
const recipient = await suite.createRecipientContext({
  recipientKey: keyPair.privateKey,
  enc: sender.enc,
});
const plaintext = await recipient.open(ciphertext);
```

---

## Keamanan

- **Private key tidak pernah dikirim** — selalu disimpan di sisi pemilik
- **Public key bisa dibagikan** — digunakan untuk enkripsi
- **Data dienkripsi end-to-end** — server tidak bisa membaca data yang dienkripsi untuk client
- **Key pair persist** — tidak berubah saat restart, data lama tetap bisa didekripsi

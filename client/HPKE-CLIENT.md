# HPKE Client Integration

Panduan penggunaan enkripsi HPKE di sisi client (Vue.js + TypeScript).

## Instalasi

```bash
cd client
npm install @hpke/core uint8array-extras
```

---

## File Structure

```
client/src/
├── utils/
│   └── hpke-crypto-go.ts      ← Utility functions untuk HPKE seal/unseal
└── views/
    └── HomeView.vue           ← Contoh implementasi lengkap
```

---

## Quick Start

### 1. Inisialisasi HPKE Suite

```typescript
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core'

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(), // ECDH P-256
  kdf: new HkdfSha256(), // HKDF-SHA-256
  aead: new Aes128Gcm(), // AES-128-GCM
})
```

### 2. Generate Key Pair

```typescript
const keyPair = await suite.kem.generateKeyPair()
// keyPair = { publicKey: CryptoKey, privateKey: CryptoKey }
```

### 3. Seal Data

Seal menggabungkan ciphertext dan encapsulated key menjadi satu wrapped string.

```typescript
import { seal, suite } from './utils/hpke-crypto-go'

const sealed = await seal(suite, serverPublicKeyRaw, 'rahasia')
// "abcde...xyz3" - format: prefix + base64(header + ct + enc) + suffix + padding
```

### 4. Unseal Data

```typescript
import { unseal, suite } from './utils/hpke-crypto-go'

const plaintext = await unseal(suite, privateKey, sealed)
// "rahasia"
```

---

## Flow 1: Client → Server → Client

Client seal data → Server unseal → Server re-seal → Client unseal.

```typescript
// === CLIENT ===

// 1. Ambil server public key
const res = await fetch('http://localhost:9003/api/server-public-key')
const { data: serverPublicKeyRaw } = await res.json()

// 2. Seal data (gabung data + clientPublicKey)
const combinedPayload = JSON.stringify({
  data: 'rahasia',
  publicKey: clientPublicKeyString,
})
const sealed = await seal(suite, serverPublicKeyRaw, combinedPayload)

// 3. Kirim ke server
const result = await fetch('http://localhost:9003/api/seal', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: sealed }),
}).then((r) => r.json())

// 4. Unseal response
const plaintext = await unseal(suite, clientPrivateKey, result.data)
console.log(plaintext) // "rahasia"
```

**Flow:**

```
Client: seal(serverPubKey, { data, publicKey }) → sealedData
       → POST /api/seal { data: sealedData }
Server: unseal → { data, publicKey }
       → seal(clientPubKey, data) → sealedResponse
Client: unseal(clientPrivateKey, sealedResponse) → plaintext
```

---

## Flow 2: External API via BE

Client seal → BE unseal → BE kirim ke API eksternal → BE seal response → Client unseal.

```typescript
// === CLIENT ===

// 1. Seal data + publicKey
const combinedPayload = JSON.stringify({
  data: 'rahasia',
  publicKey: clientPublicKeyString,
})
const sealed = await seal(suite, serverPublicKeyRaw, combinedPayload)

// 2. Kirim ke BE
const result = await fetch('http://localhost:9003/api/external-api', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: sealed }),
}).then((r) => r.json())

// 3. Unseal response dari API eksternal
const plaintext = await unseal(suite, clientPrivateKey, result.data)
console.log(plaintext) // Response dari API eksternal (JSON string)
```

**Flow:**

```
Client: seal(serverPubKey, { data, publicKey }) → sealedData
       → POST /api/external-api { data: sealedData }
Server: unseal → { data, publicKey }
       → POST https://jsonplaceholder.typicode.com/posts
       → seal(clientPubKey, apiResponse) → sealedResponse
Client: unseal(clientPrivateKey, sealedResponse) → apiResponse
```

---

## Server Endpoints

### `POST /api/seal`

Unseal data → parse payload → re-seal dengan client public key.

**Request:**

```json
{
  "data": "sealed_string_here"
}
```

**Response:**

```json
{
  "data": "sealed_response_here"
}
```

### `POST /api/external-api`

Unseal data → kirim ke API eksternal → seal response.

**Request:**

```json
{
  "data": "sealed_string_here"
}
```

**Response:**

```json
{
  "data": "sealed_api_response_here"
}
```

### `POST /api/unseal`

Unseal data dan return plaintext.

**Request:**

```json
{
  "data": "sealed_string_here"
}
```

**Response:**

```json
{
  "data": "decrypted plaintext"
}
```

---

## Utility Functions (`hpke-crypto-go.ts`)

### `seal(suite, publicKeyB64, plainText)`

Encrypt dan return wrapped base64 string.

```typescript
const sealed = await seal(suite, publicKeyRaw, 'rahasia')
```

### `unseal(suite, privateKey, cipher)`

Decrypt wrapped base64 string.

```typescript
const plaintext = await unseal(suite, privateKey, sealed)
```

### `getServerPublicKeyRaw()`

Ambil raw public key server (uncompressed EC point, base64).

```typescript
const pubKey = await getServerPublicKeyRaw()
```

### `serverUnseal(sealed)`

Kirim sealed ke server untuk unseal.

```typescript
const plaintext = await serverUnseal(sealed)
```

---

## Interface

### `HpkeEncryptedData`

```typescript
interface HpkeEncryptedData {
  ciphertext?: string // base64 ciphertext (legacy)
  enc?: string // base64 encapsulated key (legacy)
  encrypted?: string // combined base64 string (legacy)
  sealed?: string // sealed wrapped string (new format)
}
```

---

## Keamanan

| Prinsip                              | Implementasi                                                 |
| ------------------------------------ | ------------------------------------------------------------ |
| **Private key tidak pernah dikirim** | Selalu disimpan di client (memory)                           |
| **Public key bisa dibagikan**        | Dikirim sebagai raw base64 (uncompressed EC point)           |
| **Data terenkripsi end-to-end**      | Hanya penerima yang bisa unseal                              |
| **Forward secrecy**                  | Setiap seal menghasilkan ciphertext berbeda (random AES key) |
| **Compact format**                   | Wrapped base64 lebih efisien dari JSON terpisah (ct + enc)   |

---

## Troubleshooting

### `Invalid public key for the ciphersuite`

Penyebab: Public key format salah (harus raw uncompressed point, bukan JWK).

Solusi: Gunakan `getServerPublicKeyRaw()` untuk ambil public key dalam format raw.

### `atob` error: "The string to be decoded is not correctly encoded"

Penyebab: String yang diparsing bukan base64 valid.

Solusi:

- Pastikan server sudah running di port 9003
- Public key yang digunakan valid
- Sealed data tidak terpotong

### `Unseal failed: open: failed to decrypt`

Penyebab: Sealed data dienkripsi dengan public key yang berbeda dari private key yang digunakan.

Solusi:

- Pastikan public key yang digunakan untuk seal sesuai dengan private key untuk unseal
- Jangan restart server antara seal dan unseal (kecuali key pair persist)

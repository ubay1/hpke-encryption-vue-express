# HPKE Server (Express.js + TypeScript)

Server HPKE menggunakan Express.js dengan TypeScript dan library `@hpke/core`.

## Instalasi

```bash
cd server
npm install
```

## Menjalankan Server

```bash
npm start
```

Server berjalan di `http://localhost:9002`.

---

## HPKE Suite

| Komponen | Implementasi |
| -------- | ------------ |
| KEM      | DHKEM P-256  |
| KDF      | HKDF-SHA-256 |
| AEAD     | AES-128-GCM  |

---

## Key Management

Server menyimpan key pair di file `src/server-keys-hpke.json` (persistent). Key pair dibuat otomatis saat pertama kali server dijalankan.

```typescript
interface KeyPair {
  publicKeyRaw: ArrayBuffer; // Raw uncompressed EC point
  privateKeyJwk: JsonWebKey; // JWK for private key
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}
```

---

## Seal/Unseal Format

### Wrapped Format

```
prefix(5) + base64(headerSize + header + ciphertext + enc) + suffix(5) + paddingCount(1)
```

- **prefix/suffix**: random 5-char string (a-z0-9)
- **headerSize**: 1 byte, panjang header
- **header**: ciphertext length dalam string
- **ciphertext**: encrypted data
- **enc**: encapsulated key

### seal

```typescript
async function seal(
  suite: CipherSuite,
  publicKeyB64: string,
  plainText: string,
): Promise<string>;
```

Encrypt plaintext dan return wrapped sealed string.

### unseal

```typescript
async function unseal(
  suite: CipherSuite,
  privateKey: CryptoKey,
  cipher: string,
): Promise<string>;
```

Decrypt wrapped sealed string dan return plaintext.

---

## Request/Response Types

### `ApiRequest`

```typescript
interface ApiRequest {
  data?: string;
  recipientPublicKey?: string;
  clientPublicKey?: string;
  encryptedData?: string;
  sealed?: string;
}
```

### Response

Semua endpoint mengembalikan response dalam format:

```typescript
{
  data: string; // encrypted/decrypted data
}
```

---

## Endpoints

### `GET /api/server-public-key`

Return raw public key server (uncompressed EC point, base64).

**Response:**

```json
{
  "data": "base64_encoded_raw_public_key"
}
```

---

### `POST /api/seal`

Unseal data → parse payload → re-seal dengan client public key.

**Request:**

```json
{
  "data": "sealed_string_with_{data, publicKey}"
}
```

Payload di dalam sealed harus berupa JSON:

```json
{
  "data": "plaintext data",
  "publicKey": "base64_jwk_client_public_key"
}
```

**Response:**

```json
{
  "data": "sealed_response_with_client_public_key"
}
```

**Flow:**

1. Server unseal `data` → dapat `{ data, publicKey }`
2. Server parse `publicKey` (JWK) → convert ke raw EC point
3. Server seal `data` dengan client public key
4. Return sealed response

---

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

### `POST /api/external-api`

Unseal data → kirim ke API eksternal → seal response.

**Request:**

```json
{
  "data": "sealed_string_with_{data, publicKey}"
}
```

Payload di dalam sealed harus berupa JSON:

```json
{
  "data": "plaintext atau JSON string",
  "publicKey": "base64_jwk_client_public_key"
}
```

**Response:**

```json
{
  "data": "sealed_external_api_response"
}
```

**Flow:**

1. Server unseal `data` → dapat `{ data, publicKey }`
2. Server parse `data` (jika JSON, kirim as-is; jika bukan, wrap sebagai post)
3. Server POST ke `https://jsonplaceholder.typicode.com/posts`
4. Server seal response dengan client public key
5. Return sealed response

---

### `POST /api/encrypt` (Legacy)

Encrypt data dengan public key penerima (format lama, JSON terpisah).

**Request:**

```json
{
  "data": "plaintext",
  "recipientPublicKey": "base64_raw_public_key"
}
```

**Response:**

```json
{
  "data": "base64({ciphertext, enc})"
}
```

---

### `POST /api/server-encrypt`

Unseal data → re-seal dengan client public key.

**Request:**

```json
{
  "data": "sealed_string",
  "clientPublicKey": "base64_jwk_or_raw_client_public_key"
}
```

**Response:**

```json
{
  "data": "sealed_response"
}
```

---

## CORS

Server mengizinkan request dari `http://localhost:5173` (Vue dev server).

```typescript
app.use(
  cors({
    origin: "http://localhost:5173",
    exposedHeaders: ["*"],
  }),
);
```

---

## Public Key Format

### JWK Format (dari client)

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64url_x_coordinate",
  "y": "base64url_y_coordinate",
  "ext": true
}
```

### Raw Format (dari server)

Uncompressed EC point: `0x04 || x (32 bytes) || y (32 bytes)` = 65 bytes

Server mengirim public key dalam format raw base64, bukan JWK.

---

## Key Parsing

### `importPublicKey(rawBytes: ArrayBuffer): Promise<CryptoKey>`

Import raw uncompressed EC point ke CryptoKey menggunakan `suite.kem.importKey()`.

### JWK ke Raw Conversion

Saat client mengirim JWK (base64 encoded):

1. Decode base64 → JSON
2. Extract `x` dan `y` coordinates
3. Build uncompressed point: `0x04 || x || y`
4. Encode ke base64

### `publicKeyToJWK`

Export CryptoKey ke JWK menggunakan `crypto.subtle.exportKey("jwk", key)`.

---

## Troubleshooting

### `Invalid public key for the ciphersuite`

Penyebab: Public key format salah atau tidak valid untuk P-256.

Solusi: Pastikan public key dalam format raw uncompressed point (65 bytes) atau JWK valid.

### `Failed to unseal data: open: failed to decrypt`

Penyebab: Sealed data dienkripsi dengan public key yang berbeda.

Solusi: Pastikan sealed data dibuat dengan public key yang sesuai dengan private key server.

### `Server key pair not initialized`

Penyebab: File `src/server-keys-hpke.json` tidak ada atau corrupt.

Solusi: Hapus file key dan restart server (key baru akan dibuat otomatis).

### `Missing 'data' or 'recipientPublicKey'`

Penyebab: Request body tidak lengkap.

Solusi: Pastikan request body sesuai dengan format yang diharapkan (lihat endpoint documentation di atas).

# HPKE Client Integration

Panduan penggunaan enkripsi HPKE di sisi client (Vue.js + TypeScript).

## Instalasi

```bash
cd client
npm install @hpke/core
```

---

## File Structure

```
client/src/
├── utils/
│   └── hpke-crypto.ts      ← Utility functions untuk HPKE
└── views/
    └── HpkeView.vue        ← Contoh implementasi lengkap
```

---

## Quick Start

### 1. Inisialisasi HPKE Suite

```typescript
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),  // ECDH P-256
  kdf: new HkdfSha256(),            // HKDF-SHA-256
  aead: new Aes128Gcm(),            // AES-128-GCM
});
```

### 2. Generate Key Pair

```typescript
const keyPair = await suite.kem.generateKeyPair();
// keyPair = { publicKey: CryptoKey, privateKey: CryptoKey }
```

### 3. Export Public Key ke JWK

```typescript
const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
// { kty: "EC", crv: "P-256", x: "...", y: "...", ext: true, key_ops: [] }
```

### 4. Convert Public Key ke String (untuk dikirim)

```typescript
const publicKeyString = btoa(JSON.stringify(publicKeyJwk));
// "eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVlLCJrdHkiOiJFQyIs..."
```

### 5. Import Public Key dari String

```typescript
const jwk = JSON.parse(atob(publicKeyString));
const publicKey = await crypto.subtle.importKey(
  "jwk",
  jwk,
  { name: "ECDH", namedCurve: "P-256" },
  true,
  []
);
```

---

## Encrypt & Decrypt

### Encrypt (Mengirim Data)

```typescript
// 1. Import public key penerima
const recipientPublicKey = await crypto.subtle.importKey(
  "jwk",
  recipientJwk,
  { name: "ECDH", namedCurve: "P-256" },
  true,
  []
);

// 2. Buat sender context
const sender = await suite.createSenderContext({ recipientPublicKey });

// 3. Encrypt data
const ciphertext = await sender.seal(new TextEncoder().encode("rahasia"));

// 4. Format untuk dikirim
const encrypted = {
  ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
  enc: btoa(String.fromCharCode(...new Uint8Array(sender.enc))),
};

// 5. Combined string (untuk copy-paste mudah)
const encryptedString = btoa(JSON.stringify(encrypted));
```

### Decrypt (Menerima Data)

```typescript
// 1. Parse encrypted data
const parsed = JSON.parse(atob(encryptedString));
const ciphertext = Uint8Array.from(atob(parsed.ciphertext), c => c.charCodeAt(0));
const enc = Uint8Array.from(atob(parsed.enc), c => c.charCodeAt(0));

// 2. Buat recipient context
const recipient = await suite.createRecipientContext({
  recipientKey: privateKey,  // private key kamu
  enc: enc.buffer,
});

// 3. Decrypt
const plaintext = await recipient.open(ciphertext.buffer);
const message = new TextDecoder().decode(plaintext);
```

---

## 3 Skenario Penggunaan

### Skenario 1: Client Encrypt → Server Decrypt

Client mengenkripsi data yang hanya bisa dibaca server.

```typescript
// === CLIENT ===

// 1. Ambil server public key
const { publicKey } = await fetch("http://localhost:9002/api/public-key").then(r => r.json());

// 2. Encrypt data
const encrypted = await hpkeEncrypt("rahasia", publicKey);

// 3. Kirim ke server untuk decrypt
const decrypted = await fetch("http://localhost:9002/api/decrypt", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ encrypted: encrypted.encrypted }),
}).then(r => r.json());

console.log(decrypted.data); // "rahasia"
```

**Flow:**
```
Client: "rahasia" → encrypt(serverPublicKey) → { encrypted: "..." }
       → POST /api/decrypt
Server: decrypt → "rahasia"
```

---

### Skenario 2: Server Encrypt → Client Decrypt

Server mengirim data yang hanya bisa dibaca client.

```typescript
// === CLIENT ===

// 1. Generate key pair (jika belum ada)
const keyPair = await suite.kem.generateKeyPair();
const clientPublicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const clientPublicKeyString = btoa(JSON.stringify(clientPublicKeyJwk));

// 2. Minta server encrypt data pakai public key kita
const encrypted = await fetch("http://localhost:9002/api/server-encrypt", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    data: "balasan dari server",
    clientPublicKey: clientPublicKeyString,
  }),
}).then(r => r.json());

// 3. Decrypt dengan private key kita
const recipient = await suite.createRecipientContext({
  recipientKey: keyPair.privateKey,
  enc: Uint8Array.from(atob(encrypted.enc), c => c.charCodeAt(0)).buffer,
});
const plaintext = await recipient.open(
  Uint8Array.from(atob(encrypted.ciphertext), c => c.charCodeAt(0)).buffer
);

console.log(new TextDecoder().decode(plaintext)); // "balasan dari server"
```

**Flow:**
```
Client: kirim clientPublicKey → POST /api/server-encrypt
Server: encrypt(clientPublicKey) → { encrypted: "..." }
Client: decrypt(clientPrivateKey) → "balasan dari server"
```

---

### Skenario 3: Double Encryption (Data Terenkripsi 2 Kali)

Data dienkripsi client → server decrypt → server re-encrypt → client decrypt.

```typescript
// === CLIENT ===

// 1. Ambil server public key
const { publicKey: serverPublicKey } = await fetch("http://localhost:9002/api/public-key").then(r => r.json());

// 2. Generate client key pair
const clientKeyPair = await suite.kem.generateKeyPair();
const clientPublicKeyString = btoa(JSON.stringify(
  await crypto.subtle.exportKey("jwk", clientKeyPair.publicKey)
));

// 3. Encrypt data dengan server public key
const encryptedForServer = await hpkeEncrypt("data rahasia", serverPublicKey);

// 4. Kirim encrypted data + client public key ke server
//    Server akan: decrypt → re-encrypt dengan client public key
const result = await fetch("http://localhost:9002/api/server-encrypt", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    encryptedData: encryptedForServer.encrypted,
    clientPublicKey: clientPublicKeyString,
  }),
}).then(r => r.json());

// 5. Decrypt dengan private key client
const decrypted = await hpkeDecrypt(result, clientKeyPair.privateKey);
console.log(decrypted); // "data rahasia"
```

**Flow:**
```
Client: "data rahasia" → encrypt(serverPublicKey) → encryptedData
       → POST /api/server-encrypt { encryptedData, clientPublicKey }
Server: decrypt(serverPrivateKey) → "data rahasia"
       → encrypt(clientPublicKey) → result
Client: decrypt(clientPrivateKey) → "data rahasia"
```

**Kenapa double encryption?**
- Data **tidak pernah dikirim dalam bentuk plaintext**
- Server hanya bisa membaca sementara, tidak bisa menyimpan plaintext
- End-to-end encryption tetap terjaga

---

## Utility Functions (`hpke-crypto.ts`)

### `generateKeyPair()`
Generate ECDH P-256 key pair.

```typescript
const keyPair = await generateKeyPair();
// { publicKey: CryptoKey, privateKey: CryptoKey }
```

### `exportPublicKey(publicKey)`
Export CryptoKey ke JWK.

```typescript
const jwk = await exportPublicKey(keyPair.publicKey);
```

### `publicKeyToString(jwk)`
Convert JWK ke base64 string.

```typescript
const str = publicKeyToString(jwk);
// "eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVl..."
```

### `publicKeyFromString(str)`
Convert base64 string ke JWK.

```typescript
const jwk = publicKeyFromString(str);
```

### `hpkeEncrypt(data, recipientPublicKey)`
Encrypt data dengan public key penerima.

```typescript
const encrypted = await hpkeEncrypt("rahasia", recipientPublicKey);
// { ciphertext: "...", enc: "...", encrypted: "..." }
```

### `hpkeDecrypt(encrypted, privateKey)`
Decrypt data dengan private key.

```typescript
const plaintext = await hpkeDecrypt(encrypted, privateKey);
// "rahasia"
```

### `getServerPublicKey()`
Ambil public key server.

```typescript
const jwk = await getServerPublicKey();
```

### `getServerPublicKeyString()`
Ambil public key server dalam format string.

```typescript
const str = await getServerPublicKeyString();
```

### `serverDecrypt(encrypted)`
Kirim encrypted data ke server untuk didecrypt.

```typescript
const result = await serverDecrypt({ encrypted: "eyJ..." });
// { data: "rahasia" }
```

### `serverEncryptForClient(data, clientPublicKeyString, serverPublicKey)`
Server encrypt data dengan double encryption.

```typescript
const result = await serverEncryptForClient(
  "rahasia",
  clientPublicKeyString,
  serverPublicKey
);
// { encrypted: "eyJ..." }
```

---

## Interface

### `HpkeEncryptedData`

```typescript
interface HpkeEncryptedData {
  ciphertext: string;   // base64 ciphertext
  enc: string;          // base64 encapsulated key
  encrypted?: string;   // combined base64 string (optional)
}
```

---

## Contoh Lengkap di Vue Component

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  generateKeyPair,
  exportPublicKey,
  publicKeyToString,
  hpkeEncrypt,
  hpkeDecrypt,
  getServerPublicKeyString,
  serverEncryptForClient,
  serverDecrypt,
} from './utils/hpke-crypto'

const clientKeyPair = ref<any>(null)
const clientPublicKeyString = ref<string | null>(null)
const serverPublicKeyString = ref<string | null>(null)

// Init key pair saat component mount
onMounted(async () => {
  clientKeyPair.value = await generateKeyPair()
  clientPublicKeyString.value = publicKeyToString(
    await exportPublicKey(clientKeyPair.value.publicKey)
  )
})

// Flow 1: Client → Server
async function sendToServer(data: string) {
  const serverPubKey = JSON.parse(atob(serverPublicKeyString.value!))
  const encrypted = await hpkeEncrypt(data, serverPubKey)
  const decrypted = await serverDecrypt(encrypted)
  console.log('Server decrypted:', decrypted.data)
}

// Flow 2: Server → Client
async function receiveFromServer(data: string) {
  const encrypted = await serverEncryptForClient(
    data,
    clientPublicKeyString.value!,
    JSON.parse(atob(serverPublicKeyString.value!))
  )
  const decrypted = await hpkeDecrypt(encrypted, clientKeyPair.value.privateKey)
  console.log('Client decrypted:', decrypted)
}
</script>
```

---

## Keamanan

| Prinsip | Implementasi |
|---|---|
| **Private key tidak pernah dikirim** | Selalu disimpan di client (IndexedDB / memory) |
| **Public key bisa dibagikan** | Dikirim sebagai base64 string |
| **Data terenkripsi end-to-end** | Hanya penerima yang bisa decrypt |
| **Forward secrecy** | Setiap encrypt menghasilkan ciphertext berbeda (random AES key) |
| **Key persistence** | Server key disimpan di file, client key bisa disimpan di IndexedDB |

---

## Troubleshooting

### `atob` error: "The string to be decoded is not correctly encoded"

Penyebab: String yang diparsing bukan base64 valid. Pastikan:
- Server sudah running di port 9002
- Public key yang digunakan valid
- Encrypted data tidak terpotong

### `Decryption failed: The operation failed for an operation-specific reason`

Penyebab: `encryptedKey` dienkripsi dengan public key yang berbeda dari private key yang digunakan.

Solusi:
- Pastikan public key yang digunakan untuk encrypt sesuai dengan private key untuk decrypt
- Jangan restart server antara encrypt dan decrypt (kecuali key pair persist)

### `Missing 'clientPublicKey'`

Pastikan `clientPublicKey` dikirim dalam request body, bukan query parameter.

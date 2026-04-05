# HPKE Components Explained

## Overview

HPKE (Hybrid Public Key Encryption) adalah standar [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) yang menggabungkan **asymmetric encryption** (untuk key exchange) dan **symmetric encryption** (untuk data encryption).

## Komponen HPKE

### 1. `CipherSuite`

**Apa itu:** Container yang menggabungkan 3 algoritma kriptografi menjadi satu suite.

```typescript
const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),  // Key Encapsulation Mechanism
  kdf: new HkdfSha256(),            // Key Derivation Function
  aead: new Aes128Gcm(),            // Authenticated Encryption
});
```

**Fungsi:** Menentukan algoritma apa yang dipakai untuk setiap tahap enkripsi. Semua pihak yang berkomunikasi harus pakai suite yang sama.

---

### 2. `DhkemP256HkdfSha256` (KEM - Key Encapsulation Mechanism)

**Apa itu:** Algoritma untuk **key exchange** menggunakan Elliptic Curve Diffie-Hellman (ECDH) dengan kurva **P-256**.

**Cara kerja:**
```
Sender (encrypt)                          Recipient (decrypt)
─────────────────                         ───────────────────
1. Generate random shared secret
2. Encrypt data dengan shared secret
3. "Encapsulate" shared secret
   → menghasilkan `enc` (encapsulated key)
                                        4. Terima `enc`
                                        5. "Decapsulate" dengan private key
                                        6. Dapat shared secret yang sama
```

**Kenapa P-256?**
- Kurva elliptic yang distandarisasi NIST
- 256-bit security level (~128-bit symmetric equivalent)
- Kompromi antara keamanan dan performa
- Didukung semua browser modern

**Contoh:**
```typescript
// Generate key pair
const keyPair = await suite.kem.generateKeyPair();
// { publicKey: CryptoKey, privateKey: CryptoKey }

// Import public key dari JWK
const publicKey = await crypto.subtle.importKey(
  "jwk",
  jwk,
  { name: "ECDH", namedCurve: "P-256" },
  true,
  []
);
```

---

### 3. `HkdfSha256` (KDF - Key Derivation Function)

**Apa itu:** Fungsi untuk **menurunkan kunci** dari shared secret menjadi key yang bisa dipakai untuk enkripsi.

**Kenapa perlu KDF?**
Shared secret dari ECDH tidak langsung bisa dipakai untuk AES. KDF mengubah shared secret menjadi key dengan format yang benar.

**Cara kerja:**
```
Shared Secret (dari ECDH)
         ↓
    [HKDF-SHA256]
         ↓
    AES Key (128/256 bit)
```

**Parameter:**
- **Input:** Shared secret + optional info/context
- **Output:** Key dengan panjang yang diinginkan
- **Hash:** SHA-256 (256-bit output)

**Contoh:**
```typescript
// Internal HPKE:
// 1. ECDH menghasilkan shared secret
// 2. HKDF-SHA256 menurunkan AES key dari shared secret
// 3. AES key dipakai untuk enkripsi data
```

---

### 4. `Aes128Gcm` (AEAD - Authenticated Encryption with Associated Data)

**Apa itu:** Algoritma enkripsi **symmetric** yang menyediakan **kerahasiaan** + **autentikasi** sekaligus.

**Cara kerja:**
```
Plaintext + AES Key + IV
         ↓
    [AES-128-GCM]
         ↓
Ciphertext + Authentication Tag
```

**Kenapa AES-128-GCM?**
- **Cepat** — hardware-accelerated di kebanyakan CPU
- **Aman** — menyediakan confidentiality + integrity
- **Standar** — dipakai di TLS 1.3, Signal, dll
- **128-bit** — cukup aman untuk kebanyakan use case

**Parameter:**
- **Key length:** 128 bit (16 bytes)
- **IV length:** 12 bytes (96 bits) — standar untuk GCM
- **Tag length:** 128 bits (authentication tag)

**Contoh:**
```typescript
// Encrypt
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  aesKey,
  plaintext
);

// Decrypt
const plaintext = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv },
  aesKey,
  ciphertext
);
```

---

## Flow Lengkap HPKE

```
┌─────────────────────────────────────────────────────────────┐
│                        SENDER                               │
│                                                             │
│  1. Generate ephemeral key pair (ECDH P-256)               │
│     ↓                                                       │
│  2. ECDH: shared_secret = ECDH(sender_private, recipient_public)
│     ↓                                                       │
│  3. HKDF-SHA256: aes_key = HKDF(shared_secret, context)    │
│     ↓                                                       │
│  4. AES-128-GCM: ciphertext = AES-Encrypt(aes_key, data)   │
│     ↓                                                       │
│  5. Output: { ciphertext, enc (encapsulated key) }         │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                      RECIPIENT                              │
│                                                             │
│  1. Terima { ciphertext, enc }                             │
│     ↓                                                       │
│  2. ECDH: shared_secret = ECDH(recipient_private, enc)     │
│     ↓                                                       │
│  3. HKDF-SHA256: aes_key = HKDF(shared_secret, context)    │
│     ↓                                                       │
│  4. AES-128-GCM: plaintext = AES-Decrypt(aes_key, ciphertext)
│     ↓                                                       │
│  5. Output: plaintext                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Perbandingan dengan Alternatif

| Approach | Key Exchange | Data Encryption | Authenticated? |
|---|---|---|---|
| **HPKE (ECDH + AES-GCM)** | ✅ ECDH P-256 | ✅ AES-128-GCM | ✅ Ya (GCM tag) |
| **RSA-OAEP + AES-GCM** | ✅ RSA | ✅ AES-GCM | ✅ Ya |
| **AES saja** | ❌ Butuh shared secret | ✅ AES-GCM | ✅ Ya |
| **RSA saja** | ✅ RSA | ❌ RSA lambat untuk data besar | ✅ Ya |

---

## Kenapa HPKE?

1. **Standar IETF** — RFC 9180, dipakai di TLS 1.3, MLS, dll
2. **Forward secrecy** — setiap encrypt pakai ephemeral key baru
3. **Efisien** — hanya 1 round-trip untuk key exchange
4. **Aman** — kombinasi algoritma yang sudah teruji
5. **Fleksibel** — bisa ganti algoritma di CipherSuite

---

## Security Considerations

| Aspek | Detail |
|---|---|
| **Key size** | P-256 = ~128-bit security |
| **AES key** | 128-bit (cukup untuk kebanyakan use case) |
| **IV** | 12 bytes random — jangan reuse! |
| **Forward secrecy** | ✅ Setiap encrypt pakai key baru |
| **Authentication** | ✅ AES-GCM menyediakan integrity check |
| **Key storage** | Private key jangan pernah dikirim |

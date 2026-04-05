<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  generateKeyPair,
  exportPublicKey,
  publicKeyToString,
  publicKeyFromString,
  hpkeEncrypt,
  hpkeDecrypt,
  getServerPublicKey,
  getServerPublicKeyString,
  serverEncrypt,
  serverDecrypt,
  serverEncryptForClient,
  type HpkeEncryptedData,
} from '../utils/hpke-crypto'

const loading = ref(false)
const clientData = ref('')
const serverData = ref('')
const serverPublicKey = ref<JsonWebKey | null>(null)
const serverPublicKeyString = ref<string | null>(null)
const clientKeyPair = ref<{ publicKey: CryptoKey; privateKey: CryptoKey } | null>(null)

const clientEncrypted = ref<HpkeEncryptedData | null>(null)
const serverDecrypted = ref<string | null>(null)
const serverEncrypted = ref<HpkeEncryptedData | null>(null)
const clientDecrypted = ref<string | null>(null)
const manualEncrypted = ref('')
const manualDecrypted = ref<string | null>(null)
const clientPublicKeyJwk = ref<JsonWebKey | null>(null)
const clientPublicKeyString = ref<string | null>(null)

// Generate client key pair on mount
onMounted(async () => {
  clientKeyPair.value = await generateKeyPair()
  clientPublicKeyJwk.value = await exportPublicKey(clientKeyPair.value.publicKey)
  clientPublicKeyString.value = publicKeyToString(clientPublicKeyJwk.value)
})

async function fetchServerKey() {
  serverPublicKeyString.value = await getServerPublicKeyString()
  serverPublicKey.value = publicKeyFromString(serverPublicKeyString.value)
}

async function clientEncrypt() {
  if (!clientData.value) {
    alert('Fill data first!')
    return
  }

  loading.value = true
  try {
    // Auto-fetch server public key if not loaded
    if (!serverPublicKeyString.value) {
      serverPublicKeyString.value = await getServerPublicKeyString()
    }
    serverPublicKey.value = publicKeyFromString(serverPublicKeyString.value)

    // 1. Client encrypt with server public key
    clientEncrypted.value = await hpkeEncrypt(clientData.value, serverPublicKey.value)

    // 2. Server decrypt
    serverDecrypted.value = await serverDecrypt(clientEncrypted.value)
  } catch (error) {
    console.error('Client encrypt error:', error)
    alert('Encryption failed!')
  } finally {
    loading.value = false
  }
}

async function serverEncrypts() {
  if (!serverData.value || !clientKeyPair.value) {
    alert('Fill data first!')
    return
  }

  if (!clientPublicKeyString.value) {
    clientPublicKeyString.value = publicKeyToString(
      await exportPublicKey(clientKeyPair.value.publicKey),
    )
  }

  // Auto-fetch server public key if not loaded
  if (!serverPublicKeyString.value) {
    serverPublicKeyString.value = await getServerPublicKeyString()
  }
  serverPublicKey.value = publicKeyFromString(serverPublicKeyString.value)

  loading.value = true
  try {
    // 1. Client encrypt data with server public key → server decrypt → server encrypt with client public key
    serverEncrypted.value = await serverEncryptForClient(
      serverData.value,
      clientPublicKeyString.value,
      serverPublicKey.value,
    )

    // 2. Client decrypt with own private key
    clientDecrypted.value = await hpkeDecrypt(serverEncrypted.value, clientKeyPair.value.privateKey)
  } catch (error) {
    console.error('Server encrypt error:', error)
    alert('Encryption failed: ' + (error instanceof Error ? error.message : String(error)))
  } finally {
    loading.value = false
  }
}

async function manualDecrypt() {
  if (!manualEncrypted.value || !clientKeyPair.value) {
    alert('Paste encrypted JSON and wait for key pair to load!')
    return
  }

  loading.value = true
  try {
    let encrypted: HpkeEncryptedData

    // Try parsing as combined string first
    try {
      const parsed = JSON.parse(atob(manualEncrypted.value))
      if (parsed.ciphertext && parsed.enc) {
        encrypted = parsed
      } else {
        throw new Error('Invalid format')
      }
    } catch {
      // Try as JSON object
      encrypted = JSON.parse(manualEncrypted.value)
    }

    manualDecrypted.value = await hpkeDecrypt(encrypted, clientKeyPair.value.privateKey)
  } catch (error) {
    console.error('Manual decrypt error:', error)
    alert('Decryption failed! Pastikan encrypted JSON valid dan dienkripsi dengan public key Anda.')
  } finally {
    loading.value = false
  }
}

async function copyText(text: string) {
  await navigator.clipboard.writeText(text)
  alert('Copied to clipboard!')
}
</script>

<template>
  <div class="hpke-test">
    <h1>HPKE Encryption Test</h1>

    <!-- Flow 1: Client Encrypt → Server Decrypt -->
    <section class="card">
      <h2>Flow 1: Client Encrypt → Server Decrypt</h2>
      <p class="hint">Client encrypt pakai server public key → server decrypt</p>

      <div class="form-group">
        <label>Data to encrypt:</label>
        <input v-model="clientData" placeholder="Rahasia dari client" />
      </div>

      <button @click="clientEncrypt" :disabled="loading">
        {{ loading ? 'Processing...' : 'Encrypt & Send to Server' }}
      </button>

      <div v-if="clientEncrypted" class="result">
        <h3>Encrypted (client → server):</h3>
        <div class="key-string">
          <code>{{ clientEncrypted.encrypted }}</code>
          <button @click="copyText(clientEncrypted.encrypted!)" class="btn-small">Copy</button>
        </div>
      </div>

      <div v-if="serverDecrypted" class="result success">
        <h3>✅ Decrypted by server:</h3>
        <pre>{{ serverDecrypted }}</pre>
      </div>
    </section>

    <!-- Flow 2: Server Encrypt → Client Decrypt -->
    <section class="card">
      <h2>Flow 2: Server → Client</h2>

      <div class="form-group">
        <label>Data from server:</label>
        <input v-model="serverData" placeholder="Balasan dari server" />
      </div>

      <button @click="serverEncrypts" :disabled="loading">
        {{ loading ? 'Processing...' : 'Server Encrypt → Client Decrypt' }}
      </button>

      <div v-if="serverEncrypted" class="result">
        <h3>Encrypted (server → client):</h3>
        <div class="key-string">
          <code>{{ serverEncrypted.encrypted }}</code>
          <button @click="copyText(serverEncrypted.encrypted!)" class="btn-small">Copy</button>
        </div>
      </div>

      <div v-if="clientDecrypted" class="result success">
        <h3>Decrypted by client:</h3>
        <pre>{{ clientDecrypted }}</pre>
      </div>
    </section>

    <!-- Server Public Key -->
    <section class="card">
      <h2>Server Public Key</h2>
      <button @click="fetchServerKey">Fetch Public Key</button>
      <div v-if="serverPublicKeyString" class="key-string">
        <code>{{ serverPublicKeyString }}</code>
        <button @click="copyText(serverPublicKeyString)" class="btn-small">Copy</button>
      </div>
    </section>

    <!-- Client Public Key (for server to encrypt) -->
    <section class="card">
      <h2>Your Public Key</h2>
      <p class="hint">Kasih public key ini ke server supaya server bisa encrypt untuk kamu</p>
      <div v-if="clientPublicKeyString" class="key-string">
        <code>{{ clientPublicKeyString }}</code>
        <button @click="copyText(clientPublicKeyString)" class="btn-small">Copy</button>
      </div>
    </section>

    <!-- Manual Decrypt: paste encrypted data from server -->
    <section class="card">
      <h2>Manual Decrypt (Server → Client)</h2>
      <p class="hint">Paste JSON hasil encrypt dari server/hpke-server</p>

      <div class="form-group">
        <label>Encrypted JSON from server:</label>
        <textarea
          v-model="manualEncrypted"
          placeholder='{"ciphertext":"...","enc":"..."}'
          rows="4"
        />
      </div>

      <button @click="manualDecrypt" :disabled="loading">
        {{ loading ? 'Processing...' : 'Decrypt' }}
      </button>

      <div v-if="manualDecrypted" class="result success">
        <h3>Decrypted:</h3>
        <pre>{{ manualDecrypted }}</pre>
      </div>
    </section>
  </div>
</template>

<style scoped>
.hpke-test {
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  color: #fff;
}

.card {
  background: #1a1a2e;
  border: 1px solid #333;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 15px;
}

label {
  display: block;
  margin-bottom: 5px;
  font-weight: bold;
}

input {
  width: 100%;
  padding: 8px;
  border: 1px solid #444;
  border-radius: 4px;
  background: #0f0f23;
  color: #fff;
}

button {
  padding: 10px 20px;
  background: #42b983;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

button:hover {
  background: #369f6b;
}

.hint {
  color: #888;
  font-size: 0.85em;
  margin-bottom: 10px;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.key-string {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
  padding: 8px 12px;
  background: #0a0a1a;
  border-radius: 4px;
}

.key-string code {
  flex: 1;
  color: #0f0;
  font-family: monospace;
  font-size: 0.8em;
  word-break: break-all;
}

.btn-small {
  padding: 4px 10px;
  font-size: 0.8em;
  white-space: nowrap;
}

.result {
  margin-top: 15px;
  padding: 10px;
  background: #0f0f23;
  border-radius: 4px;
}

.result.success {
  border-left: 3px solid #42b983;
}

pre {
  background: #0a0a1a;
  color: #0f0;
  padding: 10px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85em;
}
</style>

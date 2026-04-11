<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  generateKeyPair,
  exportPublicKey,
  publicKeyToString,
  seal,
  unseal,
  suite,
  getServerPublicKeyRaw,
} from '../utils/hpke-crypto'

const loading = ref(false)
const clientData = ref('')
const serverData = ref('')
const serverPublicKeyRaw = ref<string | null>(null)
const clientKeyPair = ref<{ publicKey: CryptoKey; privateKey: CryptoKey } | null>(null)
const clientPublicKeyString = ref<string | null>(null)

const clientSealed = ref<string | null>(null)
const serverDecrypted = ref<string | null>(null)
const serverSealed = ref<string | null>(null)
const clientDecrypted = ref<string | null>(null)
const apiInput = ref('')
const apiSealed = ref<string | null>(null)
const apiResponse = ref<string | null>(null)

// Generate client key pair on mount
onMounted(async () => {
  clientKeyPair.value = await generateKeyPair()
  const pubKey = await exportPublicKey(clientKeyPair.value.publicKey)
  clientPublicKeyString.value = publicKeyToString(pubKey)

  // Fetch server public key on mount
  serverPublicKeyRaw.value = await getServerPublicKeyRaw()
})

async function clientEncrypt() {
  if (!clientData.value) {
    alert('Fill data first!')
    return
  }

  loading.value = true
  try {
    if (!serverPublicKeyRaw.value) {
      throw new Error('Server public key not loaded')
    }
    const pubKey = serverPublicKeyRaw.value

    // Combine data + publicKey into one payload, then seal
    const combinedPayload = JSON.stringify({
      data: clientData.value,
      publicKey: clientPublicKeyString.value,
    })
    clientSealed.value = await seal(suite, pubKey, combinedPayload)

    // Send sealed payload only (data + publicKey inside)
    const res = await fetch('http://localhost:9002/api/seal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: clientSealed.value,
      }),
    })
    const result = await res.json()

    // Server returns sealed response, client unseals it
    if (result.data) {
      serverDecrypted.value = await unseal(suite, clientKeyPair.value!.privateKey, result.data)
    }
  } catch (error) {
    console.error('Client encrypt error:', error)
    alert('Encryption failed: ' + (error instanceof Error ? error.message : String(error)))
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

  loading.value = true
  try {
    if (!serverPublicKeyRaw.value) {
      throw new Error('Server public key not loaded')
    }

    // Combine data + clientPublicKey, then seal with server's public key
    const combinedPayload = JSON.stringify({
      data: serverData.value,
      publicKey: clientPublicKeyString.value,
    })
    const data = await seal(suite, serverPublicKeyRaw.value, combinedPayload)

    // Send sealed payload to server
    const res = await fetch('http://localhost:9002/api/seal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data,
      }),
    })
    const result = await res.json()

    // Server returns sealed response, client unseals it
    if (result.data) {
      const sealed = result.data as string
      serverSealed.value = sealed
      clientDecrypted.value = await unseal(suite, clientKeyPair.value!.privateKey, sealed)
    }
  } catch (error) {
    console.error('Server encrypt error:', error)
    alert('Encryption failed: ' + (error instanceof Error ? error.message : String(error)))
  } finally {
    loading.value = false
  }
}

async function copyText(text: string) {
  await navigator.clipboard.writeText(text)
  alert('Copied to clipboard!')
}

async function sendSealedToExternalApi() {
  if (!apiInput.value) {
    alert('Fill data first!')
    return
  }

  loading.value = true
  try {
    if (!serverPublicKeyRaw.value) {
      throw new Error('Server public key not loaded')
    }

    // Combine data + publicKey into one payload, then seal
    const combinedPayload = JSON.stringify({
      data: apiInput.value,
      publicKey: clientPublicKeyString.value,
    })
    apiSealed.value = await seal(suite, serverPublicKeyRaw.value, combinedPayload)

    // Send sealed payload only (data + publicKey inside)
    const res = await fetch('http://localhost:9002/api/external-api', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: apiSealed.value,
      }),
    })
    const result = await res.json()

    // BE returns sealed response from jsonplaceholder
    if (result.data) {
      apiResponse.value = await unseal(suite, clientKeyPair.value!.privateKey, result.data)
    }
  } catch (error) {
    console.error('External API error:', error)
    alert('Failed: ' + (error instanceof Error ? error.message : String(error)))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="hpke-test">
    <h1>HPKE Encryption Test</h1>

    <!-- Flow 1: Client Encrypt → Server Decrypt -->
    <section class="card">
      <h2>Flow 1: Client Encrypt → Server Decrypt</h2>
      <p class="hint">Client seal pakai server public key → server unseal</p>

      <div class="form-group">
        <label>Data to seal:</label>
        <input v-model="clientData" placeholder="Rahasia dari client" />
      </div>

      <button @click="clientEncrypt" :disabled="loading">
        {{ loading ? 'Processing...' : 'Seal & Send to Server' }}
      </button>

      <div v-if="clientSealed" class="result">
        <h3>Sealed (data + publicKey → server):</h3>
        <div class="key-string">
          <code>{{ clientSealed }}</code>
          <button @click="copyText(clientSealed!)" class="btn-small">Copy</button>
        </div>
      </div>

      <div v-if="serverDecrypted" class="result success">
        <h3>✅ Unsealed by server:</h3>
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
        {{ loading ? 'Processing...' : 'Server Seal → Client Unseal' }}
      </button>

      <div v-if="serverSealed" class="result">
        <h3>Sealed (server → client):</h3>
        <div class="key-string">
          <code>{{ serverSealed }}</code>
          <button @click="copyText(serverSealed!)" class="btn-small">Copy</button>
        </div>
      </div>

      <div v-if="clientDecrypted" class="result success">
        <h3>Unsealed by client:</h3>
        <pre>{{ clientDecrypted }}</pre>
      </div>
    </section>

    <!-- External API: Seal → BE → jsonplaceholder → Seal → Client Unseal -->
    <section class="card">
      <h2>External API via BE</h2>
      <p class="hint">
        Client seal → BE unseal → BE kirim ke jsonplaceholder → BE seal response → Client unseal
      </p>

      <div class="form-group">
        <label>Data to seal:</label>
        <input v-model="apiInput" placeholder="Data rahasia" />
      </div>

      <button @click="sendSealedToExternalApi" :disabled="loading">
        {{ loading ? 'Processing...' : 'Seal & Send via BE' }}
      </button>

      <div v-if="apiSealed" class="result">
        <h3>Sealed payload (client → BE):</h3>
        <div class="key-string">
          <code>{{ apiSealed }}</code>
          <button @click="copyText(apiSealed!)" class="btn-small">Copy</button>
        </div>
      </div>

      <div v-if="apiResponse" class="result success">
        <h3>✅ Unsealed response (BE → jsonplaceholder → BE → client):</h3>
        <pre>{{ apiResponse }}</pre>
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

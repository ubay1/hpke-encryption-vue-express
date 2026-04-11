import { CipherSuite } from '@hpke/core'
import {
  concatUint8Arrays,
  uint8ArrayToBase64,
  base64ToUint8Array,
  stringToUint8Array,
  uint8ArrayToString,
} from 'uint8array-extras'

// Min 3, Max 9
const WRAPPER_LENGTH = 5

// Taken and modified from
// https://github.com/validatorjs/validator.js/blob/master/src/lib/isBase64.js
export const isBase64String = (str: string) => {
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

// Use native crypto (available in Node.js 19+)
const getRandomValues = (array: Uint32Array): Uint32Array => {
  const { webcrypto } = require('crypto')
  return webcrypto.getRandomValues(array)
}

// Advices from https://github.com/gkouziik/eslint-plugin-security-node/blob/master/docs/rules/detect-insecure-randomness.md
// Divide a random UInt32 by the maximum value (2^32 -1) to get a result between 0 and 1
const secureMathRandom = () => getRandomValues(new Uint32Array(1))[0] / 4294967295

// Taken from https://www.programiz.com/javascript/examples/generate-random-strings
const generateWrapperString = () =>
  secureMathRandom()
    .toString(36)
    .substring(2, 2 + WRAPPER_LENGTH)

export const wrapBase64 = (base64: string) => {
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

export const unwrapBase64 = (str: string) => {
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

export const seal = async (suite: CipherSuite, publicKeyB64: string, plainText: string) => {
  const publicKey = base64ToUint8Array(publicKeyB64).buffer
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

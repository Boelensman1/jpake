import { sha3_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { mod } from '@noble/curves/abstract/modular.js'
import { n } from './constants.mjs'
import { InvalidArgumentError } from './JPakeErrors.mjs'
import { encodeUnicodeString } from './encodeProtocolString.mjs'

/**
 * Derives s from a password using sha3_256. You might want to repeatedly hash the password or apply a key derivation function (e.g., PBKDF2, Argon2, or scrypt) to strengthen it and ensure more uniform distribution over the scalar field. This is particularly important if the password space is weak.
 * @param password - The password to derive s from.
 * @returns The derived s value.
 * @throws {InvalidArgumentError} If password is empty, is not a string, or contains unpaired surrogates.
 */
const deriveSFromPassword = (password: string): Uint8Array => {
  const passwordBytes = encodeUnicodeString(password, 'password')
  if (passwordBytes.length === 0) {
    throw new InvalidArgumentError('Missing password')
  }

  let passwordHash = sha3_256(passwordBytes)
  passwordBytes.fill(0)
  let s = mod(bytesToNumberBE(passwordHash), n)
  passwordHash.fill(0)

  // Retry if s is 0 (very unlikely)
  while (s === 0n) {
    const retryBytes = encodeUnicodeString(password + 'retried', 'password')
    passwordHash = sha3_256(retryBytes)
    retryBytes.fill(0)
    s = mod(bytesToNumberBE(passwordHash), n)
    passwordHash.fill(0)
  }

  return numberToBytesBE(s, 32)
}

export default deriveSFromPassword

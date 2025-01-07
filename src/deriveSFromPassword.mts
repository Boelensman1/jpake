import { sha3_256 } from '@noble/hashes/sha3'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/abstract/utils'
import { mod } from '@noble/curves/abstract/modular'
import { n } from './constants.mjs'
import { InvalidArgumentError } from './JPakeErrors.mjs'

/**
 * Derives s from a password using sha3_256. You might want to repeatedly hash the password or apply a key derivation function (e.g., PBKDF2, Argon2, or scrypt) to strengthen it and ensure more uniform distribution over the scalar field. This is particularly important if the password space is weak.
 * @param password - The password to derive s from.
 * @returns The derived s value.
 */
const deriveSFromPassword = (password: string): Uint8Array => {
  if (!password) {
    throw new InvalidArgumentError('Missing password')
  }

  let passwordHash = sha3_256(new TextEncoder().encode(password))
  let s = mod(bytesToNumberBE(passwordHash), n)

  // Retry if s is 0 (very unlikely)
  while (s === 0n) {
    passwordHash = sha3_256(new TextEncoder().encode(password + 'retried'))
    s = mod(bytesToNumberBE(passwordHash), n)
  }

  return numberToBytesBE(s, 32)
}

export default deriveSFromPassword

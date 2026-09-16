import { sha3_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { mod } from '@noble/curves/abstract/modular.js'
import { n } from './constants.mjs'
import { InvalidArgumentError } from './JPakeErrors.mjs'
import { encodeUnicodeString } from './encodeProtocolString.mjs'

/**
 * Hashes one password candidate to a scalar, wiping both intermediate buffers.
 * @param value - The candidate to hash.
 * @returns The hash reduced modulo the curve order.
 * @throws {InvalidArgumentError} If value is empty, is not a string, or contains unpaired surrogates.
 */
const scalarFromPassword = (value: string): bigint => {
  const valueBytes = encodeUnicodeString(value, 'password')
  if (valueBytes.length === 0) {
    throw new InvalidArgumentError('Missing password')
  }

  const valueHash = sha3_256(valueBytes)
  valueBytes.fill(0)
  const scalar = mod(bytesToNumberBE(valueHash), n)
  valueHash.fill(0)

  return scalar
}

/**
 * Derives s from a password using sha3_256. You might want to repeatedly hash the password or apply a key derivation function (e.g., PBKDF2, Argon2, or scrypt) to strengthen it and ensure more uniform distribution over the scalar field. This is particularly important if the password space is weak.
 * @param password - The password to derive s from.
 * @returns The derived s value.
 * @throws {InvalidArgumentError} If password is empty, is not a string, or contains unpaired surrogates.
 */
const deriveSFromPassword = (password: string): Uint8Array => {
  let s = scalarFromPassword(password)

  // Retry if s is 0 (very unlikely). Each attempt hashes a distinct candidate,
  // so a zero cannot be recomputed forever.
  for (let attempt = 1; s === 0n; attempt++) {
    s = scalarFromPassword(`${password}retried${attempt}`)
  }

  return numberToBytesBE(s, 32)
}

export default deriveSFromPassword

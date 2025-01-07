import { describe, it, expect } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'
import {
  generateSchnorrChallenge,
  generateSchnorrProof,
  verifySchnorrProof,
} from '../src/schnorr.mjs'
import { G } from '../src/constants.mjs'

describe('Schnorr Signature Scheme', () => {
  const userId = 'testUser'
  const privateKey = secp256k1.utils.randomPrivateKey()
  const publicKey = G.multiply(bytesToNumberBE(privateKey))

  it('should generate a valid Schnorr challenge', () => {
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomPrivateKey()))
    const challenge = generateSchnorrChallenge(userId, publicKey, gr)

    expect(challenge).toBeDefined()
    expect(typeof challenge).toBe('bigint')
  })

  it('should generate and verify a valid Schnorr proof', () => {
    const proof = generateSchnorrProof(userId, privateKey, publicKey, G)

    expect(proof).toBeDefined()
    expect(proof instanceof Uint8Array).toBe(true)

    const isValid = verifySchnorrProof(userId, publicKey, proof, G)
    expect(isValid).toBe(true)
  })

  it('should fail verification with an invalid proof', () => {
    const proof = generateSchnorrProof(userId, privateKey, publicKey, G)
    const tamperedProof = new Uint8Array(proof)
    tamperedProof[10] ^= 1 // Flip a bit to tamper with the proof

    const isValid = verifySchnorrProof(userId, publicKey, tamperedProof, G)
    expect(isValid).toBe(false)
  })

  it('should fail verification with mismatched userId', () => {
    const proof = generateSchnorrProof(userId, privateKey, publicKey, G)
    const isValid = verifySchnorrProof('wrongUser', publicKey, proof, G)
    expect(isValid).toBe(false)
  })

  it('should handle otherInfo correctly', () => {
    const otherInfo = ['additional', 'information']
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomPrivateKey()))
    const challenge = generateSchnorrChallenge(userId, publicKey, gr, otherInfo)

    expect(challenge).toBeDefined()
    expect(typeof challenge).toBe('bigint')

    const proof = generateSchnorrProof(
      userId,
      privateKey,
      publicKey,
      G,
      otherInfo,
    )
    const isValid = verifySchnorrProof(userId, publicKey, proof, G, otherInfo)
    expect(isValid).toBe(true)
  })

  it('should throw an error for long userId', () => {
    const longUserId = 'a'.repeat(256)
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomPrivateKey()))

    expect(() =>
      generateSchnorrChallenge(longUserId, publicKey, gr),
    ).toThrowError(
      'userId is too long. It must be 255 bytes or less when UTF-8 encoded.',
    )
  })

  it('should throw an error for long otherInfo', () => {
    const longOtherInfo = ['a'.repeat(256)]
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomPrivateKey()))

    expect(() =>
      generateSchnorrChallenge(userId, publicKey, gr, longOtherInfo),
    ).toThrowError(
      'Each otherInfo string must be 255 bytes or less when UTF-8 encoded.',
    )
  })

  it('should fail verification with malformed proofs', () => {
    const validProof = generateSchnorrProof(userId, privateKey, publicKey, G)

    // Test incorrect VLength
    const incorrectVLength = new Uint8Array(validProof)
    incorrectVLength[0] = 32 // Change VLength to an incorrect value
    expect(() =>
      verifySchnorrProof(userId, publicKey, incorrectVLength, G),
    ).toThrowError('Invalid proof, V must be 33 bytes and r must be 32 bytes')

    // Test incorrect rLength
    const incorrectRLength = new Uint8Array(validProof)
    incorrectRLength[34] = 31 // Change rLength to an incorrect value
    expect(() =>
      verifySchnorrProof(userId, publicKey, incorrectRLength, G),
    ).toThrowError('Invalid proof, V must be 33 bytes and r must be 32 bytes')

    // Test incorrect total number of bytes
    const incorrectTotalBytes = new Uint8Array(validProof.slice(0, -1)) // Remove last byte
    expect(() =>
      verifySchnorrProof(userId, publicKey, incorrectTotalBytes, G),
    ).toThrowError('Invalid proof, must be 33 + 32 + 2 bytes long')

    // Test only VLength
    const onlyVLength = new Uint8Array([33])
    expect(() =>
      verifySchnorrProof(userId, publicKey, onlyVLength, G),
    ).toThrowError('Invalid proof, must be 33 + 32 + 2 bytes long')
  })
})

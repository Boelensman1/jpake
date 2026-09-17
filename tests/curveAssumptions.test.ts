import { describe, it, expect } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { G, n } from '../src/constants.mjs'

// Properties this implementation leans on @noble/curves to provide. They are
// not guarantees of this codebase, so a dependency bump or a different curve
// backend could withdraw one silently. These tests exist to make that loud.
describe('@noble/curves assumptions', () => {
  // JPake checks for the point at infinity in round 2 and in key derivation.
  // Those checks are unreachable today because no encoding of the identity
  // survives fromBytes, which is why decoding has to keep rejecting it: without
  // that, a peer could send the identity as G3, G4, B, or a proof's V.
  it.each([
    ['33 zero bytes', new Uint8Array(33)],
    [
      'compressed even prefix over a zero x',
      new Uint8Array([2, ...new Uint8Array(32)]),
    ],
    [
      'compressed odd prefix over a zero x',
      new Uint8Array([3, ...new Uint8Array(32)]),
    ],
    ['the single-byte SEC1 identity', new Uint8Array([0])],
    ['65 zero bytes', new Uint8Array(65)],
    [
      'uncompressed prefix over zero coordinates',
      new Uint8Array([4, ...new Uint8Array(64)]),
    ],
  ])('should refuse to decode %s as a point', (_, bytes) => {
    expect(() => secp256k1.Point.fromBytes(bytes)).toThrowError()
  })

  it('should refuse to encode the point at infinity', () => {
    expect(() => secp256k1.Point.ZERO.toBytes(true)).toThrowError()
    expect(() => secp256k1.Point.ZERO.toBytes(false)).toThrowError()
  })

  // JPake multiplies by secret scalars and schnorr.mts multiplies by public
  // ones. Only the public path may accept zero: a zero secret scalar would
  // collapse a point to the identity, while a zero challenge or response is a
  // legitimate, if astronomically unlikely, proof component.
  it('should reject a zero or out-of-range secret scalar', () => {
    for (const scalar of [0n, n, n + 1n]) {
      expect(() => G.multiply(scalar)).toThrowError()
    }
  })

  it('should accept a zero but not an out-of-range public scalar', () => {
    expect(G.multiplyUnsafe(0n).equals(secp256k1.Point.ZERO)).toBe(true)
    for (const scalar of [n, n + 1n]) {
      expect(() => G.multiplyUnsafe(scalar)).toThrowError()
    }
  })

  // JPake.round1 relies on this range to use one generator for both ephemeral
  // keys: RFC 8236 allows x1 in [0, q-1] but requires x2 in [1, q-1].
  it('should draw secret keys as 32 bytes inside [1, n-1]', () => {
    for (let i = 0; i < 64; i++) {
      const secret = secp256k1.utils.randomSecretKey()
      expect(secret).toHaveLength(32)
      const scalar = bytesToNumberBE(secret)
      expect(scalar).toBeGreaterThanOrEqual(1n)
      expect(scalar).toBeLessThan(n)
    }
    expect(numberToBytesBE(n - 1n, 32)).toHaveLength(32)
  })
})

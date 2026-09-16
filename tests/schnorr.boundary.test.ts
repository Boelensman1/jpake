import { afterEach, describe, expect, it, vi } from 'vitest'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { numberToBytesBE } from '@noble/curves/utils.js'
import { G } from '../src/constants.mjs'
import { generateSchnorrProof, verifySchnorrProof } from '../src/schnorr.mjs'
import { InvalidArgumentError } from '../src/JPakeErrors.mjs'

vi.mock('@noble/hashes/sha3.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/hashes/sha3.js')>()
  return { ...actual, sha3_256: vi.fn(actual.sha3_256) }
})

vi.mock('@noble/curves/secp256k1.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('@noble/curves/secp256k1.js')>()
  return {
    ...actual,
    secp256k1: {
      ...actual.secp256k1,
      utils: {
        ...actual.secp256k1.utils,
        randomSecretKey: vi.fn(actual.secp256k1.utils.randomSecretKey),
      },
    },
  }
})

afterEach(() => {
  vi.mocked(sha3_256).mockReset()
  vi.mocked(secp256k1.utils.randomSecretKey).mockReset()
  vi.restoreAllMocks()
})

describe('Schnorr scalar boundaries and nonce cleanup', () => {
  // Force otherwise astronomically unlikely challenges. With x=3 and V=6G,
  // the verification equation is 6G = rG + c(3G).
  it.each([
    { name: 'zero response', r: 0n, c: 2n },
    { name: 'zero challenge', r: 6n, c: 0n },
  ])(
    'should accept a valid $name and reject a changed response',
    ({ r, c }) => {
      vi.mocked(sha3_256).mockReturnValue(numberToBytesBE(c, 32))
      const proof = new Uint8Array([
        33,
        ...G.multiply(6n).toBytes(true),
        32,
        ...numberToBytesBE(r, 32),
      ])
      expect(verifySchnorrProof('Alice', G.multiply(3n), proof, G)).toBe(true)

      proof.set(numberToBytesBE(r + 1n, 32), 35)
      expect(verifySchnorrProof('Alice', G.multiply(3n), proof, G)).toBe(false)
    },
  )

  it('should generate and self-verify a proof whose response is zero', () => {
    vi.mocked(sha3_256).mockReturnValue(numberToBytesBE(2n, 32))
    const nonceBytes = numberToBytesBE(6n, 32)
    vi.mocked(secp256k1.utils.randomSecretKey).mockReturnValueOnce(nonceBytes)
    const proof = generateSchnorrProof(
      'Alice',
      numberToBytesBE(3n, 32),
      G.multiply(3n),
      G,
    )
    expect(proof.subarray(35)).toEqual(new Uint8Array(32))
    expect(nonceBytes).toEqual(new Uint8Array(32))
    expect(verifySchnorrProof('Alice', G.multiply(3n), proof, G)).toBe(true)
  })

  it('should wipe the nonce buffer before a later proof-generation failure', () => {
    const nonceBytes = numberToBytesBE(6n, 32)
    vi.mocked(secp256k1.utils.randomSecretKey).mockReturnValueOnce(nonceBytes)

    expect(() =>
      generateSchnorrProof(
        '\uD800',
        numberToBytesBE(3n, 32),
        G.multiply(3n),
        G,
      ),
    ).toThrowError(InvalidArgumentError)
    expect(nonceBytes).toEqual(new Uint8Array(32))
  })
})

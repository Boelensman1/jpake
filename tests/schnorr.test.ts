import { describe, it, expect } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import {
  bytesToNumberBE,
  hexToBytes,
  numberToBytesBE,
} from '@noble/curves/utils.js'
import {
  generateSchnorrChallenge,
  generateSchnorrProof,
  verifySchnorrProof,
} from '../src/schnorr.mjs'
import { G, n } from '../src/constants.mjs'
import { VerificationError } from '../src/JPakeErrors.mjs'

describe('Schnorr Signature Scheme', () => {
  const userId = 'testUser'
  const privateKey = secp256k1.utils.randomSecretKey()
  const publicKey = G.multiply(bytesToNumberBE(privateKey))

  // Independently calculated with Python hashlib.sha3_256 and affine secp256k1
  // arithmetic, using x = 3, v = 5, and one-byte length prefixes on each field.
  // The transcript order is generator, commitment, public key, ID, then context.
  const otherInfo = ['jpake-test', 'context']
  const vectors = [
    {
      name: 'base generator',
      generator: G,
      challenge:
        0xcddfdcebc5ab911a77b248c99c9258e072b9d9208b294172a5957525e230de22n,
      proof:
        '21022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4209660693caefd4cb098e925a32a48f55ad7df0b526c5e1c5b4eb6bc34ca102962',
      legacyProof:
        '21022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe420e41fefdfd1146c1851f4e7833cdc2292e0ee9a0fe4da96ea963c236cf4057969',
    },
    {
      name: 'derived generator',
      generator: G.multiply(7n),
      challenge:
        0xa6a621613f18cee8983014f0c8005fc9b8049ef2aaa78448dd55a4b1767987e2n,
      proof:
        '2103605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479200c0d9bdc42b59346376fc12da7fee0a04d4fdcf55e9ab39ce7a3cf053cffeae1',
      legacyProof:
        '2103605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a747920e400039e8beedc53afeaeaaa607d03bd1b31a38e4a4c68bcbc23a7e25ec8f1a0',
    },
  ]

  it.each(vectors)(
    'should match the independent challenge for $name',
    ({ generator, challenge }) => {
      expect(
        generateSchnorrChallenge(
          userId,
          generator.multiply(3n),
          generator.multiply(5n),
          generator,
          otherInfo,
        ),
      ).toBe(challenge)
    },
  )

  it.each(vectors)(
    'should verify independently computed proofs for $name',
    ({ generator, proof }) => {
      expect(
        verifySchnorrProof(
          userId,
          generator.multiply(3n),
          hexToBytes(proof),
          generator,
          otherInfo,
        ),
      ).toBe(true)
    },
  )

  it.each(vectors)(
    'should reject legacy proofs without generator binding for $name',
    ({ generator, legacyProof }) => {
      expect(
        verifySchnorrProof(
          userId,
          generator.multiply(3n),
          hexToBytes(legacyProof),
          generator,
          otherInfo,
        ),
      ).toBe(false)
    },
  )

  it('should change the challenge when only the generator changes', () => {
    const gr = G.multiply(5n)
    const challenge = generateSchnorrChallenge(userId, publicKey, gr, G)

    expect(
      generateSchnorrChallenge(userId, publicKey, gr, G.multiply(7n)),
    ).not.toBe(challenge)
  })

  it('should generate a valid Schnorr challenge', () => {
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomSecretKey()))
    const challenge = generateSchnorrChallenge(userId, publicKey, gr, G)

    expect(challenge).toBeDefined()
    expect(typeof challenge).toBe('bigint')
  })

  it.each(vectors)(
    'should generate and verify a valid Schnorr proof for $name',
    ({ generator }) => {
      const gx = generator.multiply(bytesToNumberBE(privateKey))
      const proof = generateSchnorrProof(userId, privateKey, gx, generator)

      expect(proof).toBeDefined()
      expect(proof instanceof Uint8Array).toBe(true)

      const isValid = verifySchnorrProof(userId, gx, proof, generator)
      expect(isValid).toBe(true)
    },
  )

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

  it.each([n, n + 1n, (1n << 256n) - 1n])(
    'should reject out-of-range response %s with a protocol error',
    (r) => {
      const proof = hexToBytes(vectors[0].proof)
      proof.set(numberToBytesBE(r, 32), 35)
      expect(() =>
        verifySchnorrProof(userId, G.multiply(3n), proof, G, otherInfo),
      ).toThrowError(VerificationError)
    },
  )

  it('should reject an incorrect zero response without a RangeError', () => {
    const proof = hexToBytes(vectors[0].proof)
    proof.fill(0, 35)
    expect(
      verifySchnorrProof(userId, G.multiply(3n), proof, G, otherInfo),
    ).toBe(false)
  })

  it.each([null, {}, 'not a proof', new Array<number>(67).fill(0)])(
    'should reject non-byte proof %j with a protocol error',
    (proof) => {
      expect(() =>
        verifySchnorrProof(
          userId,
          publicKey,
          proof as unknown as Uint8Array,
          G,
        ),
      ).toThrowError(VerificationError)
    },
  )

  it.each(['peer\uD800', 'peer\uDC00'])(
    'should reject proof identity alias %j',
    (peerId) => {
      const proof = generateSchnorrProof('peer\uFFFD', privateKey, publicKey, G)

      expect(() =>
        verifySchnorrProof(peerId, publicKey, proof, G),
      ).toThrowError('userId must contain only well-formed Unicode.')
    },
  )

  it.each(['context\uD800', 'context\uDC00'])(
    'should reject proof context alias %j',
    (context) => {
      const proof = generateSchnorrProof(userId, privateKey, publicKey, G, [
        'context\uFFFD',
      ])

      expect(() =>
        verifySchnorrProof(userId, publicKey, proof, G, [context]),
      ).toThrowError('otherInfo must contain only well-formed Unicode.')
      expect(() =>
        generateSchnorrProof(userId, privateKey, publicKey, G, [context]),
      ).toThrowError('otherInfo must contain only well-formed Unicode.')
    },
  )

  it('should preserve valid Unicode context, including empty strings', () => {
    const context = ['', '🔐', '\uFFFD', '\uFEFF', 'é', 'e\u0301']
    const proof = generateSchnorrProof(
      userId,
      privateKey,
      publicKey,
      G,
      context,
    )

    expect(verifySchnorrProof(userId, publicKey, proof, G, context)).toBe(true)
    expect(
      verifySchnorrProof(userId, publicKey, proof, G, [
        '',
        '🔐',
        '\uFFFD',
        '',
        'é',
        'e\u0301',
      ]),
    ).toBe(false)
  })

  it('should handle otherInfo correctly', () => {
    const otherInfo = ['additional', 'information']
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomSecretKey()))
    const challenge = generateSchnorrChallenge(
      userId,
      publicKey,
      gr,
      G,
      otherInfo,
    )

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
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomSecretKey()))

    expect(() =>
      generateSchnorrChallenge(longUserId, publicKey, gr, G),
    ).toThrowError(
      'userId is too long. It must be 255 bytes or less when UTF-8 encoded.',
    )
  })

  it('should throw an error for long otherInfo', () => {
    const longOtherInfo = ['a'.repeat(256)]
    const gr = G.multiply(bytesToNumberBE(secp256k1.utils.randomSecretKey()))

    expect(() =>
      generateSchnorrChallenge(userId, publicKey, gr, G, longOtherInfo),
    ).toThrowError(
      'otherInfo is too long. It must be 255 bytes or less when UTF-8 encoded.',
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

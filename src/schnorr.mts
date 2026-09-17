import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { concatBytes, isBytes } from '@noble/hashes/utils.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { mod } from '@noble/curves/abstract/modular.js'

import {
  InvalidArgumentError,
  JPakeError,
  VerificationError,
} from './JPakeErrors.mjs'
import { n } from './constants.mjs'
import { encodeProtocolField } from './encodeProtocolString.mjs'

// Implementation of Schnorr ZKP using https://www.rfc-editor.org/rfc/rfc8235

/**
 * Generates a Schnorr challenge.
 * @param userId - The user ID.
 * @param gx - The public key point.
 * @param gr - The random point.
 * @param g - The generator point.
 * @param otherInfo - Additional information to include in the challenge.
 * @returns The challenge.
 * @throws {InvalidArgumentError} If userId or any context string is not well-formed Unicode or exceeds 255 UTF-8 bytes.
 */
export const generateSchnorrChallenge = (
  userId: string,
  gx: WeierstrassPoint<bigint>,
  gr: WeierstrassPoint<bigint>,
  g: WeierstrassPoint<bigint>,
  otherInfo: string[] = [],
): bigint => {
  const userIdBytes = encodeProtocolField(userId, 'userId')
  const gBytes = g.toBytes(true)
  const gxBytes = gx.toBytes(true)
  const grBytes = gr.toBytes(true)

  // These point-length checks should be superfluous
  if (gBytes.length > 255) {
    throw new InvalidArgumentError(
      'gBytes is too long. It must be 255 bytes or less.',
    )
  }
  if (gxBytes.length > 255) {
    throw new InvalidArgumentError(
      'gxBytes is too long. It must be 255 bytes or less.',
    )
  }
  if (grBytes.length > 255) {
    throw new InvalidArgumentError(
      'grBytes is too long. It must be 255 bytes or less.',
    )
  }

  // RFC 8235: H(G || V || A || UserID || OtherInfo), with length prefixes.
  const challenge = mod(
    bytesToNumberBE(
      sha3_256(
        concatBytes(
          new Uint8Array([gBytes.length]),
          gBytes,

          new Uint8Array([grBytes.length]),
          grBytes,

          new Uint8Array([gxBytes.length]),
          gxBytes,

          new Uint8Array([userIdBytes.length]),
          userIdBytes,

          ...otherInfo.map((info) => {
            const infoBytes = encodeProtocolField(info, 'otherInfo')
            return concatBytes(new Uint8Array([infoBytes.length]), infoBytes)
          }),
        ),
      ),
    ),
    n,
  )

  return challenge
}

/**
 * Generates a Schnorr proof.
 * @param  userId - The user ID.
 * @param  x - The private key.
 * @param  gx - The public key point.
 * @param  g - The generator point.
 * @param  otherInfo - Additional information to include in the challenge.
 * @returns The proof.
 * @throws {Error} If the generated proof is invalid.
 */
export const generateSchnorrProof = (
  userId: string,
  x: Uint8Array,
  gx: WeierstrassPoint<bigint>,
  g: WeierstrassPoint<bigint>,
  otherInfo: string[] = [],
): Uint8Array => {
  const vBytes = secp256k1.utils.randomSecretKey()
  const v = bytesToNumberBE(vBytes)
  vBytes.fill(0)

  const V = g.multiply(v)

  const challenge = generateSchnorrChallenge(userId, gx, V, g, otherInfo)

  const r = numberToBytesBE(mod(v - bytesToNumberBE(x) * challenge, n), 32)

  const Vbytes = V.toBytes(true)
  if (Vbytes.length !== 33 || r.length !== 32) {
    throw new JPakeError(
      'Generated proof is invalid, V and r must be 33 and 32 bytes respectively',
    )
  }
  const proof = concatBytes(
    new Uint8Array([Vbytes.length]),
    Vbytes,
    new Uint8Array([r.length]),
    r,
  )

  // Verify the proof before returning it
  const isValidProof = verifySchnorrProof(userId, gx, proof, g, otherInfo)
  if (!isValidProof) {
    throw new JPakeError('Generated Schnorr proof is invalid')
  }

  return proof
}

/**
 * Checks the byte type, total length, and component lengths of a Schnorr proof.
 * @param proof - The proof to check.
 * @throws {VerificationError} If the proof does not have the required wire shape.
 */
export function assertProofShape(proof: unknown): asserts proof is Uint8Array {
  if (!isBytes(proof) || proof.length !== 33 + 32 + 2) {
    throw new VerificationError('Invalid proof, must be 33 + 32 + 2 bytes long')
  }
  if (proof[0] !== 33 || proof[34] !== 32) {
    throw new VerificationError(
      'Invalid proof, V must be 33 bytes and r must be 32 bytes',
    )
  }
}

/**
 * Verifies a Schnorr proof.
 * Any malformed proof returns false instead of throwing, so peer-supplied bytes
 * cannot decide between a boolean result and an exception. Invalid local
 * arguments, such as an ill-formed peerUserId or otherInfo, still throw. Use
 * assertProofShape where a caller must reject the wire shape explicitly.
 * @param peerUserId - The peer user ID.
 * @param gx - The public key point.
 * @param proof - The proof to verify.
 * @param g - The generator point.
 * @param otherInfo - Additional information to include in the challenge.
 * @returns True if the proof is valid, false otherwise.
 * @throws {InvalidArgumentError} If peerUserId or any context string is not well-formed Unicode or exceeds 255 UTF-8 bytes.
 */
export const verifySchnorrProof = (
  peerUserId: string,
  gx: WeierstrassPoint<bigint>,
  proof: Uint8Array,
  g: WeierstrassPoint<bigint>,
  otherInfo: string[] = [],
): boolean => {
  try {
    assertProofShape(proof)
  } catch {
    // Wrong type, total length, or component lengths.
    return false
  }
  // Component lengths have been validated by assertProofShape.
  const VLength = proof[0]
  const rLength = proof[1 + VLength]

  // Extract V and r from the proof
  let V
  try {
    V = secp256k1.Point.fromBytes(proof.slice(1, 1 + VLength))
  } catch {
    // Error: Point is not on curve, proof was tampered with
    return false
  }
  const r = bytesToNumberBE(
    proof.slice(1 + VLength + 1, 1 + VLength + 1 + rLength),
  )
  // A response at or above the curve order cannot come from a valid proof.
  if (r >= n) {
    return false
  }

  // Compute the challenge
  const c = generateSchnorrChallenge(peerUserId, gx, V, g, otherInfo)

  // Verify that V = G * [r] + gx * [c]
  const leftSide = V
  // Both scalars are public and may be zero. Secret-scalar multiply rejects zero.
  const rightSide = g.multiplyUnsafe(r).add(gx.multiplyUnsafe(c))

  // Convert both sides to affine coordinates for comparison
  // This is necessary because one side might be normalized (in affine form)
  // while the other might not be, leading to false negatives in the comparison
  const leftSideAffine = leftSide.toAffine()
  const rightSideAffine = rightSide.toAffine()

  const isValid =
    leftSideAffine.x === rightSideAffine.x &&
    leftSideAffine.y === rightSideAffine.y

  return isValid
}

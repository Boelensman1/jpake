import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import {
  assertProofShape,
  generateSchnorrProof,
  verifySchnorrProof,
} from './schnorr.mjs'
import { mod } from '@noble/curves/abstract/modular.js'

import {
  InvalidArgumentError,
  InvalidStateError,
  VerificationError,
  JPakeError,
} from './JPakeErrors.mjs'
import { n, G } from './constants.mjs'
import { encodeProtocolField } from './encodeProtocolString.mjs'

export interface Round1Result {
  G1: Uint8Array
  G2: Uint8Array
  ZKPx1: Uint8Array
  ZKPx2: Uint8Array
}

export interface Round2Result {
  A: Uint8Array
  ZKPx2s: Uint8Array
}

export interface SharedKeyResult {
  key: Uint8Array
  transcript: Uint8Array
}

// Domain separation tag for the shared key. Hashing it alongside Ka keeps the
// key bound to this protocol and encoding, so another protocol that reaches the
// same Ka does not reach the same key. Changing it changes every derived key.
const KEY_DERIVATION_LABEL = 'jpake-ts/v2 secp256k1 sha3-256 shared key'

/**
 * Prefixes a protocol field with its one-byte length.
 * @param bytes - The field, at most 255 bytes long.
 * @returns The length-prefixed field.
 */
const lengthPrefixed = (bytes: Uint8Array): Uint8Array =>
  concatBytes(new Uint8Array([bytes.length]), bytes)

/**
 * Orders two byte strings lexicographically, shorter first on a common prefix.
 * @param a - The first byte string.
 * @param b - The second byte string.
 * @returns A negative number if a sorts first, a positive number if b does.
 */
const compareBytes = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i]
    }
  }
  return a.length - b.length
}

export enum JPakeState {
  INITIAL,
  ROUND1FINISHED,
  ROUND2FINISHED,
  ROUND2RESULTSRECEIVED,
  /** Local key derivation succeeded; peer possession remains unconfirmed. */
  KEYDERIVED,
  FAILED,
}

/**
 * Implements the J-PAKE (Password Authenticated Key Exchange by Juggling) protocol.
 * Based on RFC 8236: https://www.rfc-editor.org/rfc/rfc8236.txt
 * Comments with 'from RFC' refer directly to this RFC
 * Two round implementation is fully from the perspective of Alice
 * Errors during a round abort the session and clear its secret buffers.
 * Calls made in the wrong state throw without changing the session state.
 */
class JPake {
  readonly userId: string
  #state: JPakeState

  #x1?: Uint8Array
  #x2?: Uint8Array
  private G1?: WeierstrassPoint<bigint>
  private G2?: WeierstrassPoint<bigint>
  private G3?: WeierstrassPoint<bigint>
  private G4?: WeierstrassPoint<bigint>
  private A?: WeierstrassPoint<bigint>
  private B?: WeierstrassPoint<bigint>
  #x2s?: Uint8Array
  private ZKPx2sBob?: Uint8Array
  private bobUserId?: string

  /**
   * @returns The current state of the J-PAKE transfer.
   */
  public getState() {
    return this.#state
  }

  /**
   * Creates a new instance of the JPake protocol.
   * @param userId - The unique identifier for the current user.
   * @param otherInfo - Optional additional information to be included in the protocol.
   * @throws {InvalidArgumentError} If userId or any context string is empty, not a well-formed Unicode string, or exceeds 255 UTF-8 bytes.
   */
  constructor(
    userId: string,
    private readonly otherInfo?: string[],
  ) {
    if (!userId) {
      throw new InvalidArgumentError('UserId cannot be empty')
    }
    encodeProtocolField(userId, 'userId')
    // Reject unusable context up front rather than partway through round one.
    // Each proof re-encodes it, so a caller that mutates the array afterwards
    // still fails, and both peers still fail closed on mismatched context.
    for (const info of otherInfo ?? []) {
      encodeProtocolField(info, 'otherInfo')
    }
    this.userId = userId
    this.#state = JPakeState.INITIAL
  }

  #clearSecrets(): void {
    this.#x1?.fill(0)
    this.#x2?.fill(0)
    this.#x2s?.fill(0)
    this.#x1 = undefined
    this.#x2 = undefined
    this.#x2s = undefined
  }

  // Both peers must hash the same transcript, but each labels its own keys G1
  // and G2 and its peer's G3 and G4. Ordering the two parties by encoded user ID
  // makes the bytes identical on both sides while keeping each identity next to
  // its own contributions. Round two already rejects equal IDs, so the order is
  // total.
  #buildTranscript(
    selfPoints: Uint8Array[],
    peerPoints: Uint8Array[],
    peerUserId: string,
  ): Uint8Array {
    const self = {
      id: encodeProtocolField(this.userId, 'userId'),
      points: selfPoints,
    }
    const peer = {
      id: encodeProtocolField(peerUserId, 'peerUserId'),
      points: peerPoints,
    }
    const ordered =
      compareBytes(self.id, peer.id) < 0 ? [self, peer] : [peer, self]

    return concatBytes(
      ...ordered.flatMap((party) => [
        lengthPrefixed(party.id),
        ...party.points.map((point) => lengthPrefixed(point)),
      ]),
      ...(this.otherInfo ?? []).map((info) =>
        lengthPrefixed(encodeProtocolField(info, 'otherInfo')),
      ),
    )
  }

  // State checks stay outside this boundary: processing failures abort the
  // session, while an out-of-order API call does not interrupt a valid exchange.
  #runStep<T>(step: () => T): T {
    try {
      return step()
    } catch (error) {
      this.#state = JPakeState.FAILED
      this.#clearSecrets()
      if (error instanceof JPakeError) {
        throw error
      }
      throw new JPakeError('J-PAKE operation failed', { cause: error })
    }
  }

  /**
   * Verifies the Schnorr Zero-Knowledge Proof from the peer.
   * @param peerUserId - The unique identifier of the peer.
   * @param gx - The public key point to verify.
   * @param proof - The Schnorr proof to verify.
   * @param g - The base point for the proof.
   * @returns True if the proof is valid, false otherwise.
   * @throws {VerificationError} If the peerUserId is invalid or matches the current user's ID.
   */
  private verifyPeerProof(
    peerUserId: string,
    gx: WeierstrassPoint<bigint>,
    proof: Uint8Array,
    g: WeierstrassPoint<bigint>,
  ): boolean {
    if (this.userId === peerUserId) {
      throw new VerificationError(
        'Proof verification failed, userIds are equal.',
      )
    }
    if (!peerUserId) {
      throw new InvalidArgumentError('PeerUserId is empty.')
    }

    return verifySchnorrProof(peerUserId, gx, proof, g, this.otherInfo)
  }

  /**
   * Executes Round 1 of the J-PAKE protocol.
   * From RFC:
   * Round 1: Alice selects an ephemeral private key x1 uniformly at
   * random from [0, q-1] and another ephemeral private key x2 uniformly
   * at random from [1, q-1]. G1 = G x [x1], G2 = G x [x2] and ZKPs for x1 and x2
   * @returns The public values and proofs for Round 1.
   * @throws {InvalidStateError} If called in an invalid state.
   * @throws {JPakeError} If generation fails; the session enters FAILED.
   */
  public round1(): Round1Result {
    if (this.#state !== JPakeState.INITIAL) {
      throw new InvalidStateError(
        'Round 1 can only be executed in INITIAL state',
      )
    }

    return this.#runStep(() => {
      // secp256k1.utils.randomSecretKey() ends with:
      // mod(b2n(hash), N - 1n) + 1n;
      // therefore this guarantees that the output is in the range
      // of [1, n-1], making it valid for both
      this.#x1 = secp256k1.utils.randomSecretKey()
      this.#x2 = secp256k1.utils.randomSecretKey()

      // calculate G1 = G x [x1]
      this.G1 = G.multiply(bytesToNumberBE(this.#x1))
      //  and G2 = G x [x2].
      this.G2 = G.multiply(bytesToNumberBE(this.#x2))

      // calculate ZKPs for x1 and x2
      const ZKPx1 = generateSchnorrProof(
        this.userId,
        this.#x1,
        this.G1,
        G,
        this.otherInfo,
      )
      const ZKPx2 = generateSchnorrProof(
        this.userId,
        this.#x2,
        this.G2,
        G,
        this.otherInfo,
      )

      if (!this.G1 || !this.G2 || !ZKPx1 || !ZKPx2) {
        throw new JPakeError('Failed to generate round 1 results')
      }

      // x1 is no longer needed once its proof has been generated.
      this.#x1.fill(0)
      this.#x1 = undefined
      this.#state = JPakeState.ROUND1FINISHED
      return { G1: this.G1.toBytes(), G2: this.G2.toBytes(), ZKPx1, ZKPx2 }
    })
  }

  /**
   * Executes Round 2 of the J-PAKE protocol.
   * From RFC:
   * When round 1 finishes, Alice verifies the received ZKPs as
   * specified in [RFC8235]. The verifier shall check the prover's UserID is a
   * valid identity and is different from its own identity. If the verification
   * of the ZKP fails, the session is aborted.
   * Then: Alice -> Bob: A = (G1 + G3 + G4) x [x2*s] and a ZKP for x2*s
   * @param round1ResultBob - The Round 1 results received from Bob.
   * @param s - The shared secret (password) encoded as big-endian scalar bytes.
   * @param bobUserId - Bob's unique identifier.
   * @returns The public values and proofs for Round 2.
   * @throws {InvalidStateError} If called in an invalid state.
   * @throws {JPakeError} If arguments or proofs are invalid; the session enters FAILED.
   */
  public round2(
    round1ResultBob: Round1Result,
    s: Uint8Array,
    bobUserId: string,
  ): Round2Result {
    if (this.#state !== JPakeState.ROUND1FINISHED) {
      throw new InvalidStateError('Round 2 can only be executed after Round 1')
    }

    return this.#runStep(() => {
      if (
        !round1ResultBob?.G1 ||
        !round1ResultBob.G2 ||
        !round1ResultBob.ZKPx1 ||
        !round1ResultBob.ZKPx2 ||
        !s ||
        !bobUserId
      ) {
        throw new InvalidArgumentError('Missing required arguments for round 2')
      }

      if (!this.#x2 || !this.G1) {
        throw new JPakeError('Missing required data for round 2')
      }

      let round1ResultBobG1, round1ResultBobG2
      try {
        round1ResultBobG1 = secp256k1.Point.fromBytes(round1ResultBob.G1)
        round1ResultBobG2 = secp256k1.Point.fromBytes(round1ResultBob.G2)
      } catch {
        throw new InvalidArgumentError(
          'Invalid points received: G1 or G2 is not a valid Point',
        )
      }

      const sBigInt = bytesToNumberBE(s)

      // from RFC: s MUST not be equal to 0 mod n
      if (mod(sBigInt, n) === 0n) {
        throw new InvalidArgumentError(
          'Invalid s: s MUST not be equal to 0 mod n',
        )
      }

      // Verify both peer proofs before using their points with the shared secret.
      if (
        !this.verifyPeerProof(
          bobUserId,
          round1ResultBobG1,
          round1ResultBob.ZKPx1,
          G,
        ) ||
        !this.verifyPeerProof(
          bobUserId,
          round1ResultBobG2,
          round1ResultBob.ZKPx2,
          G,
        )
      ) {
        throw new VerificationError('ZKP verification failed')
      }

      this.bobUserId = bobUserId
      this.G3 = round1ResultBobG1 // Bob's G1
      this.G4 = round1ResultBobG2 // Bob's G2

      this.#x2s = numberToBytesBE(
        mod(bytesToNumberBE(this.#x2) * sBigInt, n),
        32,
      )

      // For Alice, the new generator is G1 + G3 + G4
      const generator = this.G1.add(this.G3).add(this.G4)

      // Check the generator before using it in secret-scalar multiplication.
      if (generator.equals(secp256k1.Point.ZERO)) {
        throw new VerificationError(
          'Invalid point: The new generator is the point at infinity',
        )
      }

      // A = (G1 + G3 + G4) x [x2*s]
      const A = generator.multiply(bytesToNumberBE(this.#x2s))

      // and a ZKP for x2*s
      const ZKPx2s = generateSchnorrProof(
        this.userId,
        this.#x2s,
        A,
        generator,
        this.otherInfo,
      )

      if (!A || !ZKPx2s) {
        throw new JPakeError('Failed to generate round 2 results')
      }

      this.A = A
      this.#state = JPakeState.ROUND2FINISHED
      return { A: A.toBytes(true), ZKPx2s }
    })
  }

  /**
   * Sets the Round 2 results received from Bob.
   * @param round2ResultBob - The Round 2 results received from Bob.
   * @throws {InvalidStateError} If called in an invalid state.
   * @throws {JPakeError} If the received results are invalid; the session enters FAILED.
   */
  public setRound2ResultFromBob(round2ResultBob: Round2Result) {
    if (this.#state !== JPakeState.ROUND2FINISHED) {
      throw new InvalidStateError(
        'Round 2 results can only be set after Round 2 is finished',
      )
    }

    this.#runStep(() => {
      if (!round2ResultBob?.A || !round2ResultBob.ZKPx2s) {
        throw new InvalidArgumentError(
          'Missing required arguments for setRound2ResultFromBob',
        )
      }

      try {
        this.B = secp256k1.Point.fromBytes(round2ResultBob.A)
      } catch {
        throw new InvalidArgumentError(
          'Invalid point received: A is not a valid Point',
        )
      }
      assertProofShape(round2ResultBob.ZKPx2s)
      // Construct a copy even when the caller passes a Node Buffer, whose slice()
      // method would retain a view of the caller's storage.
      this.ZKPx2sBob = new Uint8Array(round2ResultBob.ZKPx2s)
      this.#state = JPakeState.ROUND2RESULTSRECEIVED
    })
  }

  /**
   * Derives the shared key after completing Round 2.
   * Peers with different passwords can both succeed and derive different keys.
   * The application must confirm peer possession before authenticating the peer.
   * This method does not perform key confirmation (RFC 8236 Section 5).
   *
   * From RFC:
   * When the second round finishes, Alice verifies the received
   * ZKPs. Alice and Bob shall check that these new generators are not points
   * at infinity. If the verification fails, the session is aborted. Otherwise,
   * the two parties compute the common key material as follows:
   * o  Alice computes Ka = (B - (G4 x [x2*s])) x [x2]
   * The key is the hash of the length-prefixed domain separation tag, the
   * length-prefixed compressed Ka, and the transcript. The transcript holds the
   * public values of the exchange in an order both peers compute identically;
   * it is not secret, and is what a confirmation step should be built over.
   * @returns The derived, unconfirmed session key and the transcript it is
   * bound to.
   * @throws {InvalidStateError} If called in an invalid state.
   * @throws {JPakeError} If derivation or verification fails; the session enters FAILED.
   */
  public deriveSharedKey(): SharedKeyResult {
    if (this.#state !== JPakeState.ROUND2RESULTSRECEIVED) {
      throw new InvalidStateError(
        'Shared key can only be derived after receiving Round 2 results',
      )
    }
    return this.#runStep(() => {
      if (
        !this.B ||
        !this.G1 ||
        !this.G2 ||
        !this.G3 ||
        !this.G4 ||
        !this.A ||
        !this.#x2 ||
        !this.#x2s ||
        !this.ZKPx2sBob ||
        !this.bobUserId
      ) {
        throw new JPakeError('Missing required data for key derivation')
      }

      // Check that B is not a point at infinity
      if (this.B.equals(secp256k1.Point.ZERO)) {
        throw new VerificationError('Invalid point: B is the point at infinity')
      }

      // Verify the received ZKP from Bob
      const generator = this.G1.add(this.G3).add(this.G2)
      if (generator.equals(secp256k1.Point.ZERO)) {
        throw new VerificationError(
          'Invalid point: The new generator is the point at infinity',
        )
      }
      const isValidZKP = this.verifyPeerProof(
        this.bobUserId,
        this.B,
        this.ZKPx2sBob,
        generator,
      )
      if (!isValidZKP) {
        throw new VerificationError('ZKP verification failed')
      }

      // Ka = (B - (G4 x [x2*s])) x [x2]
      const Ka = this.B.subtract(
        this.G4.multiply(bytesToNumberBE(this.#x2s)),
      ).multiply(bytesToNumberBE(this.#x2))

      // Convert Ka to bytes
      const sharedSecret = Ka.toBytes(true)

      if (!sharedSecret) {
        throw new JPakeError('Failed to derive shared key')
      }

      const label = encodeProtocolField(
        KEY_DERIVATION_LABEL,
        'keyDerivationLabel',
      )
      // The transcript trails the fixed fields, and every field it holds
      // carries its own length, so the hashed encoding stays unambiguous.
      const transcript = this.#buildTranscript(
        [this.G1, this.G2, this.A].map((point) => point.toBytes(true)),
        [this.G3, this.G4, this.B].map((point) => point.toBytes(true)),
        this.bobUserId,
      )

      try {
        const key = sha3_256(
          concatBytes(
            lengthPrefixed(label),
            lengthPrefixed(sharedSecret),
            transcript,
          ),
        )
        this.#clearSecrets()
        this.#state = JPakeState.KEYDERIVED
        return { key, transcript }
      } finally {
        sharedSecret.fill(0)
      }
    })
  }
}

export default JPake

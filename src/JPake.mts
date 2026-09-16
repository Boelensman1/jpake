import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { generateSchnorrProof, verifySchnorrProof } from './schnorr.mjs'
import { mod } from '@noble/curves/abstract/modular.js'

import {
  InvalidArgumentError,
  InvalidStateError,
  VerificationError,
  JPakeError,
} from './JPakeErrors.mjs'
import { n, G } from './constants.mjs'

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

export enum JPakeState {
  INITIAL,
  ROUND1FINISHED,
  ROUND2FINISHED,
  ROUND2RESULTSRECEIVED,
  KEYDERIVED,
}

/**
 * Implements the J-PAKE (Password Authenticated Key Exchange by Juggling) protocol.
 * Based on RFC 8236: https://www.rfc-editor.org/rfc/rfc8236.txt
 * Comments with 'from RFC' refer directly to this RFC
 * Two round implementation is fully from the perspective of Alice
 */
class JPake {
  readonly userId: string
  private state: JPakeState

  private x1?: Uint8Array
  private x2?: Uint8Array
  private G1?: WeierstrassPoint<bigint>
  private G2?: WeierstrassPoint<bigint>
  private G3?: WeierstrassPoint<bigint>
  private G4?: WeierstrassPoint<bigint>
  private B?: WeierstrassPoint<bigint>
  private x2s?: Uint8Array
  private ZKPx2sBob?: Uint8Array
  private bobUserId?: string

  /**
   * @returns The current state of the J-PAKE transfer.
   */
  public getState() {
    return this.state
  }

  /**
   * Creates a new instance of the JPake protocol.
   * @param userId - The unique identifier for the current user.
   * @param otherInfo - Optional additional information to be included in the protocol.
   * @throws {InvalidArgumentError} If userId is empty.
   */
  constructor(
    userId: string,
    private readonly otherInfo?: string[],
  ) {
    if (!userId) {
      throw new InvalidArgumentError('UserId cannot be empty')
    }
    this.userId = userId
    this.state = JPakeState.INITIAL
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
   * @throws {InvalidStateError} If called in an invalid state or if generation fails.
   */
  public round1(): Round1Result {
    if (this.state !== JPakeState.INITIAL) {
      throw new InvalidStateError(
        'Round 1 can only be executed in INITIAL state',
      )
    }

    // secp256k1.utils.randomSecretKey() ends with:
    // mod(b2n(hash), N - 1n) + 1n;
    // therefore this guarantees that the output is in the range
    // of [1, n-1], making it valid for both
    this.x1 = secp256k1.utils.randomSecretKey()
    this.x2 = secp256k1.utils.randomSecretKey()

    // calculate G1 = G x [x1]
    this.G1 = G.multiply(bytesToNumberBE(this.x1))
    //  and G2 = G x [x2].
    this.G2 = G.multiply(bytesToNumberBE(this.x2))

    // calculate ZKPs for x1 and x2
    const ZKPx1 = generateSchnorrProof(
      this.userId,
      this.x1,
      this.G1,
      G,
      this.otherInfo,
    )
    const ZKPx2 = generateSchnorrProof(
      this.userId,
      this.x2,
      this.G2,
      G,
      this.otherInfo,
    )

    if (!this.G1 || !this.G2 || !ZKPx1 || !ZKPx2) {
      throw new JPakeError('Failed to generate round 1 results')
    }

    this.state = JPakeState.ROUND1FINISHED
    return { G1: this.G1.toBytes(), G2: this.G2.toBytes(), ZKPx1, ZKPx2 }
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
   * @param s - The shared secret (password) converted to a bigint.
   * @param bobUserId - Bob's unique identifier.
   * @returns The public values and proofs for Round 2.
   * @throws {InvalidStateError} If called in an invalid state, if arguments are invalid, or if verification fails.
   */
  public round2(
    round1ResultBob: Round1Result,
    s: Uint8Array,
    bobUserId: string,
  ): Round2Result {
    if (this.state !== JPakeState.ROUND1FINISHED) {
      throw new InvalidStateError('Round 2 can only be executed after Round 1')
    }

    if (
      !round1ResultBob.G1 ||
      !round1ResultBob.G2 ||
      !round1ResultBob.ZKPx1 ||
      !round1ResultBob.ZKPx2 ||
      !s ||
      !bobUserId
    ) {
      throw new InvalidArgumentError('Missing required arguments for round 2')
    }

    if (!this.x2 || !this.G1) {
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

    this.x2s = numberToBytesBE(mod(bytesToNumberBE(this.x2) * sBigInt, n), 32)

    //  A = (G1 + G3 + G4) x [x2*s]
    const A = this.G1.add(this.G3)
      .add(this.G4)
      .multiply(bytesToNumberBE(this.x2s))

    // For Alice, the new generator is G1 + G3 + G4
    const generator = this.G1.add(this.G3).add(this.G4)

    // and a ZKP for x2*s
    const ZKPx2s = generateSchnorrProof(
      this.userId,
      this.x2s,
      A,
      generator,
      this.otherInfo,
    )

    // from RFC: Alice shall check that these new generators are not points at infinity.
    if (generator.equals(secp256k1.Point.ZERO)) {
      throw new VerificationError(
        'Invalid point: The new generator is the point at infinity',
      )
    }

    if (!A || !ZKPx2s) {
      throw new JPakeError('Failed to generate round 2 results')
    }

    this.state = JPakeState.ROUND2FINISHED
    return { A: A.toBytes(true), ZKPx2s }
  }

  /**
   * Sets the Round 2 results received from Bob.
   * @param round2ResultBob - The Round 2 results received from Bob.
   * @throws {InvalidStateError} If called in an invalid state or if the received results are incomplete.
   */
  public setRound2ResultFromBob(round2ResultBob: Round2Result) {
    if (this.state !== JPakeState.ROUND2FINISHED) {
      throw new InvalidStateError(
        'Round 2 results can only be set after Round 2 is finished',
      )
    }

    if (!round2ResultBob.A || !round2ResultBob.ZKPx2s) {
      throw new InvalidArgumentError(
        'Missing required arguments for setRound2ResultFromBob',
      )
    }

    this.B = secp256k1.Point.fromBytes(round2ResultBob.A)
    this.ZKPx2sBob = round2ResultBob.ZKPx2s
    this.state = JPakeState.ROUND2RESULTSRECEIVED
  }

  /**
   * Derives the shared key after completing Round 2.
   * From RFC:
   * When the second round finishes, Alice verifies the received
   * ZKPs. Alice and Bob shall check that these new generators are not points
   * at infinity. If the verification fails, the session is aborted. Otherwise,
   * the two parties compute the common key material as follows:
   * o  Alice computes Ka = (B - (G4 x [x2*s])) x [x2]
   * @returns The derived shared key.
   * @throws {InvalidStateError} If called in an invalid state, if required data is missing, or if verification fails.
   */
  public deriveSharedKey(): Uint8Array {
    if (this.state !== JPakeState.ROUND2RESULTSRECEIVED) {
      throw new InvalidStateError(
        'Shared key can only be derived after receiving Round 2 results',
      )
    }
    if (
      !this.B ||
      !this.G1 ||
      !this.G2 ||
      !this.G3 ||
      !this.G4 ||
      !this.x2 ||
      !this.x2s ||
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
      this.G4.multiply(bytesToNumberBE(this.x2s)),
    ).multiply(bytesToNumberBE(this.x2))

    // Convert Ka to bytes
    const sharedSecret = Ka.toBytes(true)

    if (!sharedSecret) {
      throw new JPakeError('Failed to derive shared key')
    }

    this.state = JPakeState.KEYDERIVED
    return sha3_256(sharedSecret)
  }
}

export default JPake

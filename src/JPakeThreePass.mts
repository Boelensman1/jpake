import JPake, { Round1Result, Round2Result } from './JPake.mjs'

export type Pass1Result = Round1Result
export interface Pass2Result {
  round1Result: Round1Result
  round2Result: Round2Result
}
export type Pass3Result = Round2Result

/**
 * Implements a three-pass J-PAKE protocol.
 */
class JPakeThreePass {
  private jpake: JPake

  /**
   * Creates a new instance of JPakeThreePass.
   * @param userId - The unique identifier for the current user.
   */
  constructor(readonly userId: string) {
    this.jpake = new JPake(this.userId)
  }

  /**
   * Performs the first pass of the J-PAKE protocol. Ran on the initiator.
   * @returns The result of the first pass.
   */
  public pass1(): Pass1Result {
    const round1Result = this.jpake.round1()
    return round1Result
  }

  /**
   * Performs the second pass of the J-PAKE protocol. Ran on the responder.
   * @param peerRound1Result - The result from the peer's first round.
   * @param s - The shared secret.
   * @param peerUserId - The identifier for the peer user.
   * @returns The result of the second pass.
   */
  public pass2(
    peerRound1Result: Round1Result,
    s: Uint8Array,
    peerUserId: string,
  ): Pass2Result {
    const round1Result = this.jpake.round1()
    const round2Result = this.jpake.round2(peerRound1Result, s, peerUserId)
    return { round1Result, round2Result }
  }

  /**
   * Performs the third pass of the J-PAKE protocol. Ran on the initiator.
   * @param pass2Result - The result from the second pass.
   * @param s - The shared secret.
   * @param peerUserId - The identifier for the peer user.
   * @returns The result of the third pass.
   */
  public pass3(
    pass2Result: Pass2Result,
    s: Uint8Array,
    peerUserId: string,
  ): Pass3Result {
    const round2Result = this.jpake.round2(
      pass2Result.round1Result,
      s,
      peerUserId,
    )
    this.jpake.setRound2ResultFromBob(pass2Result.round2Result)

    return round2Result
  }

  /**
   * Processes the results from the third pass received from the peer.
   * Ran on the responder.
   * @param pass3Result - The result from the peer's third pass.
   */
  public receivePass3Results(pass3Result: Pass3Result) {
    this.jpake.setRound2ResultFromBob(pass3Result)
  }

  /**
   * Derives the shared key after completing the J-PAKE protocol. Ran on both
   * the initiator and the responder.
   * @returns The derived shared key.
   */
  public deriveSharedKey() {
    return this.jpake.deriveSharedKey()
  }
}

export default JPakeThreePass

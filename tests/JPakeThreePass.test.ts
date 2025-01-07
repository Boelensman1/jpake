import { describe, it, expect, beforeEach } from 'vitest'
import { JPakeThreePass, deriveSFromPassword } from '../src/main.mjs'

describe('JPakeThreePass', () => {
  let alice: JPakeThreePass
  let bob: JPakeThreePass
  const password = 'secretPassword123'
  const s = deriveSFromPassword(password)

  beforeEach(() => {
    // Create new JPakeThreePass instances for each test
    alice = new JPakeThreePass('Alice')
    bob = new JPakeThreePass('Bob')
  })

  it('should successfully complete a key exchange', () => {
    // Simulate the J-PAKE protocol exchange
    const alicePass1 = alice.pass1()

    const bobPass2 = bob.pass2(alicePass1, s, alice.userId)
    const alicePass3 = alice.pass3(bobPass2, s, bob.userId)
    bob.receivePass3Results(alicePass3)

    // Derive and compare the shared keys
    const aliceSharedKey = alice.deriveSharedKey()
    const bobSharedKey = bob.deriveSharedKey()

    expect(aliceSharedKey).toEqual(bobSharedKey)
  })

  it('should fail key exchange with incorrect password', () => {
    // Simulate the exchange with a wrong password for Bob
    const alicePass1 = alice.pass1()

    const bobPass2 = bob.pass2(alicePass1, s, alice.userId)
    const alicePass3 = alice.pass3(
      bobPass2,
      deriveSFromPassword('not-the-password'),
      bob.userId,
    )
    bob.receivePass3Results(alicePass3)

    // Derive and compare the shared keys
    const aliceSharedKey = alice.deriveSharedKey()
    const bobSharedKey = bob.deriveSharedKey()

    expect(aliceSharedKey).not.toEqual(bobSharedKey)
  })

  it('should throw error when trying to derive key before completing exchange', () => {
    // Attempt to derive the key without completing the exchange
    expect(() => alice.deriveSharedKey()).toThrowError(
      'Shared key can only be derived after receiving Round 2 results',
    )
  })
})

import { describe, it, expect, beforeEach } from 'vitest'
import { concatBytes } from '@noble/hashes/utils.js'
import {
  JPakeState,
  JPakeThreePass,
  deriveSFromPassword,
} from '../src/main.mjs'
import type { Pass1Result, Pass2Result, Pass3Result } from '../src/main.mjs'
import {
  InvalidArgumentError,
  InvalidStateError,
  JPakeError,
  VerificationError,
} from '../src/JPakeErrors.mjs'

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

  it.each([
    ['Alice', 'Bob'],
    ['Alice🔐', 'Bob\uFFFD'],
  ])('should complete an exchange between %j and %j', (aliceId, bobId) => {
    alice = new JPakeThreePass(aliceId)
    bob = new JPakeThreePass(bobId)
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

  it.each(['peer\uD800', 'peer\uDC00'])(
    'should reject malformed local identity %j at construction',
    (userId) => {
      expect(() => new JPakeThreePass(userId)).toThrowError(
        'userId must contain only well-formed Unicode.',
      )
    },
  )

  it.each(['peer\uD800', 'peer\uDC00'])(
    'should reject a reflected first pass with identity %j',
    (peerId) => {
      const victim = new JPakeThreePass('peer\uFFFD')
      const reflectedPass1 = new JPakeThreePass(victim.userId).pass1()

      expect(() => victim.pass2(reflectedPass1, s, peerId)).toThrowError(
        'userId must contain only well-formed Unicode.',
      )
    },
  )

  it.each(['Bob\uD800', 'Bob\uDC00'])(
    'should reject a second-pass identity alias %j',
    (peerId) => {
      const responder = new JPakeThreePass('Bob\uFFFD')
      const pass2 = responder.pass2(alice.pass1(), s, alice.userId)

      expect(() => alice.pass3(pass2, s, peerId)).toThrowError(
        'userId must contain only well-formed Unicode.',
      )
    },
  )

  it.each(['ZKPx1', 'ZKPx2'] as const)(
    'should reject a substituted %s before returning pass 2',
    (proof) => {
      const alicePass1 = alice.pass1()
      const otherAlicePass1 = new JPakeThreePass(alice.userId).pass1()
      alicePass1[proof] = otherAlicePass1[proof]

      expect(() => bob.pass2(alicePass1, s, alice.userId)).toThrowError(
        'ZKP verification failed',
      )
    },
  )

  it.each(['ZKPx1', 'ZKPx2'] as const)(
    'should reject a substituted %s before returning pass 3',
    (proof) => {
      const alicePass1 = alice.pass1()
      const bobPass2 = bob.pass2(alicePass1, s, alice.userId)
      const otherBobPass2 = new JPakeThreePass(bob.userId).pass2(
        alicePass1,
        s,
        alice.userId,
      )
      bobPass2.round1Result[proof] = otherBobPass2.round1Result[proof]

      expect(() => alice.pass3(bobPass2, s, bob.userId)).toThrowError(
        'ZKP verification failed',
      )
    },
  )

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

  it('should bind an exchange to matching context strings', () => {
    const context = ['app/v1', 'session-42']
    alice = new JPakeThreePass('Alice', context)
    bob = new JPakeThreePass('Bob', context)

    const pass2 = bob.pass2(alice.pass1(), s, alice.userId)
    bob.receivePass3Results(alice.pass3(pass2, s, bob.userId))

    const aliceResult = alice.deriveSharedKey()
    expect(aliceResult).toEqual(bob.deriveSharedKey())
    // The context reaches the transcript, so it reached the proofs too.
    const encoded = concatBytes(
      ...context.map((info) => {
        const bytes = new TextEncoder().encode(info)
        return concatBytes(new Uint8Array([bytes.length]), bytes)
      }),
    )
    expect(aliceResult.transcript.subarray(-encoded.length)).toEqual(encoded)
  })

  it('should reject a peer whose context strings differ', () => {
    alice = new JPakeThreePass('Alice', ['app/v1'])
    bob = new JPakeThreePass('Bob', ['app/v2'])

    expect(() => bob.pass2(alice.pass1(), s, alice.userId)).toThrowError(
      VerificationError,
    )
    expect(bob.getState()).toBe(JPakeState.FAILED)
  })

  it('should reject a malformed context string at construction', () => {
    expect(() => new JPakeThreePass('')).toThrowError(InvalidArgumentError)

    // Unusable context fails before an exchange starts, not partway through it.
    for (const context of ['\uD800', 'a'.repeat(256)]) {
      expect(() => new JPakeThreePass('Alice', [context])).toThrowError(
        InvalidArgumentError,
      )
    }
  })

  it('should report the state through every pass', () => {
    expect(alice.getState()).toBe(JPakeState.INITIAL)
    expect(bob.getState()).toBe(JPakeState.INITIAL)

    const pass1 = alice.pass1()
    expect(alice.getState()).toBe(JPakeState.ROUND1FINISHED)

    const pass2 = bob.pass2(pass1, s, alice.userId)
    expect(bob.getState()).toBe(JPakeState.ROUND2FINISHED)

    const pass3 = alice.pass3(pass2, s, bob.userId)
    expect(alice.getState()).toBe(JPakeState.ROUND2RESULTSRECEIVED)

    bob.receivePass3Results(pass3)
    expect(bob.getState()).toBe(JPakeState.ROUND2RESULTSRECEIVED)

    alice.deriveSharedKey()
    bob.deriveSharedKey()
    expect(alice.getState()).toBe(JPakeState.KEYDERIVED)
    expect(bob.getState()).toBe(JPakeState.KEYDERIVED)
  })

  it('should report the terminal failed state after an aborted pass', () => {
    const pass1 = alice.pass1()
    const pass2 = bob.pass2(pass1, s, alice.userId)
    pass2.round1Result.ZKPx1.fill(0xff, 35)

    expect(() => alice.pass3(pass2, s, bob.userId)).toThrowError(JPakeError)
    expect(alice.getState()).toBe(JPakeState.FAILED)
    // An out-of-order call reports the failure without changing the state.
    expect(() => alice.pass1()).toThrowError(InvalidStateError)
    expect(alice.getState()).toBe(JPakeState.FAILED)
  })

  it('should throw error when trying to derive key before completing exchange', () => {
    // Attempt to derive the key without completing the exchange
    expect(() => alice.deriveSharedKey()).toThrowError(
      'Shared key can only be derived after receiving Round 2 results',
    )
  })

  it.each(['initiator', 'responder'] as const)(
    'should abort the %s after a malformed round-two proof',
    (role) => {
      const pass1 = alice.pass1()
      const pass2 = bob.pass2(pass1, s, alice.userId)
      let receiver: JPakeThreePass
      let incoming: Pass3Result
      let original: Uint8Array
      if (role === 'initiator') {
        receiver = alice
        incoming = pass2.round2Result
        original = incoming.ZKPx2s.slice()
        incoming.ZKPx2s.fill(0xff, 35)
        alice.pass3(pass2, s, bob.userId)
      } else {
        receiver = bob
        incoming = alice.pass3(pass2, s, bob.userId)
        original = incoming.ZKPx2s.slice()
        incoming.ZKPx2s.fill(0xff, 35)
        bob.receivePass3Results(incoming)
      }
      expect(() => receiver.deriveSharedKey()).toThrowError(JPakeError)
      incoming.ZKPx2s.set(original)
      expect(() => receiver.deriveSharedKey()).toThrowError(InvalidStateError)
      expect(() => receiver.pass1()).toThrowError(InvalidStateError)
      expect(() => receiver.pass2(pass1, s, 'Peer')).toThrowError(
        InvalidStateError,
      )
      expect(() => receiver.pass3(pass2, s, 'Peer')).toThrowError(
        InvalidStateError,
      )
      expect(() => receiver.receivePass3Results(incoming)).toThrowError(
        InvalidStateError,
      )
    },
  )

  it('should isolate submitted proofs from later caller mutations on both peers', () => {
    const pass1 = alice.pass1()
    const pass2 = bob.pass2(pass1, s, alice.userId)
    const pass3 = alice.pass3(pass2, s, bob.userId)
    bob.receivePass3Results(pass3)
    pass2.round2Result.ZKPx2s.fill(0xff)
    pass3.ZKPx2s.fill(0xff)
    expect(alice.deriveSharedKey()).toEqual(bob.deriveSharedKey())
  })

  it('should abort on missing pass containers with protocol errors', () => {
    expect(() =>
      bob.pass2(null as unknown as Pass1Result, s, alice.userId),
    ).toThrowError(JPakeError)
    expect(() => bob.pass1()).toThrowError(InvalidStateError)
    alice.pass1()
    expect(() =>
      alice.pass3(null as unknown as Pass2Result, s, bob.userId),
    ).toThrowError(JPakeError)
    expect(() => alice.pass1()).toThrowError(InvalidStateError)
  })
})

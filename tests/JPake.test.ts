import { describe, it, expect, beforeEach } from 'vitest'
import {
  JPake,
  JPakeState,
  deriveSFromPassword,
  Round1Result,
  Round2Result,
} from '../src/main.mjs'
import { n } from '../src/constants.mjs'
import { numberToBytesBE } from '@noble/curves/utils.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'

describe('JPake', () => {
  let alice: JPake
  let bob: JPake
  const password = 'secretPassword123'
  const s = deriveSFromPassword(password)

  beforeEach(() => {
    // Create new JPake instances for each test
    alice = new JPake('Alice')
    bob = new JPake('Bob')
  })

  it.each([
    ['Alice', 'Bob'],
    ['Alice🔐', 'Bob\uFFFD'],
    ['\uFEFFpeer', 'peer'],
    ['é', 'e\u0301'],
    ['🔐'.repeat(63) + 'abc', 'Bob'],
  ])('should complete an exchange between %j and %j', (aliceId, bobId) => {
    alice = new JPake(aliceId)
    bob = new JPake(bobId)
    // Simulate the J-PAKE protocol exchange
    const aliceRound1 = alice.round1()
    const bobRound1 = bob.round1()

    const aliceRound2 = alice.round2(bobRound1, s, bob.userId)
    const bobRound2 = bob.round2(aliceRound1, s, alice.userId)

    alice.setRound2ResultFromBob(bobRound2)
    bob.setRound2ResultFromBob(aliceRound2)

    // Derive and compare the shared keys
    const aliceSharedKey = alice.deriveSharedKey()
    const bobSharedKey = bob.deriveSharedKey()

    expect(aliceSharedKey).toEqual(bobSharedKey)
  })

  it('should fail key exchange with incorrect password', () => {
    // Simulate the exchange with a wrong password for Bob
    const aliceRound1 = alice.round1()
    const bobRound1 = bob.round1()

    const aliceRound2 = alice.round2(bobRound1, s, bob.userId)
    const bobRound2 = bob.round2(
      aliceRound1,
      deriveSFromPassword('wrongPassword'),
      alice.userId,
    )

    alice.setRound2ResultFromBob(bobRound2)
    bob.setRound2ResultFromBob(aliceRound2)

    const aliceSharedKey = alice.deriveSharedKey()
    const bobSharedKey = bob.deriveSharedKey()

    // Expect the derived keys to be different
    expect(aliceSharedKey).not.toEqual(bobSharedKey)
  })

  it('should throw error when trying to derive key before completing exchange', () => {
    // Attempt to derive the key without completing the exchange
    expect(() => alice.deriveSharedKey()).toThrowError(
      'Shared key can only be derived after receiving Round 2 results',
    )
  })

  it("should throw error when trying to share a key with equal userId's", () => {
    // Attempt to perform the exchange between two instances with the same userId
    const alsoAlice = new JPake('Alice')
    alice.round1()
    const alsoAliceRound1 = alsoAlice.round1()

    expect(() =>
      alice.round2(alsoAliceRound1, s, alsoAlice.userId),
    ).toThrowError('Proof verification failed, userIds are equal.')
  })

  it.each(['peer\uD800', 'peer\uDC00'])(
    'should reject a reflected round-one message with identity %j',
    (peerId) => {
      const victim = new JPake('peer\uFFFD')
      const reflectedRound1 = victim.round1()

      expect(() => victim.round2(reflectedRound1, s, peerId)).toThrowError(
        'userId must contain only well-formed Unicode.',
      )
      expect(victim.getState()).toBe(JPakeState.FAILED)
    },
  )

  it.each(['\uD800', '\uDC00', 'peer\uD800x', '\uDC00\uD800'])(
    'should reject malformed local identity %j at construction',
    (userId) => {
      expect(() => new JPake(userId)).toThrowError(
        'userId must contain only well-formed Unicode.',
      )
    },
  )

  it.each(['a'.repeat(256), '🔐'.repeat(64)])(
    'should reject a local identity longer than 255 UTF-8 bytes',
    (userId) => {
      expect(() => new JPake(userId)).toThrowError(
        'userId is too long. It must be 255 bytes or less when UTF-8 encoded.',
      )
    },
  )

  it('should reject a non-string local identity instead of coercing it', () => {
    expect(() => new JPake(123 as unknown as string)).toThrowError(
      'userId must be a string.',
    )
  })

  it('should reject a reflected identity supplied as a non-string', () => {
    const victim = new JPake('123')
    const reflectedRound1 = victim.round1()

    expect(() =>
      victim.round2(reflectedRound1, s, 123 as unknown as string),
    ).toThrowError('userId must be a string.')
  })

  it('should generate different shared keys for different sessions', () => {
    // Create two separate J-PAKE sessions
    const session1 = { alice: new JPake('Alice'), bob: new JPake('Bob') }
    const session2 = { alice: new JPake('Alice'), bob: new JPake('Bob') }

    // Complete exchange for session 1
    const session1AliceRound1 = session1.alice.round1()
    const session1BobRound1 = session1.bob.round1()
    const session1AliceRound2 = session1.alice.round2(
      session1BobRound1,
      s,
      session1.bob.userId,
    )
    const session1BobRound2 = session1.bob.round2(
      session1AliceRound1,
      s,
      session1.alice.userId,
    )

    // Complete exchange for session 2
    const session2AliceRound1 = session2.alice.round1()
    const session2BobRound1 = session2.bob.round1()
    const session2AliceRound2 = session2.alice.round2(
      session2BobRound1,
      s,
      session2.bob.userId,
    )
    const session2BobRound2 = session2.bob.round2(
      session2AliceRound1,
      s,
      session2.alice.userId,
    )

    session1.alice.setRound2ResultFromBob(session1BobRound2)
    session1.bob.setRound2ResultFromBob(session1AliceRound2)

    session2.alice.setRound2ResultFromBob(session2BobRound2)
    session2.bob.setRound2ResultFromBob(session2AliceRound2)

    // Derive keys for both sessions
    const key1 = session1.alice.deriveSharedKey()
    const key2 = session2.alice.deriveSharedKey()

    // Expect the keys from different sessions to be different
    expect(key1).not.toEqual(key2)
  })

  it('should detect MITM attack in round 1', () => {
    const eve = new JPake('Eve')
    alice.round1()
    const eveRound1 = eve.round1()

    // Eve tries to intercept and replace Bob's round 1 data
    expect(() => alice.round2(eveRound1, s, bob.userId)).toThrowError(
      'ZKP verification failed',
    )
  })

  it.each(['ZKPx1', 'ZKPx2'] as const)(
    'should reject a substituted %s before returning round 2',
    (proof) => {
      alice.round1()
      const bobRound1 = bob.round1()
      const otherBobRound1 = new JPake(bob.userId).round1()
      bobRound1[proof] = otherBobRound1[proof]

      expect(() => alice.round2(bobRound1, s, bob.userId)).toThrowError(
        'ZKP verification failed',
      )
      expect(alice.getState()).toBe(JPakeState.FAILED)
    },
  )

  it.each([0, 66])(
    'should reject a second round-one proof with length %i',
    (length) => {
      alice.round1()
      const bobRound1 = bob.round1()
      bobRound1.ZKPx2 = bobRound1.ZKPx2.slice(0, length)

      expect(() => alice.round2(bobRound1, s, bob.userId)).toThrowError(
        'Invalid proof, must be 33 + 32 + 2 bytes long',
      )
      expect(alice.getState()).toBe(JPakeState.FAILED)
    },
  )

  it('should reject a substituted second point with its original proof', () => {
    alice.round1()
    const bobRound1 = bob.round1()
    bobRound1.G2 = secp256k1.Point.fromBytes(bobRound1.G2).negate().toBytes()

    expect(() => alice.round2(bobRound1, s, bob.userId)).toThrowError(
      'ZKP verification failed',
    )
    expect(alice.getState()).toBe(JPakeState.FAILED)
  })

  it('should detect MITM attack in round 2', () => {
    const eve = new JPake('Eve')
    const aliceRound1 = alice.round1()
    const bobRound1 = bob.round1()
    eve.round1()

    alice.round2(bobRound1, s, bob.userId)
    const eveRound2 = eve.round2(
      aliceRound1,
      deriveSFromPassword('evePassword'),
      alice.userId,
    )

    // Eve tries to intercept and replace Bob's round 2 data
    alice.setRound2ResultFromBob(eveRound2)

    // Attempt to derive the key after the MITM attack:
    expect(() => alice.deriveSharedKey()).toThrowError(
      'ZKP verification failed',
    )
  })

  it('should throw error when trying to create JPake instance with empty userId', () => {
    expect(() => new JPake('')).toThrowError('UserId cannot be empty')
  })

  it('should throw error when trying to perform round2 with empty userId', () => {
    alice.round1()
    const bobRound1 = bob.round1()

    expect(() => alice.round2(bobRound1, s, '')).toThrowError(
      'Missing required arguments for round 2',
    )
  })

  it('should successfully complete a key exchange with otherInfo', () => {
    const timestamp = Date.now().toString()
    const otherInfo = [timestamp]
    const aliceWOtherInfo = new JPake('AliceWithOtherInfo', otherInfo)
    const bobWOtherInfo = new JPake('BobWithOtherInfo', otherInfo)

    // Simulate the J-PAKE protocol exchange
    const aliceRound1 = aliceWOtherInfo.round1()
    const bobRound1 = bobWOtherInfo.round1()

    const aliceRound2 = aliceWOtherInfo.round2(
      bobRound1,
      s,
      bobWOtherInfo.userId,
    )
    const bobRound2 = bobWOtherInfo.round2(
      aliceRound1,
      s,
      aliceWOtherInfo.userId,
    )

    aliceWOtherInfo.setRound2ResultFromBob(bobRound2)
    bobWOtherInfo.setRound2ResultFromBob(aliceRound2)

    // Derive and compare the shared keys
    const aliceSharedKey = aliceWOtherInfo.deriveSharedKey()
    const bobSharedKey = bobWOtherInfo.deriveSharedKey()

    expect(aliceSharedKey).toEqual(bobSharedKey)
  })

  it('should fail key exchange when otherInfo does not match', () => {
    const aliceTimestamp = Date.now().toString()
    const bobTimestamp = (Date.now() + 1).toString() // Different timestamp
    const aliceWOtherInfo = new JPake('AliceWithOtherInfo', [aliceTimestamp])
    const bobWOtherInfo = new JPake('BobWithOtherInfo', [bobTimestamp])

    // Simulate the J-PAKE protocol exchange
    const aliceRound1 = aliceWOtherInfo.round1()
    bobWOtherInfo.round1()

    // Expect an error when Bob tries to process Alice's round1 result with a different timestamp
    expect(() =>
      bobWOtherInfo.round2(aliceRound1, s, aliceWOtherInfo.userId),
    ).toThrowError('ZKP verification failed')
  })

  it('should successfully complete a key exchange when s > n', () => {
    const largeS = numberToBytesBE(2n * n + 1n, 64) // s is larger than n
    const aliceWithLargeS = new JPake('AliceWithLargeS')
    const bobWithLargeS = new JPake('BobWithLargeS')

    // Simulate the J-PAKE protocol exchange
    const aliceRound1 = aliceWithLargeS.round1()
    const bobRound1 = bobWithLargeS.round1()

    const aliceRound2 = aliceWithLargeS.round2(
      bobRound1,
      largeS,
      bobWithLargeS.userId,
    )
    const bobRound2 = bobWithLargeS.round2(
      aliceRound1,
      largeS,
      aliceWithLargeS.userId,
    )

    aliceWithLargeS.setRound2ResultFromBob(bobRound2)
    bobWithLargeS.setRound2ResultFromBob(aliceRound2)

    // Derive and compare the shared keys
    const aliceSharedKey = aliceWithLargeS.deriveSharedKey()
    const bobSharedKey = bobWithLargeS.deriveSharedKey()

    expect(aliceSharedKey).toEqual(bobSharedKey)
  })

  it.each([0n, 2n * n])(
    'should abort when s = %s is zero modulo n',
    (scalar) => {
      alice.round1()
      const bobRound1 = bob.round1()

      expect(() =>
        alice.round2(bobRound1, numberToBytesBE(scalar, 64), bob.userId),
      ).toThrowError('Invalid s: s MUST not be equal to 0 mod n')
      expect(alice.getState()).toBe(JPakeState.FAILED)
    },
  )

  it('should throw an error when receiving invalid points', () => {
    const alice = new JPake('Alice')
    alice.round1()

    const invalidRound1Result = {
      G1: new Uint8Array(32), // Invalid G1
      G2: new Uint8Array(32), // Invalid G2
      ZKPx1: new Uint8Array(32),
      ZKPx2: new Uint8Array(32),
    }

    expect(() =>
      alice.round2(
        invalidRound1Result,
        numberToBytesBE(BigInt(123), 32),
        'Bob',
      ),
    ).toThrowError('Invalid points received: G1 or G2 is not a valid Point')
  })

  it('should throw errors when functions are called in the wrong state', () => {
    const alice = new JPake('Alice')
    const bob = new JPake('Bob')
    const s = deriveSFromPassword('password')

    // Attempt to run round2 before round1
    expect(() => alice.round2({} as Round1Result, s, 'Bob')).toThrowError(
      'Round 2 can only be executed after Round 1',
    )

    // Attempt to set round2 result before completing round2
    expect(() => alice.setRound2ResultFromBob({} as Round2Result)).toThrowError(
      'Round 2 results can only be set after Round 2 is finished',
    )

    // Attempt to derive shared key before completing the exchange
    expect(() => alice.deriveSharedKey()).toThrowError(
      'Shared key can only be derived after receiving Round 2 results',
    )

    // Complete round1
    const aliceRound1 = alice.round1()
    const bobRound1 = bob.round1()

    // Attempt to run round1 again
    expect(() => alice.round1()).toThrowError(
      'Round 1 can only be executed in INITIAL state',
    )

    // Complete round2
    alice.round2(bobRound1, s, bob.userId)
    const bobRound2 = bob.round2(aliceRound1, s, alice.userId)

    // Attempt to run round2 again
    expect(() => alice.round2(bobRound1, s, bob.userId)).toThrowError(
      'Round 2 can only be executed after Round 1',
    )

    // Set round2 result
    alice.setRound2ResultFromBob(bobRound2)

    // Attempt to set round2 result again
    expect(() => alice.setRound2ResultFromBob(bobRound2)).toThrowError(
      'Round 2 results can only be set after Round 2 is finished',
    )

    // Derive shared key
    alice.deriveSharedKey()

    // Attempt to derive shared key again
    expect(() => alice.deriveSharedKey()).toThrowError(
      'Shared key can only be derived after receiving Round 2 results',
    )
  })

  it('should abort when round-two data is missing', () => {
    alice.round1()
    const bobRound1 = bob.round1()
    alice.round2(bobRound1, s, bob.userId)

    expect(() => alice.setRound2ResultFromBob({} as Round2Result)).toThrowError(
      'Missing required arguments for setRound2ResultFromBob',
    )

    expect(alice.getState()).toBe(JPakeState.FAILED)
  })
})

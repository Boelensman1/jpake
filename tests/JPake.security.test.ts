import { afterEach, describe, expect, it, vi } from 'vitest'
import { inspect } from 'node:util'
import { Buffer as NodeBuffer } from 'node:buffer'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js'
import { mod } from '@noble/curves/abstract/modular.js'
import { JPake, JPakeState, deriveSFromPassword } from '../src/main.mjs'
import type { Round1Result, Round2Result } from '../src/main.mjs'
import {
  InvalidStateError,
  JPakeError,
  VerificationError,
} from '../src/JPakeErrors.mjs'
import { n } from '../src/constants.mjs'

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
  vi.mocked(secp256k1.utils.randomSecretKey).mockReset()
  vi.restoreAllMocks()
})

const s = deriveSFromPassword('security-regression-password')

const prepareExchange = () => {
  const alice = new JPake('Alice')
  const bob = new JPake('Bob')
  const a1 = alice.round1()
  const b1 = bob.round1()
  const a2 = alice.round2(b1, s, 'Bob')
  const b2 = bob.round2(a1, s, 'Alice')
  bob.setRound2ResultFromBob(a2)
  return { alice, bob, b1, b2 }
}

const expectFailed = (alice: JPake) => {
  expect(alice.getState()).toBe(JPakeState.FAILED)
  expect(() => alice.round1()).toThrowError(InvalidStateError)
  expect(() => alice.round2({} as Round1Result, s, 'Bob')).toThrowError(
    InvalidStateError,
  )
  expect(() => alice.setRound2ResultFromBob({} as Round2Result)).toThrowError(
    InvalidStateError,
  )
  expect(() => alice.deriveSharedKey()).toThrowError(InvalidStateError)
  expect(alice.getState()).toBe(JPakeState.FAILED)
}

describe('J-PAKE security boundaries', () => {
  it.each([0n, n, (1n << 256n) - 1n])(
    'should abort on an invalid round-one response %s',
    (r) => {
      const alice = new JPake('Alice')
      alice.round1()
      const b1 = new JPake('Bob').round1()
      const original = b1.ZKPx2.slice()
      b1.ZKPx2.set(numberToBytesBE(r, 32), 35)
      expect(() => alice.round2(b1, s, 'Bob')).toThrowError(JPakeError)
      b1.ZKPx2.set(original)
      expectFailed(alice)
    },
  )

  it.each([0n, n, (1n << 256n) - 1n])(
    'should abort on an invalid round-two response %s',
    (r) => {
      const { alice, b2 } = prepareExchange()
      const original = b2.ZKPx2s.slice()
      b2.ZKPx2s.set(numberToBytesBE(r, 32), 35)
      alice.setRound2ResultFromBob(b2)
      expect(() => alice.deriveSharedKey()).toThrowError(JPakeError)
      b2.ZKPx2s.set(original)
      expectFailed(alice)
    },
  )

  it.each([new Uint8Array([0]), new Uint8Array(33), new Uint8Array(65)])(
    'should abort on an invalid round-two point with a protocol error',
    (point) => {
      const { alice, b2 } = prepareExchange()
      expect(() =>
        alice.setRound2ResultFromBob({ ...b2, A: point }),
      ).toThrowError(JPakeError)
      expectFailed(alice)
    },
  )

  it('should abort on missing message containers with protocol errors', () => {
    const alice = new JPake('Alice')
    alice.round1()
    expect(() =>
      alice.round2(null as unknown as Round1Result, s, 'Bob'),
    ).toThrowError(JPakeError)
    expectFailed(alice)

    const { alice: otherAlice } = prepareExchange()
    expect(() =>
      otherAlice.setRound2ResultFromBob(null as unknown as Round2Result),
    ).toThrowError(JPakeError)
    expectFailed(otherAlice)
  })

  it.each(
    [{}, 'not a proof', new Array<number>(67).fill(0)].map(
      (proof: unknown) => ({ proof }),
    ),
  )(
    'should abort when a round-two proof is not a byte array: $proof',
    ({ proof }) => {
      const { alice, b2 } = prepareExchange()
      expect(() =>
        alice.setRound2ResultFromBob({ ...b2, ZKPx2s: proof as Uint8Array }),
      ).toThrowError(VerificationError)
      expectFailed(alice)
    },
  )

  it.each([0, 66, 68])(
    'should abort on a round-two proof of length %i',
    (length) => {
      const { alice, b2 } = prepareExchange()
      expect(() =>
        alice.setRound2ResultFromBob({ ...b2, ZKPx2s: new Uint8Array(length) }),
      ).toThrowError('Invalid proof, must be 33 + 32 + 2 bytes long')
      expectFailed(alice)
    },
  )

  it.each([0, 34])(
    'should abort on an invalid proof component length at byte %i',
    (offset) => {
      const { alice, b2 } = prepareExchange()
      b2.ZKPx2s[offset] = 0
      expect(() => alice.setRound2ResultFromBob(b2)).toThrowError(
        'Invalid proof, V must be 33 bytes and r must be 32 bytes',
      )
      expectFailed(alice)
    },
  )

  it('should preserve the cause of an unexpected error while aborting and clearing secrets', () => {
    const alice = new JPake('Alice')
    const x1 = numberToBytesBE(3n, 32)
    const x2 = numberToBytesBE(7n, 32)
    const cause = new RangeError('Injected noble failure')
    vi.spyOn(secp256k1.utils, 'randomSecretKey')
      .mockReturnValueOnce(x1)
      .mockReturnValueOnce(x2)
      .mockImplementationOnce(() => {
        throw cause
      })
    let caught: unknown
    try {
      alice.round1()
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(JPakeError)
    expect(caught).not.toBeInstanceOf(VerificationError)
    expect((caught as JPakeError).message).toBe('J-PAKE operation failed')
    expect((caught as JPakeError).cause).toBe(cause)
    expect(x1).toEqual(new Uint8Array(32))
    expect(x2).toEqual(new Uint8Array(32))
    expectFailed(alice)
  })

  it.each([
    ['Uint8Array', (bytes: Uint8Array) => new Uint8Array(bytes)],
    ['Buffer', (bytes: Uint8Array) => NodeBuffer.from(bytes)],
  ] as const)('should copy an incoming proof supplied as a %s', (_, copy) => {
    const { alice, bob, b2 } = prepareExchange()
    b2.ZKPx2s = copy(b2.ZKPx2s)
    alice.setRound2ResultFromBob(b2)
    b2.ZKPx2s.fill(0xff)
    b2.A.fill(0)
    expect(alice.deriveSharedKey()).toEqual(bob.deriveSharedKey())
  })

  it('should not repair an invalid stored proof by changing the caller buffer', () => {
    const { alice, b2 } = prepareExchange()
    const original = b2.ZKPx2s.slice()
    b2.ZKPx2s.fill(0xff, 35)
    alice.setRound2ResultFromBob(b2)
    b2.ZKPx2s.set(original)
    expect(() => alice.deriveSharedKey()).toThrowError(JPakeError)
    expectFailed(alice)
  })

  it.each(['success', 'round1', 'round2', 'receive', 'derive'] as const)(
    'should hide secret fields and wipe retained secret buffers on %s',
    (outcome) => {
      // Keep test-only references to the entropy provider's buffers so erasure
      // can be verified without exposing any private state in the API.
      const x1 = numberToBytesBE(3n, 32)
      const x2 = numberToBytesBE(7n, 32)
      const expectedX2s = numberToBytesBE(mod(7n * bytesToNumberBE(s), n), 32)
      const expectedS = s.slice()
      vi.mocked(secp256k1.utils.randomSecretKey)
        .mockReturnValueOnce(x1)
        .mockReturnValueOnce(x2)

      const wipedX2s: Uint8Array[] = []
      // eslint-disable-next-line @typescript-eslint/unbound-method -- Called with the original receiver below.
      const fill = Uint8Array.prototype.fill
      vi.spyOn(Uint8Array.prototype, 'fill').mockImplementation(function (
        this: Uint8Array,
        value: number,
        start?: number,
        end?: number,
      ) {
        if (
          value === 0 &&
          this.length === 32 &&
          this.every((v, i) => v === expectedX2s[i])
        ) {
          wipedX2s.push(this)
        }
        return fill.call(this, value, start, end)
      })

      // Invalid context causes round-one generation to fail after secrets exist.
      const alice = new JPake(
        'Alice',
        outcome === 'round1' ? ['\uD800'] : undefined,
      )
      if (outcome === 'round1') {
        expect(() => alice.round1()).toThrowError(JPakeError)
        expectFailed(alice)
      } else {
        const a1 = alice.round1()
        expect(x1).toEqual(new Uint8Array(32))
        expect(x2).toEqual(numberToBytesBE(7n, 32))
        const bob = new JPake('Bob')
        const b1 = bob.round1()
        if (outcome === 'round2') {
          b1.ZKPx1.fill(0xff, 35)
          expect(() => alice.round2(b1, s, 'Bob')).toThrowError(JPakeError)
          expectFailed(alice)
        } else {
          const a2 = alice.round2(b1, s, 'Bob')
          const b2 = bob.round2(a1, s, 'Alice')
          for (const field of ['x1', 'x2', 'x2s', '#x1', '#x2', '#x2s']) {
            expect(Reflect.ownKeys(alice)).not.toContain(field)
            expect(inspect(alice, { showHidden: true })).not.toContain(
              `${field}:`,
            )
          }
          if (outcome === 'receive') {
            expect(() =>
              alice.setRound2ResultFromBob({ ...b2, A: new Uint8Array([0]) }),
            ).toThrowError(JPakeError)
            expectFailed(alice)
          } else {
            if (outcome === 'derive') b2.ZKPx2s.fill(0xff, 35)
            alice.setRound2ResultFromBob(b2)
            if (outcome === 'derive') {
              expect(() => alice.deriveSharedKey()).toThrowError(JPakeError)
              expectFailed(alice)
            } else {
              bob.setRound2ResultFromBob(a2)
              expect(alice.deriveSharedKey()).toEqual(bob.deriveSharedKey())
              expect(alice.getState()).toBe(JPakeState.KEYDERIVED)
            }
          }
          expect(wipedX2s).toEqual([new Uint8Array(32)])
        }
      }
      expect(x1).toEqual(new Uint8Array(32))
      expect(x2).toEqual(new Uint8Array(32))
      expect(s).toEqual(expectedS)
    },
  )
})

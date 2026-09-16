import { afterEach, expect, it, vi } from 'vitest'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { numberToBytesBE } from '@noble/curves/utils.js'
import { n } from '../src/constants.mjs'
import deriveSFromPassword from '../src/deriveSFromPassword.mjs'

vi.mock('@noble/hashes/sha3.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/hashes/sha3.js')>()
  return { ...actual, sha3_256: vi.fn(actual.sha3_256) }
})

afterEach(() => vi.mocked(sha3_256).mockReset())

const decoder = new TextDecoder()

it.each([false, true])(
  'should wipe password hash buffers without changing the returned scalar (retry: %s)',
  (retry) => {
    const zeroModuloNHash = numberToBytesBE(n, 32)
    const finalHash = numberToBytesBE(7n, 32)
    const hash = vi.mocked(sha3_256)
    if (retry) hash.mockReturnValueOnce(zeroModuloNHash)
    hash.mockReturnValueOnce(finalHash)

    const s = deriveSFromPassword('password')
    expect(s).toEqual(numberToBytesBE(7n, 32))
    expect(s).not.toBe(finalHash)
    expect(finalHash).toEqual(new Uint8Array(32))
    if (retry) expect(zeroModuloNHash).toEqual(new Uint8Array(32))
    expect(hash).toHaveBeenCalledTimes(retry ? 2 : 1)
    for (const [passwordBytes] of hash.mock.calls) {
      expect(passwordBytes).toEqual(new Uint8Array(passwordBytes.length))
    }
  },
)

// Forcing the otherwise astronomically unlikely s = 0 is the only way to reach
// the retry loop at all. Repeating one candidate would never escape it.
it('should hash a distinct candidate per retry', () => {
  const candidates: string[] = []
  vi.mocked(sha3_256).mockImplementation((message) => {
    // Copy now: the encoded buffer is wiped before this call returns.
    candidates.push(decoder.decode(message))
    // 0 and n are both zero modulo n, so the first two attempts must retry.
    return numberToBytesBE([0n, n][candidates.length - 1] ?? 5n, 32)
  })

  expect(deriveSFromPassword('pw')).toEqual(numberToBytesBE(5n, 32))
  expect(candidates).toEqual(['pw', 'pwretried1', 'pwretried2'])
})

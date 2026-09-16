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

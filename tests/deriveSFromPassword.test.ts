import { describe, it, expect } from 'vitest'
import { deriveSFromPassword } from '../src/main.mjs'
import { n } from '../src/constants.mjs'
import { bytesToNumberBE, hexToBytes } from '@noble/curves/utils.js'
import { InvalidArgumentError } from '../src/JPakeErrors.mjs'

describe('deriveSFromPassword', () => {
  it('should derive a valid s value from a password', () => {
    const password = 'testPassword123'
    const s = deriveSFromPassword(password)

    expect(s).toBeDefined()
    expect(s instanceof Uint8Array).toBe(true)
    expect(s.length).toBe(32)
    const sBigInt = bytesToNumberBE(s)
    expect(sBigInt).toBeGreaterThan(0n)
    expect(sBigInt).toBeLessThan(n)
  })

  it('should derive different s values for different passwords', () => {
    const password1 = 'password1'
    const password2 = 'password2'

    const s1 = deriveSFromPassword(password1)
    const s2 = deriveSFromPassword(password2)

    expect(s1).not.toEqual(s2)
  })

  it('should derive the same s value for the same password', () => {
    const password = 'consistentPassword'

    const s1 = deriveSFromPassword(password)
    const s2 = deriveSFromPassword(password)

    expect(s1).toEqual(s2)
  })

  it('should throw an error for an empty password', () => {
    expect(() => deriveSFromPassword('')).toThrow('Missing password')
  })

  it.each(['secret\uD800', 'secret\uDC00', '\uDC00\uD800', '\uD800x'])(
    'should reject malformed Unicode password %j',
    (password) => {
      expect(() => deriveSFromPassword(password)).toThrowError(
        'password must contain only well-formed Unicode.',
      )
    },
  )

  it.each(
    [123, {}, [], null, undefined, false].map((password: unknown) => ({
      password,
    })),
  )('should reject non-string password %j without coercion', ({ password }) => {
    expect(() => deriveSFromPassword(password as string)).toThrowError(
      InvalidArgumentError,
    )
  })

  it('should preserve valid password derivation', () => {
    expect(deriveSFromPassword('password')).toEqual(
      hexToBytes(
        'c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484',
      ),
    )
    expect(deriveSFromPassword('é')).not.toEqual(deriveSFromPassword('e\u0301'))
    expect(deriveSFromPassword('secret\uFFFD')).toHaveLength(32)
  })

  it('should handle special characters in passwords', () => {
    const password = '!@#$%^&*()_+'
    const s = deriveSFromPassword(password)

    expect(s).toBeDefined()
    expect(s instanceof Uint8Array).toBe(true)
    expect(s.length).toBe(32)
    const sBigInt = bytesToNumberBE(s)
    expect(sBigInt).toBeGreaterThan(0n)
    expect(sBigInt).toBeLessThan(n)
  })

  it.each(['a'.repeat(1000), '🔐'.repeat(100)])(
    'should handle long passwords',
    (password) => {
      const s = deriveSFromPassword(password)

      expect(s).toBeDefined()
      expect(s instanceof Uint8Array).toBe(true)
      expect(s.length).toBe(32)
      const sBigInt = bytesToNumberBE(s)
      expect(sBigInt).toBeGreaterThan(0n)
      expect(sBigInt).toBeLessThan(n)
    },
  )
})

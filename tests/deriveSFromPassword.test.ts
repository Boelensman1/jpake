import { describe, it, expect } from 'vitest'
import { deriveSFromPassword } from '../src/main.mjs'
import { n } from '../src/constants.mjs'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'

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

  it('should handle long passwords', () => {
    const password = 'a'.repeat(1000)
    const s = deriveSFromPassword(password)

    expect(s).toBeDefined()
    expect(s instanceof Uint8Array).toBe(true)
    expect(s.length).toBe(32)
    const sBigInt = bytesToNumberBE(s)
    expect(sBigInt).toBeGreaterThan(0n)
    expect(sBigInt).toBeLessThan(n)
  })
})

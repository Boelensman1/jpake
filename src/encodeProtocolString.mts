import { InvalidArgumentError } from './JPakeErrors.mjs'

/**
 * Encodes a protocol field without silently replacing lone UTF-16 surrogates.
 * @param value - The string to encode.
 * @param field - The field name used in validation errors.
 * @returns The UTF-8 bytes, suitable for a one-byte length prefix.
 * @throws {InvalidArgumentError} If the value is not a well-formed string or exceeds 255 bytes.
 */
const encodeProtocolString = (value: string, field: string): Uint8Array => {
  if (typeof value !== 'string') {
    throw new InvalidArgumentError(`${field} must be a string.`)
  }

  // In Unicode mode, valid surrogate pairs match as a single code point
  // outside this range, so only unpaired surrogates are rejected.
  if (/[\uD800-\uDFFF]/u.test(value)) {
    throw new InvalidArgumentError(
      `${field} must contain only well-formed Unicode.`,
    )
  }

  const bytes = new TextEncoder().encode(value)
  if (bytes.length > 255) {
    throw new InvalidArgumentError(
      `${field} is too long. It must be 255 bytes or less when UTF-8 encoded.`,
    )
  }

  return bytes
}

export default encodeProtocolString

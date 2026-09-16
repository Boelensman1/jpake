import { InvalidArgumentError } from './JPakeErrors.mjs'

/**
 * Encodes a Unicode string without silently replacing lone UTF-16 surrogates.
 * @param value - The string to encode.
 * @param field - The field name used in validation errors.
 * @returns The UTF-8 bytes, with no length limit.
 * @throws {InvalidArgumentError} If the value is not a well-formed string.
 */
export const encodeUnicodeString = (
  value: string,
  field: string,
): Uint8Array => {
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

  return new TextEncoder().encode(value)
}

/**
 * Encodes a protocol field that must fit a one-byte length prefix.
 * @param value - The string to encode.
 * @param field - The field name used in validation errors.
 * @returns The UTF-8 bytes, at most 255 bytes long.
 * @throws {InvalidArgumentError} If the value is not a well-formed string or exceeds 255 bytes.
 */
export const encodeProtocolField = (
  value: string,
  field: string,
): Uint8Array => {
  const bytes = encodeUnicodeString(value, field)
  if (bytes.length > 255) {
    throw new InvalidArgumentError(
      `${field} is too long. It must be 255 bytes or less when UTF-8 encoded.`,
    )
  }

  return bytes
}

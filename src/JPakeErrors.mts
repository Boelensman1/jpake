/* eslint-disable no-restricted-globals */
/**
 * Base error class for J-PAKE related errors.
 */
export class JPakeError extends Error {
  /**
   * Creates a new JPakeError.
   * @param message - The error message.
   */
  constructor(message: string) {
    super(message)
    this.name = 'JPakeError'
  }
}

/**
 * Error thrown when an operation is attempted in an invalid state.
 */
export class InvalidStateError extends JPakeError {
  /**
   * @inheritdoc
   */
  constructor(message: string) {
    super(message)
    this.name = 'InvalidStateError'
  }
}

/**
 * Error thrown when an invalid argument is provided to a function.
 */
export class InvalidArgumentError extends JPakeError {
  /**
   * @inheritdoc
   */
  constructor(message: string) {
    super(message)
    this.name = 'InvalidArgumentError'
  }
}

/**
 * Error thrown when a verification step fails in the J-PAKE protocol.
 */
export class VerificationError extends JPakeError {
  /**
   * @inheritdoc
   */
  constructor(message: string) {
    super(message)
    this.name = 'VerificationError'
  }
}

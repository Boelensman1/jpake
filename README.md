# J-PAKE TypeScript Implementation

A TypeScript implementation of the Password Authenticated Key Exchange by Juggling (J-PAKE) protocol based on [RFC 8236](https://www.rfc-editor.org/rfc/rfc8236.txt).

Documentation: [https://boelensman1.github.io/jpake/](https://boelensman1.github.io/jpake/)

## Features

- Full implementation of the J-PAKE protocol
- Support for both two-round and three-pass variants
- Zero-knowledge proof verification using Schnorr signatures
- Built on the secp256k1 elliptic curve
- Written in TypeScript with strict type checking

## Installation

Requires Node.js 20.19.0 or newer.

```bash
npm install jpake-ts
```

## Usage

### Two-Round Implementation

```typescript
import { JPake, deriveSFromPassword } from 'jpake-ts'

// Initialize participants
const alice = new JPake('Alice')
const bob = new JPake('Bob')

// Convert password to shared secret
const password = 'secretPassword123'
const s = deriveSFromPassword(password)

// Execute Round 1
const aliceRound1 = alice.round1()
const bobRound1 = bob.round1()

// Execute Round 2
const aliceRound2 = alice.round2(bobRound1, s, bob.userId)
const bobRound2 = bob.round2(aliceRound1, s, alice.userId)

// Exchange Round 2 results
alice.setRound2ResultFromBob(bobRound2)
bob.setRound2ResultFromBob(aliceRound2)

// Derive shared keys
const aliceSharedKey = alice.deriveSharedKey()
const bobSharedKey = bob.deriveSharedKey()

// Keys should be equal
console.log(
  Buffer.from(aliceSharedKey).toString() ===
    Buffer.from(bobSharedKey).toString(),
) // true
```

### Three-Pass Implementation

```typescript
import { JPakeThreePass, deriveSFromPassword } from 'jpake-ts'

// Initialize participants
const alice = new JPakeThreePass('Alice')
const bob = new JPakeThreePass('Bob')

// Convert password to shared secret
const password = 'secretPassword123'
const s = deriveSFromPassword(password)

// Pass 1: Alice → Bob
const alicePass1 = alice.pass1()

// Pass 2: Bob → Alice
const bobPass2 = bob.pass2(alicePass1, s, alice.userId)

// Pass 3: Alice → Bob
const alicePass3 = alice.pass3(bobPass2, s, bob.userId)
bob.receivePass3Results(alicePass3)

// Derive shared keys
const aliceSharedKey = alice.deriveSharedKey()
const bobSharedKey = bob.deriveSharedKey()

// Keys should be equal
console.log(
  Buffer.from(aliceSharedKey).toString() ===
    Buffer.from(bobSharedKey).toString(),
) // true
```

## Security Considerations

Version 2.0.0 binds each Schnorr proof to its generator by hashing the
length-prefixed, compressed generator, commitment, and public key encodings,
followed by the length-prefixed user ID and optional context strings. This
changes proof compatibility with version 1.x for both exchange variants.
Upgrade both peers together; version 1.x proofs are rejected.

User IDs must be nonempty, well-formed Unicode strings of at most 255 UTF-8
bytes. Context strings must also be well-formed Unicode and at most 255
UTF-8 bytes each. Lone UTF-16 surrogates are rejected so distinct IDs cannot
collapse to the same encoded identity. Valid strings are encoded exactly as
provided, without Unicode normalization.

Passwords passed to `deriveSFromPassword` must be nonempty, well-formed Unicode
strings. Non-string values and lone UTF-16 surrogates are rejected. Passwords
have no 255-byte protocol-field limit and are not Unicode-normalized; valid
passwords retain their existing derived values.

Errors while generating or processing a round move the session to the terminal
`JPakeState.FAILED` state. Create a new instance to retry an exchange. Calls made
out of order raise `InvalidStateError` without changing the current state.
Incoming round-two proofs are copied, so subsequent caller mutations do not
change the stored proof. These rules apply to both exchange variants.

Ephemeral secret fields use JavaScript private storage. Their byte buffers are
overwritten and released when no longer needed, after successful key derivation,
or when an exchange fails. This reduces accidental exposure through object
inspection and retention; JavaScript does not guarantee complete memory erasure.
Schnorr nonce byte buffers are overwritten immediately after conversion to
bigint. The bigint intermediates cannot be explicitly erased in JavaScript.

1. This implementation is not resistant to timing attacks. In cryptographic contexts where timing attacks are a concern, additional mitigations should be implemented.
2. If using `deriveSFromPassword` the password should be strong and have sufficient entropy.

## Development

```bash
# Install dependencies
make install

# Run tests
make test

# Run tests with coverage
make coverage

# Build
make build

# Lint
make lint

# Compile docs
make docs
```

## License

MIT

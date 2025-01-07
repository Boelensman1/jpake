# J-PAKE TypeScript Implementation

A TypeScript implementation of the Password Authenticated Key Exchange by Juggling (J-PAKE) protocol based on [RFC 8236](https://www.rfc-editor.org/rfc/rfc8236.txt).

## Features

- Full implementation of the J-PAKE protocol
- Support for both two-round and three-pass variants
- Zero-knowledge proof verification using Schnorr signatures
- Built on the secp256k1 elliptic curve
- Written in TypeScript with strict type checking

## Installation

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
console.log(Buffer.from(aliceSharedKey).toString() === Buffer.from(bobSharedKey).toString()) // true
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
console.log(Buffer.from(aliceSharedKey).toString() === Buffer.from(bobSharedKey).toString()) // true
```

## Security Considerations

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
```

## License

MIT

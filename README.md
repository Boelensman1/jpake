# J-PAKE TypeScript Implementation

A TypeScript implementation of the Password Authenticated Key Exchange by Juggling (J-PAKE) protocol based on [RFC 8236](https://www.rfc-editor.org/rfc/rfc8236.txt).

Documentation: [https://boelensman1.github.io/jpake/](https://boelensman1.github.io/jpake/)

## Features

- J-PAKE key exchange with application-managed key confirmation
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

These examples compare both participants' keys locally to demonstrate agreement.
In an application, keep each key private and [confirm the peer's possession of
the same key](#key-confirmation) before granting authenticated access.

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

// Derive unconfirmed keys; the application must confirm peer possession.
const { key: aliceSharedKey } = alice.deriveSharedKey()
const { key: bobSharedKey } = bob.deriveSharedKey()

// Local demonstration only: never send these keys to the peer for comparison.
console.log(
  Buffer.from(aliceSharedKey).toString('hex') ===
    Buffer.from(bobSharedKey).toString('hex'),
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

// Derive unconfirmed keys; the application must confirm peer possession.
const { key: aliceSharedKey } = alice.deriveSharedKey()
const { key: bobSharedKey } = bob.deriveSharedKey()

// Local demonstration only: never send these keys to the peer for comparison.
console.log(
  Buffer.from(aliceSharedKey).toString('hex') ===
    Buffer.from(bobSharedKey).toString('hex'),
) // true
```

## Security Considerations

Version 2.0.0 binds each Schnorr proof to its generator by hashing the
length-prefixed, compressed generator, commitment, and public key encodings,
followed by the length-prefixed user ID and optional context strings. This
changes proof compatibility with version 1.x for both exchange variants.
Upgrade both peers together; version 1.x proofs are rejected.

`deriveSharedKey` returns `{ key, transcript }`. The key hashes a length-prefixed
tag naming this protocol and encoding, the length-prefixed shared secret, and the
transcript, so another protocol that reaches the same secret does not reach the
same key. Version 1.x hashed the shared secret alone and derives different keys.

The transcript holds the public values of the exchange: each user ID followed by
that peer's two round-one points and its round-two point, then the context
strings, every field length-prefixed. The two parties are ordered by encoded user
ID rather than by role, so both peers build the same bytes. It is not secret.
Use it to confirm the key or to bind it to a wider session.

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

A `VerificationError` means the peer failed verification, an `InvalidArgumentError`
means the local call was wrong. Count and rate-limit the former: J-PAKE allows one
online password guess per exchange.

Ephemeral secret fields use JavaScript private storage. Their byte buffers are
overwritten and released when no longer needed, after successful key derivation,
or when an exchange fails. This reduces accidental exposure through object
inspection and retention; JavaScript does not guarantee complete memory erasure.
Schnorr nonce byte buffers are overwritten immediately after conversion to
bigint. The bigint intermediates cannot be explicitly erased in JavaScript. The
`s` you pass in stays yours: it is password-equivalent, the library never
overwrites it, so wipe it yourself once the exchange completes.

1. This implementation is not resistant to timing attacks. In cryptographic contexts where timing attacks are a concern, additional mitigations should be implemented.
2. If using `deriveSFromPassword` the password should be strong and have sufficient entropy.

### Key confirmation

Both `JPake.deriveSharedKey()` and `JPakeThreePass.deriveSharedKey()` return an
**unconfirmed key**. Peers using different passwords can both complete the
exchange without an error and derive different keys. A successful return or
`JPakeState.KEYDERIVED` only means local key derivation succeeded; it does not
establish that the peer possesses the same key.

J-PAKE provides implicit authentication. Before treating the peer as
authenticated or granting access, the application must verify possession of
the same key. [RFC 8236 Section 5](https://www.rfc-editor.org/rfc/rfc8236.html#section-5)
recommends explicit key confirmation. An authenticated application protocol
can also establish possession by successfully verifying an appropriate peer
message; merely receiving bytes or ciphertext is insufficient.

The RFC's recommended MAC-based construction can be sketched as:

```text
kConfirm = KDF(key || "JPAKE_KC")
tagAlice = MAC(kConfirm, "KC_1_U" || lengthPrefixed(Alice) || transcript)
tagBob   = MAC(kConfirm, "KC_1_U" || lengthPrefixed(Bob)   || transcript)
```

The RFC encodes the peer IDs and all four round-one points into each tag. The
`transcript` returned alongside the key already is that encoding: both
identities and every public point of the exchange, length-prefixed and ordered
so that both peers produce identical bytes. Naming the sender is what keeps the
two tags distinct. Each peer verifies the other's tag with a constant-time
comparison. Reject failed confirmation, discard the session, and count it toward
failed-attempt limits. Keep derived keys private; exchange only confirmation
tags. The transcript is not secret.

This is a protocol sketch, not an API provided by this library. The RFC's `K`
is raw shared key material; this API returns `key`, a SHA3-256 hash over a
domain separation tag, the compressed shared secret, and the transcript.
Applications using these returned bytes must agree on a key schedule
that derives separate confirmation and application-traffic keys with distinct
domain labels. The confirmation messages and key schedule belong to the
application protocol and must match on both peers.

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

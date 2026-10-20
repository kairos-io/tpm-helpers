# tpm-helpers

This repository started as a fork of https://github.com/rancher-sandbox/go-tpm with additional capabilities for TPM.

> **Found a bug, or want to request a feature?** Open it on
> [kairos-io/kairos](https://github.com/kairos-io/kairos/issues), including
> issues about this repository. Every Kairos issue lives in one place, so you
> never have to work out which repository to file against.

## Remote Attestation with KMS

This library provides a complete implementation for remote attestation with a Key Management Service (KMS) using TPM-based cryptographic proofs over WebSocket connections. The flow supports both initial enrollment and subsequent verification seamlessly.

### Overview

The remote attestation flow allows a machine to:
1. **Prove its TPM identity** to a remote KMS
2. **Demonstrate boot state integrity** via PCR measurements
3. **Obtain decryption passphrases** securely over a WebSocket connection

The client doesn't need to know whether it's the first time contacting the KMS (enrollment) or a repeat visit (verification) — the same flow works for both.

### Security Guarantees

- **TPM Identity**: Endorsement Key (EK) proves requests come from a genuine TPM
- **Key Binding**: Attestation Key (AK) is bound to the specific TPM chip
- **Boot State Verification**: PCRs 0, 7, 11 prove system integrity hasn't changed
- **Connection Security**: WebSocket connection provides session binding and prevents replay attacks
- **Cryptographic Proof**: TPM quotes and credential activation provide cryptographic proof of TPM ownership

### Usage Examples

For complete, working examples of how to use this library, please refer to the [kcrypt-challenger repository](https://github.com/kairos-io/kcrypt-challenger).

### Data Structures

The WebSocket flow uses these data structures for the attestation protocol:

#### AttestationChallengeResponse
Contains the credential activation challenge sent by the server.

#### ProofRequest
Contains the secret from credential activation (proves TPM ownership) and the TPM quote (cryptographic proof of TPM state).

#### ProofResponse
Contains the decryption passphrase returned by the server.

### Go-Attestation Native Types

The library supports direct use with go-attestation library types (recommended approach). You can get EK and AttestationParameters directly and use go-attestation types for challenge generation.

### WebSocket Server-Side Implementation

The library provides helper functions for KMS WebSocket server implementation including:
- Parsing attestation data from client requests
- Generating credential activation challenge using go-attestation native types
- Validating challenge responses
- Verifying PCR quote signature and ensuring PCR values are cryptographically bound to the quote

#### WebSocket Protocol Flow

```
Client                           Server
  |-- WebSocket Connect --------->|
  |                               |
  |<------ Challenge -------------|  Server sends AttestationChallengeResponse
  |                               |
  |------ ProofRequest --------->|  Client proves TPM ownership
  |                               |
  |<------ ProofResponse ---------|  Server sends passphrase
  |                               |
Connection closed
```

#### Server Implementation Notes

The KMS WebSocket server should:

1. **On WebSocket Connection**:
   - Upgrade HTTP connection to WebSocket
   - Get client's attestation data (EK and AttestationParameters)
   - Use `tpm.GenerateChallenge()` to create credential activation challenge
   - Use PCR measurements to determine enrollment vs verification
   - Store challenge secret for this specific WebSocket session

2. **On ProofRequest**:
   - Use `tpm.ValidateChallenge()` to verify the secret matches
   - Verify `PCRQuote` signature and content (optional)
   - Return decryption passphrase
   - Close connection to prevent reuse

### WebSocket Security Model

The WebSocket approach provides inherent security against replay attacks without requiring nonces:

#### Connection-Based Security

1. **Session Binding**
   - Each challenge is bound to a specific WebSocket connection
   - Challenges cannot be replayed across different connections
   - Connection state prevents skipping authentication steps

2. **Sequential Protocol**
   - Server only sends passphrase after successful challenge resolution
   - No separate endpoints - single sequential flow within the connection
   - Impossible to "jump to step 2" without completing step 1

3. **Automatic Cleanup**
   - Connection closure automatically invalidates any stored secrets
   - No need for complex nonce expiry or cleanup mechanisms
   - Natural session lifecycle management

#### Replay Attack Prevention

**Why WebSockets Prevent Replay Attacks:**

- ✅ **Fresh Connection Required**: Each attestation requires a new WebSocket connection
- ✅ **Fresh Challenge**: Server generates a new challenge for each connection
- ✅ **Session Isolation**: Secrets are tied to the specific connection session
- ✅ **Sequential Flow**: Cannot skip challenge step to request passphrase
- ✅ **Connection Closure**: Automatic cleanup when connection ends

**Attack Scenarios That Are Prevented:**

1. **Replaying Old Challenges**: Attacker cannot reuse old challenge/response pairs because:
   - They need a new WebSocket connection
   - Server will generate a fresh challenge for the new connection
   - Old challenge response won't match new challenge

2. **Man-in-the-Middle**: Even if attacker captures the entire flow:
   - They still need to establish their own WebSocket connection
   - Server will issue a different challenge
   - Captured responses won't work with the new challenge

3. **Session Hijacking**: Connection-based security prevents:
   - Interception of in-flight messages
   - Reuse of authentication across sessions
   - Bypassing the challenge step

#### What the Connection Does Not Cover

All of the above is about the challenge and the secret recovered from it. It
holds against an attacker on the network, because such an attacker cannot open
the connection and recover the secret.

It does not hold against the node itself, which is the adversary measured boot
exists to catch. A compromised node can open a perfectly fresh connection and
answer a perfectly fresh challenge, because credential activation only proves
that the TPM is present, not what the machine booted. So the PCR quote needs
its own freshness, and it gets it from the nonce the TPM signs into it as
qualifying data. See the next section.

#### Implementation Benefits

- **Better Performance**: No database/cache operations for nonce management
- **Natural Security**: WebSocket protocol provides session binding
- **Cleaner Architecture**: Single connection handles entire flow
- **Reduced Attack Surface**: Fewer moving parts means fewer vulnerabilities

### PCR Quote Verification

The `VerifyPCRQuote` function provides comprehensive verification of TPM PCR quotes:

#### What It Does

1. **Signature Verification**: Verifies the PCR quote signature using the Attestation Key (AK) public key
2. **Freshness Check**: Verifies that the quote carries the nonce the verifier issued for this exchange
3. **PCR Consistency Check**: Ensures the provided PCR values match what was actually quoted by the TPM
4. **Cryptographic Binding**: Verifies that PCR values are cryptographically bound to the quote digest

#### Security Guarantees

- **Authenticity**: The quote signature proves the quote came from a genuine TPM
- **Freshness**: The TPM signs the verifier's nonce into the quote, so a quote recorded during an earlier boot does not verify
- **Integrity**: PCR values are verified against the TPM quote digest
- **Non-repudiation**: An attacker cannot provide fake PCR values without also providing a fake quote signature

#### Choosing a Nonce

`GeneratePCRQuote` and `VerifyPCRQuote` both require a nonce, and both reject an
empty one. The verifier picks it, and it must be unpredictable and used once.

The credential activation secret satisfies both: the verifier generates 32 fresh
random bytes per exchange, and only the TPM that owns the endorsement key can
recover them. `CreateProofRequest` therefore quotes with the secret it just
recovered, and the verifier checks the quote against the secret it issued, with
no extra round trip.

### PCR Measurements

The implementation reads and verifies these PCRs:
- **PCR 0**: BIOS/UEFI measurements
- **PCR 7**: Secure Boot state
- **PCR 11**: Unified Kernel Image (UKI) measurements

These PCRs establish the "golden" boot state during enrollment and verify it hasn't changed during subsequent requests.

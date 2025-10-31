# tpm-helpers

This repository started as a fork of https://github.com/rancher-sandbox/go-tpm with additional capabilities for TPM.

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

#### Implementation Benefits

- **Simpler Code**: No nonce generation, storage, or validation logic needed
- **Better Performance**: No database/cache operations for nonce management
- **Natural Security**: WebSocket protocol provides session binding
- **Cleaner Architecture**: Single connection handles entire flow
- **Reduced Attack Surface**: Fewer moving parts means fewer vulnerabilities

### Error Handling and Corrupted Files

#### AK File Corruption
If an AK blob file becomes corrupted, `GetOrCreateAK()` will return descriptive errors rather than automatically deleting the file:

- **Empty files (0 bytes)**: Returns error asking user to manually remove the file
- **Suspiciously small files (<50 bytes)**: Returns error suggesting potential corruption
- **JSON parsing failures**: Returns error indicating corruption or version mismatch

**Important**: The library will NOT automatically remove corrupted AK files because they may represent data that is enrolled on the server side. Manual intervention ensures users can assess the situation before taking destructive actions.

#### Example Error Messages
The library returns descriptive error messages when AK files are corrupted, asking users to manually verify or remove the file before retrying.

### PCR Quote Verification

The `VerifyPCRQuote` function provides comprehensive verification of TPM PCR quotes:

#### What It Does

1. **Signature Verification**: Verifies the PCR quote signature using the Attestation Key (AK) public key
2. **PCR Consistency Check**: Ensures the provided PCR values match what was actually quoted by the TPM
3. **Cryptographic Binding**: Verifies that PCR values are cryptographically bound to the quote digest

#### Security Guarantees

- **Authenticity**: The quote signature proves the quote came from a genuine TPM
- **Integrity**: PCR values are verified against the TPM quote digest
- **Non-repudiation**: An attacker cannot provide fake PCR values without also providing a fake quote signature

### PCR Measurements

The implementation reads and verifies these PCRs:
- **PCR 0**: BIOS/UEFI measurements
- **PCR 7**: Secure Boot state
- **PCR 11**: Unified Kernel Image (UKI) measurements

These PCRs establish the "golden" boot state during enrollment and verify it hasn't changed during subsequent requests.

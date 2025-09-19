# tpm-helpers

A fork of https://github.com/rancher-sandbox/go-tpm with additional capabilities for TPM.

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

### Usage

#### 1. Initialize AK Manager

```go
import "github.com/kairos-io/tpm-helpers"

// Create AK manager with persistent storage
akManager, err := tpm.NewAKManager(tpm.WithAKHandleFile("/etc/kairos/ak.blob"))
if err != nil {
    return fmt.Errorf("creating AK manager: %w", err)
}

// Create or load AK (creates if doesn't exist)
akPublicKey, err := akManager.GetOrCreateAK()
if err != nil {
    return fmt.Errorf("getting/creating AK: %w", err)
}

// Note: If AK file is corrupted, GetOrCreateAK() will return an error
// asking for manual intervention rather than automatically deleting the file.
// This prevents accidental removal of enrolled server-side data.
```

#### 2. WebSocket Attestation Flow

```go
import "github.com/gorilla/websocket"

// Step 1: Connect to KMS WebSocket endpoint
// Use AttestationConnection for simple WebSocket connections
conn, err := tpm.AttestationConnection("wss://kms.example.com/attestation")
if err != nil {
    return fmt.Errorf("connecting to KMS: %w", err)
}
defer conn.Close()

// Step 2: Get attestation data using go-attestation native types
ek, akParams, err := akManager.GetAttestationData()
if err != nil {
    return fmt.Errorf("getting attestation data: %w", err)
}

// Step 3: Server sends challenge, client responds with proof
// (See complete WebSocket flow example below)
```

#### 3. Complete WebSocket Flow Example

```go
func RequestDecryptionPassphraseWebSocket() ([]byte, error) {
    // Initialize AK manager
    akManager, err := tpm.NewAKManager(tpm.WithAKHandleFile("/etc/kairos/ak.blob"))
    if err != nil {
        return nil, err
    }
    
    // Ensure AK exists
    _, err = akManager.GetOrCreateAK()
    if err != nil {
        return nil, err
    }
    
    // Connect to KMS WebSocket endpoint
    conn, err := tpm.AttestationConnection("wss://kms.example.com/attestation")
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    
    // Get attestation data using go-attestation native types
    ek, akParams, err := akManager.GetAttestationData()
    if err != nil {
        return nil, err
    }
    
    // Server immediately sends challenge upon connection
    var challengeResp AttestationChallengeResponse
    if err := conn.ReadJSON(&challengeResp); err != nil {
        return nil, fmt.Errorf("reading challenge: %w", err)
    }
    
    // Generate proof of TPM ownership
    proofReq, err := akManager.CreateProofRequest(&challengeResp)
    if err != nil {
        return nil, err
    }
    
    // Send proof to server
    if err := conn.WriteJSON(proofReq); err != nil {
        return nil, fmt.Errorf("sending proof: %w", err)
    }
    
    // Receive passphrase from server
    var proofResp ProofResponse
    if err := conn.ReadJSON(&proofResp); err != nil {
        return nil, fmt.Errorf("reading passphrase: %w", err)
    }
    
    return proofResp.Passphrase, nil
}
```

### Data Structures

The WebSocket flow uses these data structures for the attestation protocol:

#### AttestationChallengeResponse  
```go
type AttestationChallengeResponse struct {
    Challenge *attest.EncryptedCredential // Credential activation challenge
    Enrolled  bool                        // True if this was first-time enrollment
}
```

#### ProofRequest
```go
type ProofRequest struct {
    Secret   []byte // Secret from credential activation (proves TPM ownership)
    PCRQuote []byte // TPM quote (cryptographic proof of TPM state)
}
```

#### ProofResponse
```go
type ProofResponse struct {
    Passphrase []byte // The decryption passphrase
}
```

### Go-Attestation Native Types

For direct use with go-attestation library (recommended approach):

```go
// Get EK and AttestationParameters directly
ek, akParams, err := akManager.GetAttestationData()

// Use go-attestation types for challenge generation
secret, challenge, err := tpm.GenerateChallenge(ek, akParams)
```

### WebSocket Server-Side Implementation

The library provides helper functions for KMS WebSocket server implementation.

#### Available Server Functions

```go
// Parse attestation data from client requests  
func DecodeEK(pemBytes []byte) (*attest.EK, error)

// Generate credential activation challenge using go-attestation native types
func GenerateChallenge(ek *attest.EK, akParams *attest.AttestationParameters) ([]byte, []byte, error)

// Validate challenge responses
func ValidateChallenge(secret, resp []byte) error
```

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

#### WebSocket Server Implementation Example

```go
import "github.com/gorilla/websocket"

// WebSocket handler for TPM attestation
func handleTPMAttestation(w http.ResponseWriter, r *http.Request) {
    // Upgrade to WebSocket
    upgrader := websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
    }
    
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
        return
    }
    defer conn.Close()
    
    // Get client's attestation data (sent during WebSocket handshake or first message)
    ek, akParams, err := getClientAttestationData(conn)
    if err != nil {
        sendError(conn, "Failed to get attestation data")
        return
    }
    
    // 1. Check enrollment vs verification
    enrolled := false
    tpmHash := hashEK(ek) // Your TPM identification logic
    if isFirstTime(tpmHash) {
        // Enrollment: store TPM identity and PCR values
        err = storeTPMIdentity(tpmHash, akParams)
        if err != nil {
            sendError(conn, "Failed to store TPM identity")
            return
        }
        enrolled = true
    } else {
        // Verification: validate PCRs match stored values  
        if !attestationMatches(tpmHash, akParams) {
            sendError(conn, "PCR values changed - possible compromise")
            return
        }
    }
    
    // 2. Generate challenge using go-attestation native types
    secret, challengeBytes, err := tpm.GenerateChallenge(ek, akParams)
    if err != nil {
        sendError(conn, "Failed to generate challenge")
        return
    }
    
    // 3. Store secret for this WebSocket session
    sessionID := generateSessionID() 
    storeSessionSecret(sessionID, secret)
    
    // 4. Parse and send challenge to client
    var challenge Challenge
    json.Unmarshal(challengeBytes, &challenge)
    
    challengeResp := &AttestationChallengeResponse{
        Challenge: challenge.EC,
        Enrolled:  enrolled,
    }
    
    if err := conn.WriteJSON(challengeResp); err != nil {
        return
    }
    
    // 5. Wait for proof from client
    var proofReq ProofRequest
    if err := conn.ReadJSON(&proofReq); err != nil {
        sendError(conn, "Failed to read proof")
        return
    }
    
    // 6. Validate challenge response
    respBytes, _ := json.Marshal(ChallengeResponse{Secret: proofReq.Secret})
    if err := tpm.ValidateChallenge(secret, respBytes); err != nil {
        sendError(conn, "Challenge validation failed")
        return
    }
    
    // 7. Verify PCR quote (optional additional verification)
    if !verifyPCRQuote(proofReq.PCRQuote, tpmHash) {
        sendError(conn, "PCR quote verification failed")
        return
    }
    
    // 8. Send passphrase to client
    proofResp := &ProofResponse{
        Passphrase: getDecryptionPassphrase(tpmHash),
    }
    
    conn.WriteJSON(proofResp)
    
    // Connection closes automatically, preventing reuse
}
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
```
AK blob file exists but is empty (0 bytes) - this indicates corruption. 
Please remove the file manually and retry: /etc/kairos/ak.blob

AK blob file is suspiciously small (15 bytes) - this may indicate corruption. 
Please verify the file or remove it manually and retry: /etc/kairos/ak.blob

failed to load existing AK blob file (this may indicate corruption or version mismatch). 
Please verify the file or remove it manually and retry. File: /etc/kairos/ak.blob
```

### PCR Measurements

The implementation reads and verifies these PCRs:
- **PCR 0**: BIOS/UEFI measurements
- **PCR 7**: Secure Boot state
- **PCR 11**: Unified Kernel Image (UKI) measurements

These PCRs establish the "golden" boot state during enrollment and verify it hasn't changed during subsequent requests.

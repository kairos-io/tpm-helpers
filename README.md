# tpm-helpers

A fork of https://github.com/rancher-sandbox/go-tpm with additional capabilities for TPM.

## Remote Attestation with KMS

This library provides a complete implementation for remote attestation with a Key Management Service (KMS) using TPM-based cryptographic proofs. The flow supports both initial enrollment and subsequent verification seamlessly.

### Overview

The remote attestation flow allows a machine to:
1. **Prove its TPM identity** to a remote KMS
2. **Demonstrate boot state integrity** via PCR measurements  
3. **Ensure request freshness** using server-generated nonces
4. **Obtain decryption passphrases** securely

The client doesn't need to know whether it's the first time contacting the KMS (enrollment) or a repeat visit (verification) - the same flow works for both.

### Security Guarantees

- **TPM Identity**: Endorsement Key (EK) proves requests come from a genuine TPM
- **Key Binding**: Attestation Key (AK) is bound to the specific TPM chip
- **Boot State Verification**: PCRs 0, 7, 11 prove system integrity hasn't changed
- **Freshness**: Server nonces prevent replay attacks
- **Cryptographic Proof**: TPM quotes sign PCR values + nonce with the AK

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
```

#### 2. Request Decryption Passphrase

```go
// Step 1: Request challenge from KMS
challengeReq, err := akManager.GetChallengeRequest()
if err != nil {
    return fmt.Errorf("creating challenge request: %w", err)
}

// Send challengeReq to KMS endpoint
challengeResp, err := sendChallengeRequestToKMS(challengeReq)
if err != nil {
    return fmt.Errorf("requesting challenge: %w", err)
}

// Step 2: Create proof of TPM ownership with nonce
proofReq, err := akManager.CreateProofRequest(challengeResp)
if err != nil {
    return fmt.Errorf("creating proof request: %w", err)
}

// Send proofReq to KMS endpoint  
proofResp, err := sendProofRequestToKMS(proofReq)
if err != nil {
    return fmt.Errorf("sending proof: %w", err)
}

// proofResp.Passphrase contains the decryption key
```

#### 3. Complete Example

```go
func RequestDecryptionPassphrase() ([]byte, error) {
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
    
    // Request challenge+nonce from KMS
    challengeReq, err := akManager.GetChallengeRequest()
    if err != nil {
        return nil, err
    }
    
    challengeResp, err := sendChallengeRequestToKMS(challengeReq)
    if err != nil {
        return nil, err
    }
    
    // Prove TPM ownership with freshness
    proofReq, err := akManager.CreateProofRequest(challengeResp)
    if err != nil {
        return nil, err
    }
    
    proofResp, err := sendProofRequestToKMS(proofReq)
    if err != nil {
        return nil, err
    }
    
    return proofResp.Passphrase, nil
}
```

### Data Structures

#### ChallengeRequest
```go
type ChallengeRequest struct {
    EK   []byte                        // Endorsement Key (TPM identity)
    AK   *attest.AttestationParameters // Attestation Key (for signing)  
    PCRs *PCRValues                    // Current PCR measurements
}
```

#### AttestationChallengeResponse  
```go
type AttestationChallengeResponse struct {
    Challenge *attest.EncryptedCredential // Credential activation challenge
    Nonce     []byte                      // Server-generated nonce
    Enrolled  bool                        // True if this was first-time enrollment
}
```

#### ProofRequest
```go
type ProofRequest struct {
    Secret   []byte // Secret from credential activation (proves TPM ownership)
    Nonce    []byte // Server nonce (anti-replay protection)  
    PCRQuote []byte // TPM quote with nonce (cryptographic freshness proof)
}
```

#### ProofResponse
```go
type ProofResponse struct {
    Passphrase []byte // The decryption passphrase
}
```

### Server-Side Implementation

The library provides helper functions for KMS server implementation:

#### Available Server Functions

```go
// Generate a cryptographically secure nonce
func GenerateNonce() ([]byte, error)

// Parse attestation data from client requests  
func DecodeEK(pemBytes []byte) (*attest.EK, error)
func GetAttestationData(header string) (*attest.EK, *AttestationData, error)

// Generate credential activation challenge
func GenerateChallenge(ek *attest.EK, attestationData *AttestationData) ([]byte, []byte, error)

// Validate challenge responses
func ValidateChallenge(secret, resp []byte) error
```

#### Server Implementation Example

```go
// Handle ChallengeRequest
func handleChallengeRequest(req *ChallengeRequest) (*AttestationChallengeResponse, error) {
    // 1. Decode EK from request
    ek, err := tpm.DecodeEK(req.EK)
    if err != nil {
        return nil, fmt.Errorf("decoding EK: %w", err)
    }
    
    // 2. Check enrollment vs verification
    tpmHash := hashEK(req.EK) // Your TPM identification logic
    if isFirstTime(tpmHash) {
        // Enrollment: store TPM identity and PCR values
        err = storeTMPIdentity(tmpHash, req.AK, req.PCRs)
        if err != nil {
            return nil, err
        }
        enrolled = true
    } else {
        // Verification: validate PCRs match stored values
        if !pcrValuesMatch(tpmHash, req.PCRs) {
            return nil, errors.New("PCR values changed - possible compromise")
        }
    }
    
    // 3. Generate challenge using library function
    attestData := &tpm.AttestationData{
        EK: req.EK,
        AK: req.AK,
    }
    secret, challengeBytes, err := tpm.GenerateChallenge(ek, attestData)
    if err != nil {
        return nil, fmt.Errorf("generating challenge: %w", err)
    }
    
    // 4. Generate fresh nonce
    nonce, err := tpm.GenerateNonce()
    if err != nil {
        return nil, fmt.Errorf("generating nonce: %w", err)
    }
    
    // 5. Store secret and nonce for validation
    storeChallenge(tmpHash, secret, nonce)
    
    // 6. Parse and return challenge
    var challenge Challenge
    json.Unmarshal(challengeBytes, &challenge)
    
    return &AttestationChallengeResponse{
        Challenge: challenge.EC,
        Nonce:     nonce,
        Enrolled:  enrolled,
    }, nil
}

// Handle ProofRequest  
func handleProofRequest(req *ProofRequest) (*ProofResponse, error) {
    // 1. Verify nonce is fresh and valid
    if !isNonceValid(req.Nonce) {
        return nil, errors.New("invalid or expired nonce")
    }
    
    // 2. Get stored challenge data
    secret, err := getStoredSecret(req.Nonce)
    if err != nil {
        return nil, err
    }
    
    // 3. Validate challenge response using library function
    respBytes, _ := json.Marshal(ChallengeResponse{Secret: req.Secret})
    if err := tpm.ValidateChallenge(secret, respBytes); err != nil {
        return nil, fmt.Errorf("challenge validation failed: %w", err)
    }
    
    // 4. Verify PCR quote contains expected nonce
    if !verifyPCRQuoteContainsNonce(req.PCRQuote, req.Nonce) {
        return nil, errors.New("PCR quote does not contain expected nonce")
    }
    
    // 5. Consume nonce and return passphrase
    consumeNonce(req.Nonce)
    return &ProofResponse{
        Passphrase: getDecryptionPassphrase(),
    }, nil
}
```

#### Server Implementation Notes

The KMS server should:

1. **On ChallengeRequest**:
   - Use `tpm.DecodeEK()` to parse the EK
   - Use `tpm.GenerateChallenge()` to create credential activation challenge
   - Use `tpm.GenerateNonce()` for fresh nonce generation
   - Use `PCRs` to determine enrollment vs verification
   - Store challenge secret and nonce for later validation

2. **On ProofRequest**:
   - Verify nonce is fresh and valid
   - Use `tpm.ValidateChallenge()` to verify the secret
   - Verify `PCRQuote` signature and nonce inclusion
   - Consume nonce to prevent reuse
   - Return decryption passphrase

### Nonce Management Best Practices

Secure nonce handling is critical for preventing replay attacks. The KMS implementation should handle nonce storage and validation.

#### Storage Options

1. **In-Memory Cache (Single Server)**
   - Best performance for single-server deployments
   - Use thread-safe data structures with expiry tracking
   - Implement periodic cleanup to prevent memory leaks
   - Suitable when no load balancing is required

2. **Redis Cache (Recommended for Production)**
   - Ideal for load-balanced/multi-server environments
   - Built-in TTL (time-to-live) for automatic expiry
   - Atomic operations for thread-safe check-and-delete
   - Shared state across multiple KMS instances

3. **Database Storage (Audit Requirements)**
   - When persistent audit trails are required
   - Slower but provides compliance logging
   - Use atomic UPDATE operations for single-use enforcement
   - Implement scheduled cleanup jobs

#### Security Recommendations

1. **Expiry Time**
   - **5-15 minutes recommended** - balance security vs user experience
   - Consider network latency and potential clock skew
   - Shorter expiry reduces replay attack window

2. **Enforcement Rules**
   - **Single-use only** - consume nonce immediately after validation
   - **Atomic operations** - prevent race conditions in multi-threaded environments
   - **Automatic cleanup** - remove expired nonces to prevent memory/storage bloat

3. **Additional Security Measures**
   - Rate limiting per client IP address
   - Maximum concurrent nonces per TPM identity
   - Security monitoring and alerting for suspicious patterns
   - Logging for audit and forensic analysis

#### Implementation Considerations

- Use the library's `tpm.GenerateNonce()` function for secure nonce generation
- Store nonces with their expiry time for efficient validation
- Implement thread-safe access for concurrent request handling
- Consider using Redis for production deployments with multiple KMS servers
- Set up monitoring for nonce usage patterns and potential abuse

### PCR Measurements

The implementation reads and verifies these PCRs:
- **PCR 0**: BIOS/UEFI measurements
- **PCR 7**: Secure Boot state
- **PCR 11**: Unified Kernel Image (UKI) measurements

These PCRs establish the "golden" boot state during enrollment and verify it hasn't changed during subsequent requests.
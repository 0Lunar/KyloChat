# KyloChat - Cryptography & Protocol

**Document**: Cryptographic Implementation and Wire Protocol  
**Version**: 1.0  
**Last Updated**: 2025-02-06

---

## Table of Contents

1. [Cryptographic Stack](#1-cryptographic-stack)
2. [Handshake Protocol](#2-handshake-protocol)
3. [Message Protocol](#3-message-protocol)
4. [CryptoHandler Implementation](#4-cryptohandler-implementation)

---

## 1. Cryptographic Stack

### 1.1 Algorithms Overview

KyloChat uses a **defense-in-depth** cryptographic approach with multiple independent security layers:

| Layer | Algorithm | Purpose | Key Size |
|-------|-----------|---------|----------|
| **Key Exchange** | X25519 (ECDH) | Establish shared secret | 256-bit |
| **Key Derivation** | HKDF-SHA256 | Derive AES key from X25519 output | 256-bit output |
| **Encryption** | AES-256-CTR | Stream encryption (no padding) | 256-bit key |
| **Authentication** | HMAC-SHA256 | Message authentication & integrity | 256-bit key |
| **Signing** | ECDSA P-256 | Server certificate | 256-bit key |
| **Password Hashing** | Bcrypt | Credential storage | Cost factor 12 |

### 1.2 X25519 + HKDF Key Exchange

**Purpose**: Establish shared secret for symmetric encryption with perfect forward secrecy.

**Process**:
1. Both parties generate ephemeral X25519 keypairs
2. Exchange public keys (32 bytes each)
3. Each computes shared secret via ECDH
4. **CRITICAL**: Apply HKDF to derive AES key from shared secret

**Why HKDF?**
- Raw X25519 output has mathematical structure
- HKDF extracts entropy and expands to uniform random key
- Provides domain separation via info parameter: `b'Key Derivation for X25519'`
- Best practice recommended by cryptographers

**Security Properties**:
- Perfect Forward Secrecy: Compromise of long-term keys doesn't reveal past sessions
- 128-bit security level (equivalent to ~3072-bit RSA)
- Constant-time implementation (no timing attacks)

### 1.3 AES-256-CTR Encryption

**Purpose**: Stream encryption of all messages (lightweight, no padding).

**Configuration**:
- Key: 256-bit (from HKDF-SHA256)
- Nonce/Counter: 128-bit (16 bytes), randomly generated per message
- Mode: Counter (CTR) - stream cipher mode
- **No padding required** - CTR mode works on any length

**Message Structure**:
```
[nonce/counter (16B)] + [ciphertext (same length as plaintext)] + [HMAC (32B)]
```

**Properties**:
- Confidentiality: AES-256 encryption
- Stream cipher: No padding overhead
- Parallelizable: Each block can be encrypted independently
- Nonce uniqueness: MUST be unique per message with same key (critical!)
- **No built-in authentication**: Relies entirely on HMAC

**Why CTR over GCM?**
- **Efficiency**: No padding means smaller payloads
- **Simplicity**: Cleaner separation of encryption and authentication
- **Performance**: CTR is slightly faster than GCM
- **Lightweight**: Reduced overhead for embedded/mobile clients

**Critical Security Note**:
CTR mode provides **NO authentication** by itself. All integrity and authenticity comes from HMAC-SHA256. This is why HMAC verification happens BEFORE decryption.

### 1.4 HMAC-SHA256 Authentication

**Purpose**: Message authentication and integrity verification (SOLE authentication mechanism).

**Configuration**:
- Key: 256-bit, randomly generated during handshake
- Hash: SHA-256
- Output: 256-bit (32 bytes) signature

**Critical Role with CTR Mode**:
Since AES-CTR provides **no authentication**, HMAC is the ONLY defense against:
- Message tampering
- Bit flipping attacks
- Replay attacks (combined with nonce tracking)
- Unauthorized message injection

**Why HMAC is Sufficient**:
- **Cryptographically Strong**: HMAC-SHA256 is proven secure
- **Industry Standard**: Used by TLS, SSH, IPsec
- **Simpler Design**: Clear separation of concerns (encrypt vs authenticate)
- **Better Performance**: Single authentication layer instead of dual (GCM + HMAC)

**Verification**:
- Uses constant-time comparison (timing attack prevention)
- Verification happens **BEFORE decryption** (critical for CTR!)
- Failure = immediate rejection, ciphertext never decrypted
- Protects against adaptive chosen-ciphertext attacks

**Security Guarantee**:
HMAC provides cryptographic integrity. Any modification to the ciphertext (even single bit) will cause HMAC verification to fail with overwhelming probability (2^-256).

### 1.5 ECDSA Certificate

**Purpose**: Server identity verification.

**Configuration**:
- Curve: secp256r1 (NIST P-256)
- Signature: ECDSA with SHA-256
- Format: OpenSSH public key format

**Server Side**:
- Generates or loads ECDSA keypair from cert.pem
- Optional password protection via CERT_PASSWD environment variable
- Signs X25519 public key during handshake
- Certificate persists across restarts

**Client Side**:
- Receives server's public key in OpenSSH format
- Verifies ECDSA signature on X25519 key
- TOFU: Stores fingerprint in .cache/fingers.pub
- Subsequent connections: Compare fingerprint, abort if mismatch

### 1.6 TOFU (Trust On First Use)

**Concept**: Accept certificate on first connection, detect changes thereafter.

**First Connection**:
1. Client receives server certificate
2. Verifies ECDSA signature on X25519 key
3. Stores certificate in `.cache/fingers.pub`
4. Connection proceeds

**Subsequent Connections**:
1. Client receives certificate
2. Compares with stored certificate
3. If match: proceed
4. If mismatch: **ABORT** (possible MITM attack!)

**Fingerprint File Format**:
```
192.168.1.100:5000 ecdsa-sha2-nistp256 AAAAE2VjZHNh...
127.0.0.1:5000 ecdsa-sha2-nistp256 AAAAE2VjZHNh...
```

**Limitations**:
- Vulnerable to MITM on first connection
- Users should verify fingerprint via independent channel
- No certificate revocation mechanism

### 1.7 Bcrypt Password Hashing

**Purpose**: Secure password storage (server-side only).

**Configuration**:
- Algorithm: Bcrypt (based on Blowfish)
- Cost factor: 12 (default) = 2^12 = 4096 iterations
- Computation time: ~100ms per hash/check
- Output format: $2b$12$[salt][hash]

**Properties**:
- Intentionally slow (anti-brute-force)
- Unique salt per password
- Adaptive (cost can be increased as hardware improves)
- Timing-safe comparison

**Usage**:
- Registration: Hash password before storing in credentials table
- Login: Verify provided password against stored hash
- ~100ms per verification = rate limiting by design

---

## 2. Handshake Protocol

### 2.1 Complete Handshake Sequence

```
CLIENT                                          SERVER

1. TCP Connect
   ────────────────────────────────────────────>

2. Receive certificate
   <────────────────────────────────────────────
   [2 bytes length][OpenSSH public key]

3. Import certificate
   Verify TOFU (compare with stored)
   
4. Receive signed X25519 public key
   <────────────────────────────────────────────
   [2 bytes length][pub_key(32B)][signature(~64B)]

5. Verify ECDSA signature
   If invalid: ABORT

6. Generate X25519 keypair
   Send public key
   ────────────────────────────────────────────>
   [32 bytes, no length prefix]

7. Derive AES key
   shared = X25519_ECDH(local_priv, server_pub)
   aes_key = HKDF(shared, info=b'Key Derivation for X25519')

8. Generate HMAC key
   hmac_key = random(32)

9. Encrypt HMAC key
   nonce = random(16)
   encrypted = AES_CTR.encrypt(nonce, hmac_key)

10. Send encrypted HMAC
    ────────────────────────────────────────────>
    [nonce(16B)] + [encrypted_hmac(32B)]

11.                                        Receive encrypted HMAC
                                           Decrypt with AES key
                                           Extract HMAC key

12. ════════ SECURE CHANNEL ESTABLISHED ═══════
```

**Handshake Duration**: Typically <100ms on local network

**Timeout**: 10 seconds (configurable via socket.settimeout)

### 2.2 Authentication Phase

**Standard Login (Username + Password)**:
```
CLIENT                                          SERVER

Send STD_LOGIN type
────────────────────────────────────────────>
[0x06] (1 byte unencrypted)

Send username
────────────────────────────────────────────>
[encrypted, length-prefixed]

                                        Check user exists
                                        Check not banned
                                        
<────────────────────────────────────────────
SUCCESS (0x00) or FAILURE (0x01)

Send password
────────────────────────────────────────────>
[encrypted, length-prefixed]

                                        Bcrypt verify (~100ms)
                                        Generate UUID token
                                        Store in tokens table
                                        Set expiration (7 days)

<────────────────────────────────────────────
SUCCESS + token (36 bytes)

Cache token locally
```

**Cached Login (Token-Based)**:
```
CLIENT                                          SERVER

Send CACHED_LOGIN type
────────────────────────────────────────────>
[0x05] (1 byte unencrypted)

Send cached token
────────────────────────────────────────────>
[36 bytes UUID, encrypted]

                                        Check token exists
                                        Check not expired
                                        Check not revoked
                                        Check user not banned

<────────────────────────────────────────────
SUCCESS (0x00) or FAILURE (0x01)
```

---

## 3. Message Protocol

### 3.1 Message Types

```python
class MessageTypes(Enum):
    SUCCESS = 0           # Login success
    FAILURE = 1           # Login failed
    MESSAGE = 2           # Text message
    STATUS_CODE = 3       # Server status (2 bytes)
    COMPRESSED_MSG = 4    # Zlib compressed text
    CACHED_LOGIN = 5      # Token login request
    STD_LOGIN = 6         # Username/password login
    IMAGE = 7             # Binary image data
    COMPRESSED_IMAGE = 8  # Zlib compressed image
```

### 3.2 Message Structure on Wire

**Complete Message**:
```
┌──────────┬────────────────────────────────────────────┬───────────┐
│   TYPE   │         ENCRYPTED PAYLOAD                  │   HMAC    │
│  (1 B)   │  [length][nonce][ciphertext]               │  (32 B)   │
└──────────┴────────────────────────────────────────────┴───────────┘
    ↑                        ↑                               ↑
Unencrypted         Length-prefixed                  Over encrypted
                    (1/2/4/8 bytes)                   payload only
```

**Encrypted Payload (before encryption)**:
```
┌───────────────────────┬────────────────────┐
│   TOKEN (36 B UUID)   │   MESSAGE DATA     │
└───────────────────────┴────────────────────┘
      No padding required (CTR mode)
```

**Encrypted Payload (after encryption)**:
```
┌──────────────┬────────────────────────────────────┐
│ NONCE (16B)  │  CIPHERTEXT (same length as plain) │
└──────────────┴────────────────────────────────────┘
```

**Key Differences from GCM**:
- Nonce is 16 bytes (128-bit) instead of 12 bytes (96-bit)
- No GCM authentication tag (removed 16 bytes overhead)
- No PKCS7 padding (removed 1-16 bytes overhead)
- Ciphertext is exactly same length as plaintext
- **Result**: Smaller payloads, better efficiency

### 3.3 Length-Prefixed Protocol

All encrypted payloads use length prefixes:

| Method | Prefix Size | Max Payload |
|--------|-------------|-------------|
| `send_char_bytes` | 1 byte | 255 B |
| `send_short_bytes` | 2 bytes | 65,535 B (~64 KB) |
| `send_int_bytes` | 4 bytes | 4,294,967,295 B (~4 GB) |
| `send_long_bytes` | 8 bytes | 18,446,744,073,709,551,615 B (~18 EB) |

**Send Process**:
1. Encrypt payload with AES-GCM
2. Calculate HMAC over ciphertext
3. Construct: nonce + ciphertext + hmac
4. Calculate total length
5. Send length prefix (little-endian)
6. Send complete encrypted payload

**Receive Process**:
1. Read length prefix (N bytes)
2. Read exactly that many bytes
3. Split into: nonce + ciphertext + hmac
4. Verify HMAC (constant-time)
5. Decrypt with AES-GCM
6. Remove PKCS7 padding
7. Return plaintext

### 3.4 Text Message Example

**Client Sends**:
```
1. Prepare payload:
   payload = token.encode() + message.encode()
   # "550e8400...Hello, World!"

2. Optional compression:
   if compression_enabled:
       payload = token + zlib.compress(message)
       msg_type = COMPRESSED_MSG

3. Send message type (unencrypted):
   conn.send_char_bytes(bytes([MESSAGE]))  # 0x02

4. Send encrypted payload (length-prefixed):
   conn.send_int_bytes(payload)
   # Internally: encrypt → add HMAC → send length + data
```

**Server Receives**:
```
1. Receive message type:
   msg_type = int.from_bytes(conn.recv_char_bytes(1))
   # 0x02 = MESSAGE

2. Receive encrypted payload:
   payload = conn.recv_int_bytes()
   # Internally: read length → read data → verify HMAC → decrypt

3. Decompress if needed:
   if msg_type == COMPRESSED_MSG:
       payload = payload[:36] + zlib.decompress(payload[36:])

4. Extract token and data:
   token = payload[:36].decode()
   data = payload[36:]

5. Validate token in database

6. Broadcast to all clients
```

### 3.5 Image Message

**Same structure as text**, but:
- Message type: `IMAGE` (0x07) or `COMPRESSED_IMAGE` (0x08)
- Data: Binary image bytes instead of UTF-8 text
- Size limit: Configurable (default: 250 KB, recommend 1 MB for production)

**Client-side image handling**:
1. Read image file
2. Check size against max_image_size
3. If too large: Resize with PIL
4. Optional: Compress with zlib
5. Send as IMAGE or COMPRESSED_IMAGE type

### 3.6 Status Codes

**Special message type** (unencrypted, no HMAC):
```
┌──────────────┬──────────────┐
│  0x03        │  CODE (2B)   │
└──────────────┴──────────────┘
```

**Common status codes**:
- `100`: Command received (processing)
- `200`: Success
- `400`: Bad request (invalid format, size exceeded)
- `401`: Unauthorized (rate limit exceeded, invalid/expired token)
- `403`: Forbidden (user banned)

---

## 4. CryptoHandler Implementation

### 4.1 Server CryptoHandler (275 lines)

**Responsibilities**:
- Generate/load ECDSA certificate (Load_CERT)
- Sign data with ECDSA (CERT_Sign)
- X25519 key generation and exchange
- AES-256-GCM encryption/decryption
- HMAC-SHA256 signing/verification
- Bcrypt password hashing/checking

**Key Methods**:

**Certificate Operations**:
- `Load_CERT(cert_path)`: Load existing or generate new ECDSA keypair
- `Export_CERT_public_key()`: Export public key in OpenSSH format
- `CERT_Sign(data)`: Sign data with ECDSA private key
- `CERT_Close()`: Clear certificate from memory

**Password Operations** (server only):
- `Generate_Bcrypt_Salt()`: Generate random salt
- `Bcrypt_Hash(password, salt)`: Hash password with bcrypt
- `Bcrypt_Check(password, hash)`: Verify password (timing-safe)

### 4.2 Client CryptoHandler (226 lines)

**Responsibilities**:
- Import server certificates (CERT_Import)
- Verify ECDSA signatures (CERT_Verify)
- TOFU certificate validation (CERT_Check, CERT_Save)
- X25519 key generation and exchange
- AES-256-GCM encryption/decryption
- HMAC-SHA256 signing/verification

**Key Methods**:

**Certificate Operations**:
- `CERT_Import(cert_bytes)`: Load server's public key
- `CERT_Verify(data, signature)`: Verify ECDSA signature
- `CERT_Check(hostname, fingerprint_file)`: TOFU validation
- `CERT_Save(hostname, fingerprint_file)`: Store fingerprint

**TOFU Implementation**:
1. Check if fingerprint file exists
2. If not: Save current certificate (first connection)
3. If exists: Search for matching hostname
4. If hostname not found: Save certificate (new server)
5. If hostname found: Compare certificates
6. Return True if match, False if mismatch

### 4.3 Shared Crypto Methods

Both client and server have identical implementations for:

**X25519**:
- `New_ECC()`: Generate keypair
- `ECC_export_pub_key()`: Export 32-byte public key
- `ECC_import_pub_bytes(pub_key)`: Import peer's public key
- `ECC_calc_key()`: Derive shared secret with HKDF

**AES-CTR**:
- `New_AES(key)`: Initialize AES cipher
- `AES_Encrypt(nonce, msg)`: Encrypt (no padding needed)
- `AES_Decrypt(nonce, ciphertext)`: Decrypt (no padding removal)

**HMAC**:
- `New_HMAC(key)`: Initialize HMAC
- `Sign_HMAC(msg)`: Calculate signature
- `check_HMAC(msg, signature)`: Verify (constant-time)

**Random Generation**:
- `Generate_AES256_key()`: 32 random bytes
- `Generate_HMAC_key()`: 32 random bytes
- `Generate_nonce()`: 16 random bytes (128-bit for CTR)
- `random_bytes(length)`: N random bytes

All use `secrets.token_bytes()` for cryptographically secure randomness.

---

## 5. Security Properties

### 5.1 Perfect Forward Secrecy

**Guaranteed**: Compromise of server's ECDSA certificate does NOT reveal past session keys.

**Reason**: ECDSA signs ephemeral X25519 keys, not session data. Each session uses unique X25519 keypair.

### 5.2 Encrypt-then-MAC

**Design Pattern**: KyloChat follows the **Encrypt-then-MAC** paradigm:
1. Encrypt plaintext with AES-CTR
2. Calculate HMAC over ciphertext
3. Send: ciphertext || HMAC

**Security Benefit**:
- HMAC verification happens BEFORE decryption
- Invalid messages rejected before touching decryption engine
- Protects against padding oracle attacks (though CTR has no padding)
- Protects against chosen-ciphertext attacks

**Why Encrypt-then-MAC?**
- Proven secure construction (compared to MAC-then-encrypt)
- Recommended by cryptographers (Colin Percival, Moxie Marlinspike)
- Used by TLS 1.3, SSH, IPsec

### 5.3 Replay Attack Prevention

**Mechanism**: Unique nonces + HMAC verification

**Nonce uniqueness**: Each message uses fresh 16-byte nonce from secure RNG. Reusing a nonce with CTR mode would catastrophically break security.

**Replay detection**: While protocol doesn't explicitly track nonces, replay attacks are impractical because:
- Nonce collision probability is negligible (2^-128)
- Messages are context-dependent (token validation, state changes)
- Sessions are ephemeral (no long-term state)

### 5.4 MITM Protection

**First line**: ECDSA signature verification prevents impersonation

**Second line**: TOFU detects certificate changes

**Weakness**: Vulnerable to MITM on first connection if user doesn't verify fingerprint independently.

### 5.5 Nonce Reuse Catastrophe (CTR Mode)

**CRITICAL WARNING**: Nonce reuse with CTR mode is catastrophic!

**What happens if nonce is reused**:
- XOR of two ciphertexts reveals XOR of two plaintexts
- Attacker can recover both plaintexts
- Key stream is compromised for those blocks

**Mitigation in KyloChat**:
- Nonces generated from `secrets.token_bytes(16)` (cryptographically secure)
- 128-bit nonce space = 2^128 possible values
- Collision probability negligible even after billions of messages
- No nonce counter (stateless generation)

---

**Next**: [Server Implementation](SERVER.md) for server-side architecture details.
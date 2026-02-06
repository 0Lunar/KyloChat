# KyloChat

<p align="center">
  <img src="https://img.shields.io/badge/license-AGPL%203.0-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/docker-required-blue.svg" alt="Docker">
  <img src="https://img.shields.io/badge/encryption-X25519%20%7C%20AES--256--GCM-green.svg" alt="Encryption">
</p>

<p align="center">
  <strong>Versatile and Secure Chat - Anonymous and Private Communication</strong>
</p>

---

## 🔒 Privacy-First Architecture

KyloChat is an encrypted chat application designed with **absolute privacy** as its core principle. Unlike traditional chat platforms, KyloChat's server **never stores messages or conversation metadata**—communications exist only in volatile memory during active sessions.

### Zero-Knowledge Design
- **No message logging**: Server cannot and does not record conversations
- **No metadata collection**: No timestamps, message sizes, or communication patterns stored
- **Volatile memory only**: Messages discarded immediately after delivery
- **Anonymous by default**: No personal information required

---

## ✨ Key Features

### 🔐 Advanced Cryptography
- **X25519 (ECDH)**: Elliptic curve key exchange with HKDF-SHA256 key derivation
- **AES-256-GCM**: Authenticated encryption with PKCS7 padding
- **HMAC-SHA256**: Independent message authentication layer
- **ECDSA secp256r1**: Server certificate generation and signing
- **Bcrypt**: Secure password hashing with configurable cost factor

### 🛡️ Security Features
- **TOFU (Trust On First Use)**: Certificate fingerprint verification prevents MITM attacks
- **Bcrypt authentication**: Slow hashing protects against brute-force (~100ms per attempt)
- **Rate limiting**: Automatic protection against spam and DoS
- **Token-based sessions**: Secure, expiring authentication tokens (~1 week validity)
- **IP ban system**: Automatic temporary bans for failed login attempts
- **Defense in depth**: Multiple independent security layers

### 🎨 Modern Terminal Interface
- **Textual UI**: Rich, responsive terminal interface built with Textual framework
- **Image support**: Send and display images directly in terminal with automatic resizing
- **Message history**: Scrollable chat with timestamps and user profiles
- **User profiles**: Custom profile pictures in chat
- **Keyboard shortcuts**: Efficient navigation and controls
- **Connection caching**: Remember last server connection automatically

### ⚙️ Operational Features
- **Data compression**: Optional zlib compression reduces bandwidth usage
- **Docker deployment**: One-command server setup with docker-compose
- **Admin commands**: Full user and server management via chat commands
- **Configurable limits**: Message sizes, connection limits, rate limiting all configurable
- **Automatic token caching**: Auto-login on reconnection if token valid
- **Session persistence**: Exit chat without logout to maintain session

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Administrator Commands](#administrator-commands)
- [Configuration](#configuration)
- [Security](#security)
- [Documentation](#documentation)
- [License](#license)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (TUI)                         │
│  ┌────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │  Textual   │  │  CryptoHandler │  │  Certificate   │     │
│  │    UI      │──│                │──│   Validator    │     │
│  │            │  │  • X25519      │  │   (TOFU)       │     │
│  │            │  │  • AES-GCM     │  │                │     │
│  │            │  │  • HMAC        │  │                │     │
│  │            │  │  • Cert Verify │  │                │     │
│  └────────────┘  └────────────────┘  └────────────────┘     │
│         │               │                    │              │
│         └───────────────┴────────────────────┘              │
│                         │                                   │
│                  TCP/IP Socket                              │
│                         │                                   │
└─────────────────────────┼───────────────────────────────────┘
                          │
                Encrypted Channel
        (X25519 + AES-256-GCM + HMAC)
                          │
┌─────────────────────────┼───────────────────────────────────┐
│                         │          SERVER                   │
│                    TCP Listener                             │
│                         │                                   │
│  ┌──────────────────────┴───────────────────┐               │
│  │      Connection Handler (Thread Pool)    │               │
│  │  ┌─────────────┐  ┌──────────────────┐   │               │
│  │  │CryptoHandler│  │   Authentication │   │               │
│  │  │             │──│     Handler      │   │               │
│  │  │• X25519     │  │   • Bcrypt       │   │               │
│  │  │• AES-GCM    │  │   • Token Mgmt   │   │               │
│  │  │• HMAC       │  │                  │   │               │
│  │  │• Cert Sign  │  │                  │   │               │
│  │  │• Bcrypt     │  │                  │   │               │
│  │  └─────────────┘  └──────────────────┘   │               │
│  │          │                  │            │               │
│  │  ┌───────┴──────────────────┴───────┐    │               │
│  │  │      Message Router/Broadcaster  │    │               │
│  │  └──────────────┬───────────────────┘    │               │
│  └─────────────────┼────────────────────────┘               │
│                    │                                        │
│  ┌─────────────────┼────────────────────────┐               │
│  │         Database Manager (MariaDB)       │               │
│  │  - User credentials (bcrypt)             │               │
│  │  - Token management                      │               │
│  │  - Ban/admin status                      │               │
│  └──────────────────────────────────────────┘               │
│                                                             │
│  ⚠️  NO MESSAGE STORAGE - All chat data in memory only      │
└─────────────────────────────────────────────────────────────┘
```

### Communication Flow

1. **Handshake** (Cryptographic Setup)
   - X25519 key exchange (32-byte public keys)
   - Server signs public key with ECDSA certificate
   - Client verifies signature (TOFU)
   - Both derive shared secret via HKDF-SHA256
   - Client sends encrypted HMAC key + session AAD

2. **Authentication**
   - Username/password validation (bcrypt, ~100ms)
   - Token generation (UUID v4, 36 chars)
   - Token stored in database with expiration
   - Token cached on client for auto-login

3. **Messaging**
   - Each message: `[Type(1)] + [Nonce(12) + AES-GCM(Token+Data)] + [HMAC(32)]`
   - PKCS7 padding applied before encryption
   - Real-time broadcast to all connected clients
   - Optional zlib compression for large messages

---

## 🚀 Quick Start

### Prerequisites

**Client:**
- Python 3.8+
- pip package manager
- Terminal with UTF-8 and color support

**Server:**
- Docker 20.10+
- Docker Compose 2.0+
- 1GB disk space minimum

### Client Setup

```bash
# Clone repository
git clone https://github.com/0lunar/KyloChat.git
cd KyloChat/client

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip3 install -r requirements.txt

# Run client
python3 cli.py
```

### Server Setup

```bash
cd KyloChat/server

# Create .env file with secure passwords
cat > .env << EOF
DB_ROOT_PASSWORD=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)
# Optional: CERT_PASSWD=your_certificate_password
EOF

# Start server with Docker Compose
docker compose up --build -d

# View logs
docker compose logs -f kylochat-server
```

**Default credentials:**
- Admin: `admin` / `admin` ⚠️ **Change immediately in production!**
- Guest: `guest` / `test`

---

## 💬 Usage

### Connecting to Server

1. Start the client: `python3 cli.py`
2. Enter server IP (e.g., `127.0.0.1` for local, or domain name)
3. Enter port (default: `5000`)
4. **First connection**: Server certificate saved automatically (TOFU)
5. **Subsequent connections**: Certificate verified against saved fingerprint
6. Login with username and password

### Chat Interface

- **Send message**: Type and press Enter
- **Send image**: Click "Menu" button (or Ctrl+P) → "Send image"
- **Enable compression**: Menu → "Enable compression"
- **Clear chat**: Menu → "Clear chat"
- **Exit**: Menu → "Exit chat" (saves token for auto-login)
- **Logout**: Menu → "Logout" (removes token, requires re-login)

### Keyboard Shortcuts

- `Ctrl+P`: Open menu
- `Escape`: Close dialogs
- `Tab`: Navigate between fields
- `Ctrl+C`: Quit application

---

## 🔑 Administrator Commands

Administrators can execute commands by typing them in the chat:

| Command | Description | Example |
|---------|-------------|---------|
| `/help` | Display all available commands | `/help` |
| `/user_id <username>` | Get user ID by username | `/user_id alice` |
| `/ban <user_id>` | Ban a user from the server | `/ban 5` |
| `/unban <user_id>` | Remove ban from user | `/unban 5` |
| `/isAdmin <user_id>` | Check if user has admin privileges | `/isAdmin 3` |
| `/isBanned <user_id>` | Check if user is banned | `/isBanned 5` |
| `/usrpw <user_id> <new_password>` | Change user password | `/usrpw 5 NewPass123!` |
| `/lsip` | List all connected IP addresses | `/lsip` |
| `/mkusr <user> <pass> <email> <admin>` | Create new user | `/mkusr bob Pass123! bob@ex.com false` |
| `/rvktk <token>` | Revoke authentication token | `/rvktk 550e8400-...` |
| `/rmtk <token>` | Permanently delete token | `/rmtk 550e8400-...` |
| `/showtk <limit>` | Show active tokens (limited) | `/showtk 10` |
| `/lsusers` | List all users in database | `/lsusers` |

---

## ⚙️ Configuration

Server configuration is managed via `config.toml`:

```toml
[Address]
ip_address = '0.0.0.0'  # Listen on all interfaces
port = 5000             # Server port

[Logging]
log_dir = 'logs'
log_file = 'chatserver.log'

[Authentication]
login_attempts = 4      # Max failed login attempts before ban
ban_on_fail = true      # Enable automatic banning
ban_time = 10           # Ban duration in seconds

[Security]
rate_limit = 5              # Max messages per second
rate_limit_sleep = 5000     # Pause duration after rate limit (ms)
max_message_size = 250      # Max text message size (bytes)
max_image_size = 250_000    # Max image size (250 KB)
slow_down = 0               # Artificial delay between operations (ms)
max_conns = 0               # Max simultaneous connections (0 = unlimited)
max_conn_errors = 4         # Max errors before disconnection
sleep_on_full_conns = 100   # Pause when max connections reached (ms)
certificate = 'cert.pem'    # ECDSA certificate path
whitelist = []              # IP whitelist (empty = allow all)
blacklist = []              # IP blacklist
```

### Production Recommendations

**Critical Security Settings:**
```toml
[Authentication]
ban_time = 3600  # 1 hour instead of 10 seconds!

[Security]
rate_limit = 3              # More restrictive
max_message_size = 1024     # 1 KB (increase from 250 bytes)
max_image_size = 1048576    # 1 MB (increase from 250 KB)
max_conns = 50              # Limit connections to prevent DoS
```

**Environment Variables:**
- `CERT_PASSWD`: Password to encrypt server certificate (optional but recommended)
- `DB_ROOT_PASSWORD`: MariaDB root password
- `DB_PASSWORD`: Application database password

---

## 🔐 Security

### Cryptographic Stack

**Key Exchange:**
- X25519 ECDH (Curve25519)
- HKDF-SHA256 for key derivation
- Perfect Forward Secrecy (unique keys per session)

**Encryption:**
- AES-256-GCM (authenticated encryption)
- PKCS7 padding for block alignment
- 96-bit nonces (cryptographically random)
- 16-byte session AAD for context binding

**Authentication:**
- HMAC-SHA256 (independent of AES-GCM)
- Constant-time comparison prevents timing attacks
- 32-byte signatures

**Certificate Security:**
- ECDSA secp256r1 (NIST P-256)
- SHA-256 hashing
- Optional password protection (BestAvailableEncryption)
- OpenSSH format for compatibility

**Password Security:**
- Bcrypt with cost factor 12 (2^12 = 4096 iterations)
- Random salts per password
- ~100ms computation time (anti-brute-force)

### What is NOT Stored

KyloChat guarantees these data are **NEVER** saved:

- ❌ Message content (text or images)
- ❌ Message metadata (timestamps, sizes, sender/receiver)
- ❌ Conversation histories
- ❌ Session information beyond authentication tokens
- ❌ User activity logs (except system events)

### What IS Stored (Minimal)

Only essential authentication data:

- ✅ Usernames and bcrypt password hashes
- ✅ Email addresses (for account recovery)
- ✅ Authentication tokens (UUID with expiration)
- ✅ Admin and ban status flags
- ✅ Server logs (system events only, no message content)

### Database Schema

```sql
-- User accounts
CREATE TABLE users(
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(60),
    email VARCHAR(120),
    banned BOOLEAN DEFAULT false,
    admin BOOLEAN DEFAULT false
);

-- Password hashes (bcrypt)
CREATE TABLE credentials(
    CredID INT AUTO_INCREMENT PRIMARY KEY,
    user INT,
    password VARCHAR(60),  -- $2b$12$... format
    FOREIGN KEY (user) REFERENCES users(UserID)
);

-- Session tokens
CREATE TABLE tokens(
    TokenID INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(36) NOT NULL UNIQUE,  -- UUID
    user INT,
    expire DATETIME,
    revoked BOOL,
    FOREIGN KEY (user) REFERENCES users(UserID)
);
```

### TOFU (Trust On First Use)

Certificate verification workflow:

1. **First Connection**: Server certificate automatically saved to `.cache/fingers.pub`
2. **Subsequent Connections**: Certificate compared with saved version
3. **Certificate Change**: Connection aborted (possible MITM attack!)

Format in `.cache/fingers.pub`:
```
192.168.1.100:5000 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...
```

---

## 📚 Documentation

Complete documentation is available in the `docs/` directory:

- **[Technical Documentation](docs/TECHNICAL.md)**: Detailed architecture, cryptography protocols, and implementation (coming soon)
- **[API Reference](docs/API.md)**: Protocol specification for developers (coming soon)
- **[Deployment Guide](docs/DEPLOYMENT.md)**: Production setup and best practices (coming soon)
- **[Security Analysis](docs/SECURITY.md)**: Threat model and security guarantees (coming soon)

---

## 📜 License

KyloChat is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means:
- ✅ Free to use, modify, and distribute
- ✅ Source code must remain open
- ✅ Network use requires making source available to users
- ✅ Modifications must use the same license

See [LICENSE](LICENSE) for full details.

---

## 🌟 Why KyloChat?

### Privacy-First Design
Unlike mainstream platforms, KyloChat is built from the ground up with privacy as the **core feature**, not an afterthought.

### Open and Auditable
Fully open-source under AGPL-3.0. Anyone can verify there are no backdoors or hidden data collection.

### Self-Hosted
Run your own server with complete control over your data and communications.

### Modern Cryptography
Uses state-of-the-art encryption recommended by security experts:
- X25519 (used in Signal, WireGuard)
- AES-256-GCM (used in TLS 1.3)
- HKDF-SHA256 (NIST recommended)
- Bcrypt (industry standard for passwords)

### Comparison with Other Platforms

| Feature | KyloChat | WhatsApp | Telegram | Signal |
|---------|----------|----------|----------|--------|
| **Open Source** | ✅ Full | ❌ No | ⚠️ Partial | ✅ Yes |
| **Server Stores Messages** | ❌ Never | ✅ Yes (backups) | ✅ Yes | ❌ No |
| **Self-Hosting** | ✅ Easy | ❌ No | ❌ No | ⚠️ Complex |
| **Metadata Collection** | ❌ Minimal | ✅ Extensive | ✅ Extensive | ⚠️ Some |
| **E2E Encryption** | ✅ Always | ✅ Default | ⚠️ Optional | ✅ Always |
| **Phone Number Required** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **Perfect Forward Secrecy** | ✅ Yes | ✅ Yes | ⚠️ Optional | ✅ Yes |

---

## 🙏 Acknowledgments

KyloChat is built with:
- [Textual](https://github.com/Textualize/textual) - Terminal UI framework
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [cryptography](https://cryptography.io/) - Cryptographic primitives (Python)
- [MariaDB](https://mariadb.org/) - Database
- [Docker](https://www.docker.com/) - Containerization
- [bcrypt](https://github.com/pyca/bcrypt/) - Password hashing

---

<p align="center">
  <strong>Built with ❤️ for privacy and security</strong><br>
  <a href="https://github.com/0lunar/KyloChat">⭐ Star on GitHub</a>
</p>
# KyloChat - Technical Documentation Index

**Version**: 1.0  
**Last Updated**: 2025-02-06  
**Total Codebase**: ~4,135 lines of Python  
**Repository**: https://github.com/0lunar/KyloChat

---

## 📚 Documentation Overview

This technical documentation provides comprehensive coverage of KyloChat's architecture, implementation, and deployment. The documentation is organized into modular sections for easy navigation and reference.

### Target Audience

- **Developers**: Looking to understand, modify, or extend KyloChat
- **Security Researchers**: Analyzing the cryptographic implementation and security model
- **System Administrators**: Deploying and maintaining KyloChat in production
- **Contributors**: Contributing code, fixes, or improvements to the project

---

## 📖 Documentation Structure

### 1. [Architecture](ARCHITECTURE.md)
**Purpose**: High-level system design and component interaction

**Topics Covered**:
- System architecture overview with visual diagrams
- Client-server communication model
- Threading and concurrency model
- Component responsibilities and data flow
- Session management architecture

**When to Read**: Start here to understand the overall system design before diving into implementation details.

---

### 2. [Server Implementation](SERVER.md)
**Purpose**: Detailed server-side implementation details

**Topics Covered**:
- Main server loop and connection handling
- SocketHandler wrapper with encryption integration
- Thread-safe ConnectionsHandler for session management
- Authentication system (standard + token-based)
- Message routing and broadcasting
- Admin command processing
- Rate limiting and security measures
- Configuration system (config.toml)

**When to Read**: When implementing server-side features, debugging server issues, or understanding message flow.

---

### 3. [Client Implementation](CLIENT.md)
**Purpose**: Client application architecture and UI implementation

**Topics Covered**:
- Textual TUI architecture (733 lines)
- Screen navigation flow (Connection → Login → Chat)
- Message receiver thread and UI updates
- Connection and token caching
- Image handling with automatic resizing
- Client-side encryption and handshake
- User interaction patterns

**When to Read**: When developing client features, customizing the UI, or understanding client-side security.

---

### 4. [Cryptography & Protocol](CRYPTOGRAPHY.md)
**Purpose**: Cryptographic implementation and wire protocol specification

**Topics Covered**:
- X25519 (ECDH) key exchange with HKDF
- AES-256-GCM authenticated encryption with PKCS7 padding
- HMAC-SHA256 independent authentication
- ECDSA certificate generation and verification
- TOFU (Trust On First Use) certificate validation
- Bcrypt password hashing
- Complete handshake sequence
- Message structure and wire format
- Length-prefixed protocol specification

**When to Read**: When auditing security, implementing protocol changes, or understanding the cryptographic guarantees.

---

### 5. [Database Design](DATABASE.md)
**Purpose**: Database schema and data management

**Topics Covered**:
- Complete SQL schema (users, credentials, tokens)
- Table relationships and foreign keys
- Database operations and query patterns
- Token lifecycle management
- Privacy guarantees and data retention
- Database breach impact analysis

**When to Read**: When managing user data, implementing admin features, or understanding privacy guarantees.

---

### 6. [Security Model](SECURITY.md)
**Purpose**: Security architecture, threat model, and attack resistance

**Topics Covered**:
- Threat model and assumptions
- Perfect forward secrecy explanation
- Defense in depth strategy
- Attack resistance analysis (MITM, replay, tampering, etc.)
- Rate limiting and anti-abuse mechanisms
- Login attempt tracking and IP banning
- Security recommendations for production

**When to Read**: When performing security audits, hardening deployments, or assessing security posture.

---

### 7. [Deployment Guide](DEPLOYMENT.md)
**Purpose**: Production deployment and operational procedures

**Topics Covered**:
- Docker containerization architecture
- docker-compose.yml configuration
- Environment variables and secrets
- Network configuration and port mapping
- Volume management for persistence
- Production hardening recommendations
- Monitoring and logging
- Backup and recovery procedures

**When to Read**: When deploying KyloChat to production, configuring infrastructure, or troubleshooting deployment issues.

---

## 🚀 Quick Start Guide

### For Developers
1. Start with **[Architecture](ARCHITECTURE.md)** to understand the system design
2. Read **[Cryptography & Protocol](CRYPTOGRAPHY.md)** to understand the wire protocol
3. Dive into **[Server Implementation](SERVER.md)** or **[Client Implementation](CLIENT.md)** based on your focus

### For Security Researchers
1. Begin with **[Security Model](SECURITY.md)** for the threat model
2. Study **[Cryptography & Protocol](CRYPTOGRAPHY.md)** for cryptographic details
3. Review **[Database Design](DATABASE.md)** for privacy guarantees

### For System Administrators
1. Start with **[Deployment Guide](DEPLOYMENT.md)** for setup instructions
2. Review **[Security Model](SECURITY.md)** for hardening recommendations
3. Reference **[Server Implementation](SERVER.md)** for configuration options

---

## 📊 Project Metrics

| Component | Lines of Code | File |
|-----------|---------------|------|
| **Server Core** | 462 | server.py |
| **Client UI** | 733 | tui.py |
| **Server Socket Handler** | 355 | server/core/HandleConnection.py |
| **Client Socket Handler** | ~355 | client/core/HandleConnection.py |
| **Server Crypto** | 275 | server/core/CryptoHandler.py |
| **Client Crypto** | 226 | client/core/CryptoHandler.py |
| **Session Management** | 270 | server/core/ConnectionsHandler.py |
| **Authentication** | 92 | server/core/Login.py |
| **Total** | **~4,135** | Complete codebase |

---

## 🔑 Key Concepts

### Architecture
- **Threading Model**: One thread per connection (daemon threads)
- **Session Management**: Thread-safe with RLock, multiple indexes (session_id, username, host)
- **Message Flow**: Unencrypted type byte → encrypted length-prefixed payload → broadcast

### Cryptography
- **Key Exchange**: X25519 ECDH with HKDF-SHA256 key derivation
- **Encryption**: AES-256-GCM with PKCS7 padding and 96-bit nonces
- **Authentication**: Dual-layer (GCM tag + HMAC-SHA256)
- **Certificates**: ECDSA P-256 for server identity, TOFU for MITM protection

### Database
- **Tables**: 3 tables (users, credentials, tokens)
- **Privacy**: Zero message storage, only authentication data
- **Passwords**: Bcrypt hashed (cost factor 12, ~100ms per verification)
- **Tokens**: UUID v4 with 7-day expiration

### Deployment
- **Containerization**: Docker with docker-compose orchestration
- **Services**: 2 containers (kylochat-server + mariadb)
- **Network**: Bridge network with ICC enabled
- **Ports**: Host 53900 → Container 5000

---

## 🛠️ Technology Stack

### Server
- **Language**: Python 3.8+
- **Database**: MariaDB 11.4
- **Containerization**: Docker + Docker Compose
- **Concurrency**: threading module (thread-per-connection)

### Client
- **Language**: Python 3.8+
- **UI Framework**: Textual (terminal UI)
- **Image Processing**: Pillow (PIL)
- **Terminal Rendering**: Rich

### Shared Libraries
- **Cryptography**: cryptography library (X25519, AES-GCM, ECDSA, HMAC)
- **Password Hashing**: bcrypt
- **Compression**: zlib

---

## 📝 Documentation Conventions

### Code Examples
Code snippets are provided to illustrate concepts, not as complete implementations. Refer to the actual source code for full implementations.

### Diagrams
ASCII diagrams are used throughout to visualize:
- Architecture and data flow
- Protocol sequences
- Message structures
- Threading models

### File References
File paths are relative to the project root:
```
KyloChat/
├── server/
│   ├── server.py
│   └── core/
└── client/
    └── core/
```

---

## 🔗 Related Resources

- **Main README**: [README.md](../README.md) - Project overview and quick start
- **License**: [LICENSE](../LICENSE) - AGPL-3.0 license details
- **Source Code**: [GitHub Repository](https://github.com/0lunar/KyloChat)

---

## 📞 Support

For questions or issues:
- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions or discuss ideas
- **Security Issues**: Report privately (see SECURITY.md)

---

**Next Steps**: Choose a documentation section from the list above based on your needs.
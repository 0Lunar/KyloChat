# KyloChat

[![Top language](https://img.shields.io/github/languages/top/0Lunar/KyloChat.svg)](https://github.com/0Lunar/KyloChat)
[![License](https://img.shields.io/github/license/0Lunar/KyloChat.svg)](https://github.com/0Lunar/KyloChat/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/0Lunar/KyloChat.svg?style=social)](https://github.com/0Lunar/KyloChat)
[![Forks](https://img.shields.io/github/forks/0Lunar/KyloChat.svg?style=social)](https://github.com/0Lunar/KyloChat/network)
[![Open issues](https://img.shields.io/github/issues/0Lunar/KyloChat.svg)](https://github.com/0Lunar/KyloChat/issues)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

KyloChat is an encrypted, lightweight chat designed for maximum versatility and user anonymity. It consists of a Dockerized server and a terminal-based client. The project aims to provide secure, private communication while keeping the system small and easy to deploy.

## Key features
- End-to-end encryption with client-side cryptographic operations to protect user privacy.
- Minimal, lightweight design with a terminal (CLI) client.
- Strong focus on user anonymity — the server should not require identifying information beyond the credentials needed to authenticate.
- Simple installation: client via Python requirements, server via Docker Compose.
- Docker images and Dockerfiles are provided and preconfigured.

## Cryptography (protocol overview)
KyloChat implements a hybrid cryptographic handshake and per-message authenticated encryption as follows:

Handshake
- Certificate validation and key signing with **ECDSA secp256r1**
- **TOFU** (_Trust On First Use_) and **OpenSSH-style** certificate **fingerprinting**
- Key exchange with **x25519 - ECDH**
- **HKDF** (Key Derivation) with SHA256
- **AES256-GCM** block cipher
- Message signing with **HMAC-SHA256**

Per-message format
- Each message payload sent from client to server is:
  - **nonce** = AES256-GCM nonce (12 bytes)
  - **cipher** = AES256-GCM encrypt(token + message)
  - **tag** = HMAC-SHA256(cipher)
  - **Final payload** = nonce || cipher || tag
- The HMAC covers the ciphertext to provide integrity and authenticity.

## Privacy
- KyloChat is designed so that message contents are not stored on the server.
- The server persists only:
  - User records (registered users)
  - IP addresses observed at login
  - The size of each message sent by each user
  - Example: `27 bytes received from user1 ('34.26.87.21', 12734)`
- No message plaintexts are written to storage by default.

## Authentication & session tokens
- User accounts are stored in MariaDB. Passwords are hashed with bcrypt before storage.
- On successful login the server issues a session token (UUIDv4) for the user.
- The token is used by the client for every message. Tokens are included in the message plaintext that gets encrypted (token + message) before AES encryption.
- Token lifetime: maximum 1 week. After expiration the client must re-authenticate (to mitigate token hijacking).
- Login attempts: the server accepts up to 4 failed login attempts per connection. After the 4th failure the server closes the connection.

## Requirements
- Python 3.x (recommended: 3.8+)
- pip
- Docker & Docker Compose (for running the server)
- MariaDB (provided/managed via Docker Compose in the repository)

## Installation

### Client (local)
1. Ensure Python and pip are installed.
2. From the repository root, install dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

### Server (Docker)
1. Ensure Docker and Docker Compose are installed and running.
2. Start the server:
   ```bash
   docker compose up --build
   ```
   All server environment variables and defaults are defined in `docker-compose.yml`.

## Configuration
- Server environment variables (ports, DB credentials, etc.) are set in `docker-compose.yml`. Edit that file to change settings.
- Ensure secure handling of secrets (do not commit production passwords or keys to git).
- If you need persistent MariaDB storage, configure volumes in `docker-compose.yml`.
- Server configuration in `server/config.toml` with **Security**, **Authentication** and other Features...

## Usage

### Start the server
From the repository directory:
```bash
docker compose up --build
```

### Start the client (CLI)
Run:
```bash
python3 cli.py
```
On startup the client will prompt for:
1. Server IP (or hostname)
2. Server port
3. Server credentials (as configured on the server)

The client then performs the cryptographic handshake (x25519/AES/HMAC) and attempts to authenticate. If both succeed, you can start chatting.

## Troubleshooting
- Connection refused:
  - Verify IP/port entered in the client.
  - Ensure the server container is running (`docker ps`) and the port is exposed.
  - Check firewall or network restrictions.
- Python dependency errors:
  - Recreate the virtual environment and reinstall dependencies:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip3 install -r requirements.txt
    ```
- Docker Compose issues:
  - Update Docker and Docker Compose to the latest versions and retry `docker compose up --build`.

## License
This project is licensed under the GNU AGPL v3.0. See the `LICENSE` file for details or visit the official page: [GNU AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html).
# KyloChat - Deployment Guide

**Document**: Production Deployment and Operations  
**Version**: 1.0  
**Last Updated**: 2025-02-06

---

## Table of Contents

1. [Docker Architecture](#1-docker-architecture)
2. [Deployment Steps](#2-deployment-steps)
3. [Configuration](#3-configuration)
4. [Production Hardening](#4-production-hardening)
5. [Monitoring & Maintenance](#5-monitoring--maintenance)

---

## 1. Docker Architecture

### 1.1 Container Overview

KyloChat runs as two containers orchestrated by docker-compose:

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Host                             │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  kylochat_net (Bridge Network)                       │   │
│  │                                                      │   │
│  │  ┌────────────────────────┐  ┌────────────────────┐  │   │
│  │  │  KyloChat_Server       │  │  KyloChat_Database │  │   │
│  │  │                        │  │                    │  │   │
│  │  │  • Python 3.11         │  │  • MariaDB 11.4    │  │   │
│  │  │  • server.py           │  │  • KyloChatDB      │  │   │
│  │  │  • Port 5000 (internal)│  │  • Port 3306       │  │   │
│  │  │                        │  │    (internal only) │  │   │
│  │  └───────────┬────────────┘  └────────┬───────────┘  │   │
│  │              │                        │              │   │
│  └──────────────┼────────────────────────┼──────────────┘   │
│                 │                        │                  │
│  ┌──────────────▼──────────┐   ┌─────────▼────────────┐     │
│  │  Port Mapping           │   │  Volume Mounts       │     │
│  │  53900:5000             │   │  • init.sql (ro)     │     │
│  └─────────────────────────┘   │  • db_data (rw)      │     │
│                                │  • config.toml (ro)  │     │
│                                │  • logs (rw)         │     │
│                                └──────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 docker-compose.yml Breakdown

**Complete configuration**:
```yaml
services:
  kylo_chat:
    container_name: KyloChat_Server
    build: .                          # Uses Dockerfile in project root
    restart: unless-stopped           # Auto-restart on failure
    depends_on:
      - db                            # Wait for database
    networks:
      - kylochat_net
    environment:
      CHAT_DB_HOST: db                # Database hostname (container name)
      CHAT_DB_USER: root              # Database username
      CHAT_DB_PASSWD: root            # ⚠️ Change in production!
      CHAT_DB_NAME: KyloChatDB        # Database name
      CERT_PASSWD: password-for-cert  # ⚠️ Change in production!
    ports:
      - "53900:5000/tcp"              # Host:Container port mapping
  
  db:
    container_name: KyloChat_Database
    image: mariadb:11.4               # Official MariaDB image
    networks:
      - kylochat_net
    environment:
      MARIADB_ROOT_PASSWORD: root     # ⚠️ Change in production!
      MARIADB_DATABASE: KyloChatDB    # Auto-create database
    volumes:
      - "./server/database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro"
      - "./db_data:/var/lib/mysql:rw"

networks:
  kylochat_net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"          # Inter-container
      com.docker.network.bridge.enable_ip_masquerade: "true" # NAT
      com.docker.network.bridge.host_binding_ipv4: "0.0.0.0"
```

### 1.3 Environment Variables

All environment configuration is in docker-compose.yml:

**Server Container**:
- `CHAT_DB_HOST`: Database hostname (use container name: `db`)
- `CHAT_DB_USER`: Database username (default: `root`)
- `CHAT_DB_PASSWD`: Database password ⚠️ **CHANGE IN PRODUCTION**
- `CHAT_DB_NAME`: Database name (default: `KyloChatDB`)
- `CERT_PASSWD`: ECDSA certificate password ⚠️ **CHANGE IN PRODUCTION**

**Database Container**:
- `MARIADB_ROOT_PASSWORD`: Root password ⚠️ **CHANGE IN PRODUCTION**
- `MARIADB_DATABASE`: Auto-create this database on first run

### 1.4 Volume Mounts

**Read-Only Mounts**:
- `./server/database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro`
  - SQL initialization script
  - Creates tables and default users
  - Runs only on first database initialization

**Read-Write Mounts**:
- `./db_data:/var/lib/mysql:rw`
  - MariaDB data directory
  - Persists database across container restarts
  - **CRITICAL**: Backup this directory regularly

**Implicit Mounts** (via Dockerfile):
- `./server/config.toml:/app/config.toml`
- `./server/logs:/app/logs`

---

## 2. Deployment Steps

### 2.1 Prerequisites

**System Requirements**:
- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- 1GB free disk space minimum
- Port 53900 available on host

**Check versions**:
```bash
docker --version
docker compose version  # Note: no hyphen in v2
```

### 2.2 Quick Deployment

**Step 1: Clone repository**
```bash
git clone https://github.com/0lunar/KyloChat.git
cd KyloChat
```

**Step 2: ⚠️ CRITICAL - Change default passwords**

Edit `docker-compose.yml`:
```yaml
# Server environment
CHAT_DB_PASSWD: <strong-random-password>
CERT_PASSWD: <strong-random-password>

# Database environment
MARIADB_ROOT_PASSWORD: <strong-random-password>
```

Generate strong passwords:
```bash
# Linux/macOS
openssl rand -base64 32

# Or use a password manager
```

**Step 3: Build and start containers**
```bash
docker compose up --build -d
```

**Step 4: Verify deployment**
```bash
# Check containers are running
docker compose ps

# Should show:
# KyloChat_Server    running   0.0.0.0:53900->5000/tcp
# KyloChat_Database  running

# Check logs
docker compose logs -f kylo_chat
```

**Step 5: Test connection**
```bash
# From another machine or same host
python3 client/cli.py

# Connect to: <host-ip>:53900
# Login: admin / admin  (⚠️ change immediately!)
```

### 2.3 First-Time Setup

**After deployment, immediately**:

1. **Change admin password**:
   - Connect as admin
   - Use command: `/usrpw 1 NewSecurePassword123!`
   - Disconnect and test new password

2. **Create regular users**:
   ```
   /mkusr alice SecurePass1! alice@example.com false
   /mkusr bob SecurePass2! bob@example.com false
   ```

3. **Delete or disable guest user**:
   - Connect as admin
   - Ban guest: `/ban 2`

4. **Verify security settings**:
   ```bash
   cat server/config.toml
   # Check rate_limit, max_conns, ban_time
   ```

---

## 3. Configuration

### 3.1 Server Configuration (config.toml)

**Location**: `server/config.toml` (mounted into container)

**Production Settings**:
```toml
[Address]
ip_address = '0.0.0.0'  # Listen on all interfaces
port = 5000              # Internal container port

[Logging]
log_dir = 'logs'
log_file = 'chatserver.log'

[Authentication]
login_attempts = 3       # Reduce from 4 to 3
ban_on_fail = true
ban_time = 3600          # 1 hour instead of 10 seconds!

[Security]
rate_limit = 3           # Reduce from 5 to 3 msg/s
rate_limit_sleep = 5000  # 5 second cooldown
max_message_size = 1024  # Increase from 250 to 1 KB
max_image_size = 1048576 # Increase from 250KB to 1 MB
slow_down = 0
max_conns = 100          # Limit connections (0 = unlimited)
max_conn_errors = 4
sleep_on_full_conns = 100
certificate = 'cert.pem'
whitelist = []           # Empty = allow all
blacklist = []           # Add IPs to block: ['1.2.3.4', '5.6.7.8']
```

**After changing config.toml**:
```bash
docker compose restart kylo_chat
```

### 3.2 Port Configuration

**Default**: Host port 53900 → Container port 5000

**To change host port**, edit docker-compose.yml:
```yaml
ports:
  - "8080:5000/tcp"  # Now accessible on host:8080
```

**⚠️ Do NOT change container port (5000)** - it's hardcoded in config.toml.

### 3.3 Database Configuration

**Connection parameters** (in docker-compose.yml):
```yaml
CHAT_DB_HOST: db        # Use container name for networking
CHAT_DB_USER: root      # Can create separate user for better security
CHAT_DB_NAME: KyloChatDB
```

**To create dedicated database user**:
```bash
docker compose exec db mysql -uroot -p

# In MySQL prompt:
CREATE USER 'kylochat'@'%' IDENTIFIED BY 'strong-password';
GRANT ALL ON KyloChatDB.* TO 'kylochat'@'%';
FLUSH PRIVILEGES;
exit

# Update docker-compose.yml:
CHAT_DB_USER: kylochat
CHAT_DB_PASSWD: strong-password

# Restart
docker compose restart kylo_chat
```

---

## 4. Production Hardening

### 4.1 Security Checklist

**Before going to production**:

- [ ] Change ALL default passwords in docker-compose.yml
- [ ] Change admin user password via `/usrpw` command
- [ ] Disable or remove guest user
- [ ] Set `ban_time = 3600` (1 hour) in config.toml
- [ ] Set `max_conns = 100` or appropriate limit
- [ ] Set `rate_limit = 3` (more restrictive)
- [ ] Configure firewall to allow only port 53900
- [ ] Enable automatic backups of `db_data/` directory
- [ ] Set up log rotation for `server/logs/`
- [ ] Review and configure whitelist/blacklist if needed

### 4.2 Firewall Configuration

**Using UFW (Ubuntu/Debian)**:
```bash
# Deny all incoming by default
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (if managing remotely)
sudo ufw allow 22/tcp

# Allow KyloChat
sudo ufw allow 53900/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

**Using firewalld (RHEL/CentOS)**:
```bash
sudo firewall-cmd --permanent --add-port=53900/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
```

### 4.3 TLS/SSL Termination

KyloChat uses application-layer encryption (X25519 + AES-GCM), but you can add TLS for defense in depth:

**Option 1: nginx reverse proxy**
```nginx
upstream kylochat {
    server localhost:53900;
}

server {
    listen 443 ssl;
    server_name chat.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://kylochat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Option 2: Cloudflare Tunnel** (easiest)
- Zero-trust tunnel
- No port forwarding needed
- Automatic TLS
- DDoS protection included

### 4.4 Secrets Management

**Never commit secrets to git**:
```bash
# Add to .gitignore
echo "docker-compose.yml" >> .gitignore
echo "db_data/" >> .gitignore
echo "server/cert.pem" >> .gitignore
```

**Use environment files** (optional):
```bash
# Create .env
cat > .env << EOF
DB_ROOT_PASSWORD=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 32)
CERT_PASSWORD=$(openssl rand -base64 32)
EOF

# Reference in docker-compose.yml
environment:
  CHAT_DB_PASSWD: ${DB_PASSWORD}
  CERT_PASSWD: ${CERT_PASSWORD}
```

---

## 5. Monitoring & Maintenance

### 5.1 Log Management

**View real-time logs**:
```bash
# All services
docker compose logs -f

# Server only
docker compose logs -f kylo_chat

# Database only
docker compose logs -f db

# Last 100 lines
docker compose logs --tail=100 kylo_chat
```

**Log files location**:
- Container: `/app/logs/chatserver.log`
- Host: `./server/logs/chatserver.log`

**Log rotation** (recommended):
```bash
# /etc/logrotate.d/kylochat
/path/to/KyloChat/server/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0644 root root
}
```

### 5.2 Monitoring Commands

**Container status**:
```bash
docker compose ps
docker stats kylo_chat db
```

**Resource usage**:
```bash
# Memory
docker stats --no-stream kylo_chat

# Disk usage
docker system df
du -sh ./db_data
```

**Active connections** (requires shell access):
```bash
docker compose exec kylo_chat python3 -c "
from core import ConnHandler
h = ConnHandler()
print(f'Connections: {h.count()}')
print(f'Users: {h.get_all_usernames()}')
"
```

**Database queries**:
```bash
docker compose exec db mysql -uroot -p -e "
USE KyloChatDB;
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM tokens;
SELECT username, banned, admin FROM users;
"
```

### 5.3 Backup & Recovery

**Database backup**:
```bash
# Backup
docker compose exec db mysqldump -uroot -p KyloChatDB > backup_$(date +%Y%m%d).sql

# Or backup data directory (simpler)
sudo tar -czf db_backup_$(date +%Y%m%d).tar.gz db_data/

# Restore from SQL dump
docker compose exec -T db mysql -uroot -p KyloChatDB < backup_20250206.sql

# Restore from data directory
docker compose down
sudo rm -rf db_data/
sudo tar -xzf db_backup_20250206.tar.gz
docker compose up -d
```

**Automated backups** (cron example):
```bash
# Add to crontab: crontab -e
0 2 * * * /path/to/backup-script.sh

# backup-script.sh
#!/bin/bash
cd /path/to/KyloChat
tar -czf /backups/kylochat_$(date +\%Y\%m\%d).tar.gz db_data/
find /backups -name "kylochat_*.tar.gz" -mtime +30 -delete
```

### 5.4 Updates & Maintenance

**Update KyloChat**:
```bash
# Pull latest code
git pull origin main

# Rebuild and restart
docker compose up --build -d

# Verify
docker compose logs -f kylo_chat
```

**Update MariaDB**:
```bash
# Change version in docker-compose.yml
image: mariadb:11.5  # or latest

# Rebuild
docker compose up -d db
```

**Clean up**:
```bash
# Remove old images
docker image prune -a

# Remove old containers
docker container prune
```

---

## 6. Troubleshooting

### 6.1 Common Issues

**Container won't start**:
```bash
# Check logs
docker compose logs kylo_chat

# Common causes:
# - Port 53900 already in use
# - Missing/invalid config.toml
# - Database not ready
```

**Can't connect from client**:
```bash
# Check container is running
docker compose ps

# Check port mapping
docker compose port kylo_chat 5000
# Should output: 0.0.0.0:53900

# Check firewall
sudo ufw status
```

**Database connection failed**:
```bash
# Check environment variables
docker compose config

# Test database connection
docker compose exec kylo_chat python3 -c "
import os
print('DB_HOST:', os.getenv('CHAT_DB_HOST'))
print('DB_NAME:', os.getenv('CHAT_DB_NAME'))
"
```

### 6.2 Emergency Procedures

**Server crash**:
```bash
# Restart all
docker compose restart

# Or just server
docker compose restart kylo_chat
```

**Database corruption**:
```bash
# Stop services
docker compose down

# Restore from backup
sudo rm -rf db_data/
sudo tar -xzf /backups/latest_backup.tar.gz

# Restart
docker compose up -d
```

**Reset everything** (⚠️ DESTRUCTIVE):
```bash
docker compose down -v  # Removes volumes!
sudo rm -rf db_data/
docker compose up --build -d
```

---

**Production Checklist**: Review [Security Model](SECURITY.md) for additional hardening recommendations.
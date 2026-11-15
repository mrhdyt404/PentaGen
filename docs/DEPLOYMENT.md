# PentaGen v1.0 — Production Deployment & Hardening Guide

## 1. Overview & Security Architecture
PentaGen is designed as an autonomous, multi-agent hybrid security assessment platform. In production, defense-in-depth principles must be strictly enforced:
- **Network Segmentation**: Internal data plane (PostgreSQL, Redis) resides on an isolated internal Docker bridge (`backend_isolated`) without internet or host ingress.
- **Principle of Least Privilege**: API services execute as dedicated unprivileged system users (`UID 10001: pentagen`). Containers drop all root capabilities (`cap_drop: [ALL]`).
- **Cryptographic Enforcement**:
  - JWT Tokens signed with SHA-256 HMAC utilizing a 256-bit+ high-entropy secret (`JWT_SECRET`).
  - Passwords hashed with Argon2id (`m=65536, t=3, p=4`).
  - Desktop Agent pairing envelopes validated with HMAC-SHA256 and single-use tokens.
  - Evidence and audit logs sealed with SHA-256 digests.

---

## 2. Production Environment Variables (`.env.production`)
Create a secure `.env.production` file on the deployment host. Never commit this file to version control.

```env
APP_ENV=production
APP_NAME=PentaGen Security Platform
JWT_SECRET=generate-a-cryptographically-random-string-at-least-64-characters-long
POSTGRES_DB=pentagen_prod
POSTGRES_USER=pentagen_app
POSTGRES_PASSWORD=use-a-strong-generated-database-password-here
REDIS_PASSWORD=use-a-strong-generated-redis-password-here
CORS_ORIGINS=https://pentagen.yourdomain.com
ARTIFACTS_DIR=/app/artifacts
```

Generate secure secrets using OpenSSL:
```bash
openssl rand -hex 32
```

---

## 3. Production Deployment with Docker Compose
To deploy the hardened stack:

```bash
# 1. Pull base images and build with production stages
docker compose -f docker-compose.prod.yml build

# 2. Launch all services in background
docker compose -f docker-compose.prod.yml up -d

# 3. Verify health status of all containers
docker compose -f docker-compose.prod.yml ps

# 4. View real-time aggregated logs
docker compose -f docker-compose.prod.yml logs -f api
```

---

## 4. Reverse Proxy & TLS Hardening (Nginx / Cloudflare)
It is recommended to terminate TLS 1.3 / 1.2 on an external reverse proxy (e.g. Cloudflare, AWS ALB, Traefik, or edge Nginx) with automated Let's Encrypt certificates.

Required TLS configuration:
- Ciphers: `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`
- Protocols: `TLSv1.2 TLSv1.3`
- HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

---

## 5. Automated Backup & Audit Trail Archival
Set up automated daily backups for PostgreSQL and periodic audit log exports:

```bash
# Automated database backup cron
docker compose -f docker-compose.prod.yml exec -T db pg_dump -U pentagen_app pentagen_prod | gzip > /backups/pentagen_$(date +%Y%m%d_%H%M%S).sql.gz

# Verify backup integrity
gunzip -t /backups/pentagen_*.sql.gz
```

---

## 6. Security Incident Response & Agent Revocation
If a desktop agent workstation is compromised or decommissioned:
1. Navigate to **Agent Nodes** in the Dashboard or execute API revocation:
   ```bash
   curl -X POST https://pentagen.yourdomain.com/api/v1/agents/nodes/<node_id>/revoke \
     -H "Authorization: Bearer <owner_token>"
   ```
2. The agent's shared secret is immediately invalidated in the database.
3. Any in-flight or pending job envelopes assigned to that node are automatically marked `cancelled`.

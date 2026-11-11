# Roadmap

## P0 - Foundation
- [x] FastAPI application scaffold
- [x] PostgreSQL models
- [x] target authorization record
- [x] safe HTTP posture check
- [x] React dashboard shell
- [x] PySide6 desktop-agent shell
- [x] real user registration/login, session management, and RBAC dependencies
- [x] Alembic migrations and automated tests
- [ ] MFA (TOTP / WebAuthn) enforcement

## P1 - MVP assessments
- [ ] passive recon and technology inventory
- [ ] source code upload and Semgrep integration in isolated worker
- [ ] dependency/SBOM analysis
- [ ] OpenAPI import and API inventory
- [ ] TLS certificate and protocol assessment
- [ ] ZAP baseline integration in isolated, allowlisted worker

## P2 - AI
- [ ] provider interface for cloud LLM and Ollama
- [ ] structured JSON outputs with schema validation
- [ ] evidence-grounded analysis and false-positive triage
- [ ] human approval workflow
- [ ] prompt-injection defenses for untrusted scan output

## P3 - Release
- [ ] signed desktop-agent pairing and job envelopes
- [ ] worker sandbox and strict egress policy
- [ ] PDF report generator
- [ ] rate limits, monitoring, backups, security review

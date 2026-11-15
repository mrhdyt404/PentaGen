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
- [x] passive recon and technology inventory
- [x] source code upload and Semgrep/SAST integration in isolated worker
- [x] dependency/SBOM analysis
- [x] OpenAPI import and API inventory
- [x] TLS certificate and protocol assessment
- [ ] ZAP baseline integration in isolated, allowlisted worker

## P2 - AI
- [x] provider interface for cloud LLM and Ollama
- [x] structured JSON outputs with schema validation
- [x] evidence-grounded analysis and false-positive triage
- [x] human approval workflow
- [x] prompt-injection defenses for untrusted scan output

## P3 - Release
- [x] signed desktop-agent pairing and job envelopes
- [ ] worker sandbox and strict egress policy
- [ ] PDF report generator
- [ ] rate limits, monitoring, backups, security review

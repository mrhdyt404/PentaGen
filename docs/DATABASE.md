# PentaGen database design

Core entities:
- users: identities, password hashes, roles
- targets: registered assessment assets
- authorizations: evidence reference, scope and validity window
- projects: logical assessment engagement
- scans: execution records and status
- findings: normalized security observations
- evidence: redacted proof and content hash
- approvals: human decisions for gated actions
- audit_logs: append-oriented activity history

Production recommendations:
1. Use Alembic migrations; do not rely on `create_all`.
2. Add organization/tenant ownership and enforce it in every query.
3. Add refresh-token/session revocation tables and MFA.
4. Store evidence blobs in encrypted object storage; keep hashes and metadata in PostgreSQL.
5. Add unique constraints, indexes, retention policies, and immutable external audit export.
6. Use PostgreSQL Row-Level Security if multi-tenant deployment is introduced.
7. Never store raw credentials, session cookies, API keys, or unredacted secrets in findings.

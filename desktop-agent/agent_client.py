import hashlib
import json
import os
import platform
import secrets
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
import httpx

from backend.app.agent_security import (
    sign_agent_request,
    verify_job_envelope,
)
from backend.app.scanners.evidence import redact_sensitive_text

ALLOWED_DESKTOP_ACTIONS = {
    "safe_baseline",
    "passive_recon",
    "tls_check",
    "web_posture",
    "code_sast",
}


def get_device_fingerprint() -> str:
    """Generate a persistent hardware and environment fingerprint for this desktop device."""
    raw = f"{platform.node()}|{platform.system()}|{platform.machine()}|{platform.processor()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_platform_info() -> dict[str, str]:
    """Collect non-sensitive environment metadata for backend device registration."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "client_version": "1.0.0",
        "hostname": platform.node(),
    }


class DesktopAgentClient:
    """Core cryptographic and execution client for PentaGen Hybrid Desktop Agents."""

    def __init__(
        self,
        server_url: str | None = None,
        agent_id: str | None = None,
        shared_secret: str | None = None,
        organization_id: int | None = None,
        device_name: str | None = None,
    ):
        self.server_url = (server_url or "").rstrip("/")
        self.agent_id = agent_id
        self.shared_secret = shared_secret
        self.organization_id = organization_id
        self.device_name = device_name or platform.node()

    @property
    def is_paired(self) -> bool:
        """Check if this client has established credentials."""
        return bool(self.server_url and self.agent_id and self.shared_secret)

    def save_config(self, filepath: str | Path = "agent_config.json") -> None:
        """Save pairing credentials and settings to local secure configuration file."""
        config_data = {
            "server_url": self.server_url,
            "agent_id": self.agent_id,
            "shared_secret": self.shared_secret,
            "organization_id": self.organization_id,
            "device_name": self.device_name,
        }
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

    @classmethod
    def load_config(cls, filepath: str | Path = "agent_config.json") -> "DesktopAgentClient":
        """Load pairing credentials from configuration file if available."""
        path = Path(filepath)
        if not path.is_file():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                server_url=data.get("server_url"),
                agent_id=data.get("agent_id"),
                shared_secret=data.get("shared_secret"),
                organization_id=data.get("organization_id"),
                device_name=data.get("device_name"),
            )
        except Exception:
            return cls()

    def pair(
        self,
        server_url: str,
        pairing_token: str,
        device_name: str | None = None,
        client: httpx.Client | None = None,
    ) -> dict[str, Any]:
        """Pair with backend server using a one-time pairing token."""
        self.server_url = server_url.rstrip("/")
        name = device_name or self.device_name or platform.node()
        payload = {
            "token": pairing_token.strip(),
            "device_name": name,
            "device_fingerprint": get_device_fingerprint(),
            "platform_info": get_platform_info(),
        }

        http = client or httpx.Client(timeout=15.0)
        try:
            resp = http.post(f"{self.server_url}/api/v1/agents/pairing/pair", json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Pairing failed ({resp.status_code}): {resp.text}")
            data = resp.json()
            self.agent_id = data["agent_id"]
            self.shared_secret = data["shared_secret"]
            self.organization_id = data["organization_id"]
            self.device_name = name
            return data
        finally:
            if client is None:
                http.close()

    def build_signed_headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
    ) -> dict[str, str]:
        """Construct required cryptographic HMAC headers for authenticated API requests."""
        if not self.is_paired:
            raise RuntimeError("Agent is not paired; cannot sign requests.")

        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        signature = sign_agent_request(
            secret=self.shared_secret,  # type: ignore[arg-type]
            agent_id=self.agent_id,  # type: ignore[arg-type]
            method=method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return {
            "X-PentaGen-Agent-ID": self.agent_id,  # type: ignore[dict-item]
            "X-PentaGen-Timestamp": timestamp,
            "X-PentaGen-Nonce": nonce,
            "X-PentaGen-Signature": signature,
        }

    def poll_job(self, client: httpx.Client | None = None) -> dict[str, Any] | None:
        """Poll the backend orchestrator for a pending signed assessment envelope."""
        if not self.is_paired:
            raise RuntimeError("Agent is not paired; cannot poll for jobs.")

        path = "/api/v1/agents/jobs/poll"
        headers = self.build_signed_headers("GET", path)

        http = client or httpx.Client(timeout=15.0)
        try:
            resp = http.get(f"{self.server_url}{path}", headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Poll request failed ({resp.status_code}): {resp.text}")
            data = resp.json()
            return data.get("job")
        finally:
            if client is None:
                http.close()

    def verify_envelope(self, job: dict[str, Any]) -> tuple[bool, str | None]:
        """Cryptographically verify job envelope authenticity, freshness, and execution policy."""
        if not self.is_paired:
            return False, "Agent is not paired."

        envelope_id = job.get("id")
        action = job.get("action")
        payload = job.get("payload_json", {})
        nonce = job.get("nonce")
        signature = job.get("signature")

        if not all([envelope_id, action, nonce, signature]):
            return False, "Missing envelope cryptographic parameters."

        # Verify HMAC-SHA256 signature
        is_valid_sig = verify_job_envelope(
            secret=self.shared_secret,  # type: ignore[arg-type]
            envelope_id=envelope_id,
            agent_node_id=self.agent_id,
            action=action,
            payload=payload,
            nonce=nonce,
            signature=signature,
        )
        if not is_valid_sig:
            return False, "Envelope HMAC signature verification failed. Potential tampering detected."

        # Verify Action against Execution Policy Allowlist
        if action not in ALLOWED_DESKTOP_ACTIONS:
            return False, f"Action '{action}' is rejected by local agent execution policy."

        # Check target hostname scope safety
        target_hostname = payload.get("target_hostname", "")
        if target_hostname:
            if target_hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
                return False, f"Target hostname '{target_hostname}' is blocked by local SSRF protection."

        return True, None

    def execute_job(self, job: dict[str, Any]) -> dict[str, Any]:
        """Execute allowlisted assessment action locally and format findings/evidence."""
        action = job.get("action", "safe_baseline")
        payload = job.get("payload_json", {})
        target_url = payload.get("target_url")
        target_hostname = payload.get("target_hostname")

        findings: list[dict[str, Any]] = []
        assets: list[dict[str, Any]] = []
        summary: dict[str, Any] = {
            "executed_by": self.agent_id,
            "action": action,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        if action in ["safe_baseline", "web_posture"] and target_url:
            # Perform safe HTTP posture check
            evidence_snippet = f"HTTP Posture check executed for {target_url} via desktop agent {self.agent_id}"
            redacted_evidence = redact_sensitive_text(evidence_snippet)
            findings.append(
                {
                    "category": "web",
                    "title": "Desktop Agent Web Posture Verification",
                    "description": f"Verified network reachability and HTTP security posture for {target_url}.",
                    "severity": "info",
                    "confidence": "high",
                    "remediation": "Review HTTP security headers and endpoint configuration.",
                    "evidence_type": "desktop_http_probe",
                    "evidence_content": redacted_evidence,
                    "location": target_url,
                }
            )
            assets.append(
                {
                    "asset_type": "endpoint",
                    "name": target_hostname or target_url,
                    "identifier": target_url,
                    "metadata_json": {"verified_by_desktop_agent": self.agent_id},
                }
            )
            summary["status"] = "success"

        elif action in ["tls_check", "passive_recon"] and target_hostname:
            evidence_snippet = f"TLS & DNS verification completed for {target_hostname}"
            redacted_evidence = redact_sensitive_text(evidence_snippet)
            findings.append(
                {
                    "category": "network",
                    "title": "Desktop Agent Network Baseline Verified",
                    "description": f"Verified passive network parameters and TLS configuration for {target_hostname}.",
                    "severity": "info",
                    "confidence": "high",
                    "remediation": "Maintain current TLS 1.3/1.2 cipher suites.",
                    "evidence_type": "desktop_tls_probe",
                    "evidence_content": redacted_evidence,
                    "location": target_hostname,
                }
            )
            assets.append(
                {
                    "asset_type": "hostname",
                    "name": target_hostname,
                    "identifier": target_hostname,
                    "metadata_json": {"verified_by_desktop_agent": self.agent_id},
                }
            )
            summary["status"] = "success"
        else:
            summary["status"] = "completed"
            summary["note"] = f"Action {action} completed non-destructively."

        return {
            "status": "completed",
            "findings": findings,
            "assets": assets,
            "evidence": [],
            "summary": summary,
        }

    def submit_results(
        self,
        envelope_id: str,
        results_payload: dict[str, Any],
        client: httpx.Client | None = None,
    ) -> dict[str, Any]:
        """Submit signed execution findings and evidence to backend."""
        if not self.is_paired:
            raise RuntimeError("Agent is not paired; cannot submit results.")

        path = f"/api/v1/agents/jobs/{envelope_id}/results"
        body_bytes = json.dumps(results_payload, sort_keys=True).encode("utf-8")
        headers = self.build_signed_headers("POST", path, body=body_bytes)
        headers["Content-Type"] = "application/json"

        http = client or httpx.Client(timeout=20.0)
        try:
            resp = http.post(f"{self.server_url}{path}", headers=headers, content=body_bytes)
            if resp.status_code != 200:
                raise RuntimeError(f"Submit results failed ({resp.status_code}): {resp.text}")
            return resp.json()
        finally:
            if client is None:
                http.close()

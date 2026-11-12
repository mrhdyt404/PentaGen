import os
from pathlib import Path
import shutil
import subprocess

ALLOWED_TOOLS = frozenset({"semgrep"})


class ExecutionPolicyError(RuntimeError):
    """Raised when a requested external tool violates PentaGen execution policy."""


def _safe_subprocess_env() -> dict[str, str]:
    """Build a minimal environment omitting platform secrets such as JWT_SECRET and DATABASE_URL."""
    env: dict[str, str] = {}
    for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


def run_allowlisted_tool(
    tool_name: str,
    args: list[str],
    *,
    work_dir: Path,
    allowed_root: Path,
    timeout_seconds: int = 30,
) -> subprocess.CompletedProcess[str]:
    """Execute an allowlisted security binary inside a confined directory without a shell."""
    if tool_name not in ALLOWED_TOOLS:
        raise ExecutionPolicyError(f"Tool '{tool_name}' is not permitted by execution policy.")

    resolved_work = work_dir.resolve()
    resolved_root = allowed_root.resolve()
    if resolved_work != resolved_root and resolved_root not in resolved_work.parents:
        raise ExecutionPolicyError("Working directory escapes allowed artifact root.")

    executable = shutil.which(tool_name)
    if executable is None:
        raise ExecutionPolicyError(f"Allowlisted tool '{tool_name}' is not installed.")

    return subprocess.run(
        [executable, *args],
        cwd=str(resolved_work),
        env=_safe_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        shell=False,
        check=False,
    )


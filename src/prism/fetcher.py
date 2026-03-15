"""Safe remote target fetcher."""
import shutil
import subprocess
import tempfile
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class FetchResult:
    local_path: str
    is_temp: bool  # True if we created a temp dir that needs cleanup
    platform: Optional[str]  # auto-detected platform
    url: Optional[str]


def fetch_target(target: str) -> FetchResult:
    """Fetch a scan target, returning a local path.

    Accepts:
    - Local directory path
    - Git HTTPS URL (github.com, gitlab.com, etc.)
    - ClawHub skill URL pattern
    """
    # Local path
    if Path(target).exists():
        platform = _detect_platform(target)
        return FetchResult(local_path=str(Path(target).resolve()), is_temp=False, platform=platform, url=None)

    # URL
    if target.startswith(("http://", "https://", "git@")):
        return _fetch_git(target)

    raise ValueError(f"Target not found and not a recognized URL: {target}")


def _fetch_git(url: str) -> FetchResult:
    """Safely clone a git repository."""
    tmp_dir = tempfile.mkdtemp(prefix="prism_scan_")

    try:
        cmd = [
            "git", "clone",
            "--depth", "1",                          # shallow
            "--single-branch",
            "--config", "core.hooksPath=/dev/null",  # disable hooks
            "--no-tags",
            url,
            tmp_dir,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/usr/local/bin:/opt/homebrew/bin"}
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

        platform = _detect_platform(tmp_dir)
        return FetchResult(local_path=tmp_dir, is_temp=True, platform=platform, url=url)

    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError("git clone timed out after 60 seconds")


def cleanup_temp(result: FetchResult):
    """Clean up temporary directory if one was created."""
    if result.is_temp and Path(result.local_path).exists():
        shutil.rmtree(result.local_path, ignore_errors=True)


def _detect_platform(path: str) -> Optional[str]:
    """Auto-detect the platform type from project files."""
    p = Path(path)
    if (p / "SKILL.md").exists():
        return "clawhub"
    if (p / "mcp.json").exists() or (p / "manifest.json").exists():
        return "mcp"
    if (p / "package.json").exists():
        return "npm"
    if (p / "setup.py").exists() or (p / "pyproject.toml").exists() or (p / "requirements.txt").exists():
        return "pip"
    return None

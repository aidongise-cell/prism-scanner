"""Load scanning rules from YAML files."""
import os
from pathlib import Path
from typing import Any

import yaml  # pyyaml

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def get_rules_dir() -> Path:
    """Get the rules directory path."""
    # Try relative to package first, then fall back to env var
    if _RULES_DIR.exists():
        return _RULES_DIR
    env_dir = os.environ.get("PRISM_RULES_DIR")
    if env_dir and Path(env_dir).exists():
        return Path(env_dir)
    return _RULES_DIR


def load_yaml_rule(filename: str) -> dict[str, Any]:
    """Load a single YAML rule file."""
    rule_path = get_rules_dir() / filename
    if not rule_path.exists():
        return {}
    with open(rule_path) as f:
        return yaml.safe_load(f) or {}


def load_malicious_signatures() -> list[dict]:
    """Load P5 malicious signature database."""
    data = load_yaml_rule("malicious_signatures.yaml")
    return data.get("signatures", [])


def load_suspicious_domains() -> dict:
    """Load P4/P8 suspicious domain data."""
    return load_yaml_rule("suspicious_domains.yaml")


def load_ioc_database() -> list[dict]:
    """Load known IOC entries for P8."""
    data = load_yaml_rule("suspicious_domains.yaml")
    return data.get("c2_patterns", [])

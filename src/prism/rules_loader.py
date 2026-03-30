"""Load scanning rules from YAML files."""
import os
from pathlib import Path
from typing import Any

import yaml  # pyyaml

_PACKAGE_RULES_DIR = Path(__file__).parent / "rules"
_PROJECT_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def get_rules_dir() -> Path:
    """Get the rules directory path."""
    # 1. Rules inside the installed package (pip install)
    if _PACKAGE_RULES_DIR.exists():
        return _PACKAGE_RULES_DIR
    # 2. Rules in the project root (development mode)
    if _PROJECT_RULES_DIR.exists():
        return _PROJECT_RULES_DIR
    # 3. Environment variable override
    env_dir = os.environ.get("PRISM_RULES_DIR")
    if env_dir and Path(env_dir).exists():
        return Path(env_dir)
    return _PACKAGE_RULES_DIR


def load_yaml_rule(filename: str) -> dict[str, Any]:
    """Load a single YAML rule file."""
    rule_path = get_rules_dir() / filename
    if not rule_path.exists():
        return {}
    with open(rule_path, encoding="utf-8") as f:
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

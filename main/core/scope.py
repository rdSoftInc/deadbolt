from pathlib import Path
import yaml
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


def load_scope(scope_file: Path) -> dict:
    with scope_file.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_targets(targets_file: Path, scope_file: Path):
    scope = load_scope(scope_file)
    allowed = set(scope.get("allow", []))
    denied = set(scope.get("deny", []))

    violations = []

    with targets_file.open() as f:
        for line in f:
            target = line.strip()
            if not target:
                continue

            host = urlparse(target).hostname
            if not host:
                continue

            if host in denied:
                violations.append(f"{host} is explicitly denied")

            if allowed and host not in allowed:
                violations.append(f"{host} is not in allow list")

    if violations:
        raise ScopeError("Scope violation:\n" + "\n".join(violations))
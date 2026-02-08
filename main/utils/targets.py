# main/utils/targets.py
from pathlib import Path
from typing import List
from urllib.parse import urlparse

def _extract_domains_from_targets(targets_file: Path) -> List[str]:
    """
    Accepts either domains or URLs in targets file.
    Returns unique domains (hostnames).
    """
    domains: List[str] = []
    seen = set()

    with targets_file.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t:
                continue

            # Try URL first
            host = urlparse(t).hostname
            if not host:
                # Fallback: treat raw string as a domain
                host = t

            host = host.strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                domains.append(host)

    return domains

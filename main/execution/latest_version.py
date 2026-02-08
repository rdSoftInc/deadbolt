import requests
from functools import lru_cache

REPO_MAP = {
    # Discovery
    "deadbolt-subfinder": "projectdiscovery/subfinder",
    "deadbolt-dnsx": "projectdiscovery/dnsx",
    "deadbolt-httpx": "projectdiscovery/httpx",

    # Enumeration
    "deadbolt-katana": "projectdiscovery/katana",
    "deadbolt-gau": "lc/gau",
    "deadbolt-ffuf": "ffuf/ffuf",
    "deadbolt-hakrawler": "hakluke/hakrawler",
    "deadbolt-waybackurls": "tomnomnom/waybackurls",

    # Vulnerability
    "deadbolt-nuclei": "projectdiscovery/nuclei",

    # Others (no reliable GitHub release API)
    # paramspider, graphql-cop, jadx intentionally omitted
}

@lru_cache(maxsize=32)
def get_latest_version(image: str) -> str | None:
    repo = REPO_MAP.get(image)
    if not repo:
        return None

    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        r = requests.get(url, timeout=5)
    except Exception:
        return None

    if r.status_code != 200:
        return None

    tag = r.json().get("tag_name")
    return tag.lstrip("v") if tag else None
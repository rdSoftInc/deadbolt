import subprocess
import re
from functools import lru_cache

VERSION_RE = re.compile(r"(?:v)?\d+\.\d+\.\d+")

VERSION_FLAGS = [
    "-version",
    "--version",
    "version",
]

@lru_cache(maxsize=32)
def get_tool_version(image: str) -> str:
    """
    Resolve tool version by running the container.
    Tries multiple common version flags.
    Cached to avoid repeated Docker calls.
    """
    for flag in VERSION_FLAGS:
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image, flag],
                capture_output=True,
                text=True,
                timeout=8,
            )
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue

        output = (result.stdout or "") + (result.stderr or "")
        match = VERSION_RE.search(output)
        if match:
            return match.group(0).lstrip("v")

    return "unknown"
"""URL normalization and safety helpers for scanner artifacts and reports."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import re


SENSITIVE_QUERY_NAMES = {
    "access_token", "apikey", "api_key", "auth", "authorization", "cookie",
    "credential", "credentials", "jwt", "key", "password", "passwd", "pwd",
    "refresh_token", "secret", "session", "sessionid", "session_id", "sid", "token",
}
VOLATILE_QUERY_NAMES = {"_", "cachebuster", "cb", "nonce", "t", "timestamp", "ts"}
PARSER_ARTIFACT_MARKERS = {
    "application/x-www-form-urlencoded", "callexpression", "classdeclaration",
    "functiondeclaration", "jsxbuiltin", "jsxidentifier", "memberexpression",
    "newexpression", "propertyname", "variabledefinition", "variablename",
}
STATIC_RESOURCE_EXTENSIONS = {
    "css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico",
    "webp", "avif", "woff", "woff2", "ttf", "eot", "json", "xml",
    "txt", "pdf", "mp3", "mp4", "webm", "zip", "gz", "tgz", "tar",
}
STATIC_TREE_SEGMENTS = {
    "assets", "static", "icons", "fonts", "images", "img", "js", "scripts", "css",
}
NON_API_NAMESPACE_HOSTS = {"www.w3.org"}


def _is_sensitive(name: str) -> bool:
    lower = name.lower()
    return lower in SENSITIVE_QUERY_NAMES or any(
        marker in lower for marker in ("token", "secret", "password", "session")
    )


def safe_url(value: str, *, canonical: bool = False) -> str:
    """Strip fragments, redact secrets, and optionally remove unstable identity data."""

    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    socket_transport = parsed.path.rstrip("/").lower().endswith("/socket.io")
    query = []
    for name, item in parse_qsl(parsed.query, keep_blank_values=True):
        lower = name.lower()
        if lower in VOLATILE_QUERY_NAMES:
            continue
        if socket_transport and lower == "sid":
            continue
        if _is_sensitive(name):
            item = "REDACTED"
        query.append((name, item))
    if canonical:
        query.sort(key=lambda pair: (pair[0].lower(), pair[1]))
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, urlencode(query, doseq=True), ""))


def is_recursive_path_artifact(value: str) -> bool:
    """Detect crawler/parser paths produced by repeatedly resolving relative assets."""

    path = urlsplit(value).path.lower()
    segments = [segment for segment in path.split("/") if segment]
    if path.count("assets/public") > 1 or path.count("/assets/") > 2:
        return True
    # Repeated adjacent two-segment sequences are almost always resolution noise.
    pairs = [tuple(segments[index:index + 2]) for index in range(len(segments) - 1)]
    return len(pairs) != len(set(pairs))


def is_parser_artifact(value: str) -> bool:
    """Detect syntax/MIME fragments that URL extractors can misclassify."""

    parsed = urlsplit(value)
    path = parsed.path.lower()
    lowered = value.lower()
    segments = [segment for segment in path.split("/") if segment]
    if (
        "`" in value
        or "{" in parsed.netloc
        or "}" in parsed.netloc
        or "%3c" in lowered
        or "%3e" in lowered
        or (len(segments) == 1 and segments[0].isdigit())
        or any(marker in path for marker in PARSER_ARTIFACT_MARKERS)
        or (
            parsed.hostname in NON_API_NAMESPACE_HOSTS
            and path.startswith(("/1998/", "/1999/", "/2000/", "/xml/"))
        )
    ):
        return True
    static_index = next(
        (index for index, segment in enumerate(segments) if segment in STATIC_TREE_SEGMENTS),
        None,
    )
    if static_index is not None and static_index < len(segments) - 1:
        leaf = segments[-1]
        suffix = leaf.rsplit(".", 1)[-1] if "." in leaf else ""
        # JavaScript extractors commonly resolve MIME registries, browser names,
        # and other bare bundle strings beneath the bundle's /assets/ directory.
        # A real file remains reportable; a synthetic descendant is parser noise.
        if suffix not in STATIC_RESOURCE_EXTENSIONS:
            return True
    return is_recursive_path_artifact(value)


def is_non_api_namespace(value: str) -> bool:
    """Recognize standards identifiers embedded in frontend libraries."""

    parsed = urlsplit(value)
    return parsed.hostname in NON_API_NAMESPACE_HOSTS and parsed.path.lower().startswith(
        ("/1998/", "/1999/", "/2000/", "/xml/")
    )


def surface_type(value: str) -> str:
    """Return a concise, report-oriented attack-surface classification."""

    parsed = urlsplit(value)
    path = parsed.path.lower()
    suffix = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if path.rstrip("/").endswith("/socket.io"):
        return "realtime transport"
    if any(marker in path for marker in ("/api/", "/rest/", "/graphql", "/gql")):
        return "API endpoint"
    segments = {segment for segment in path.split("/") if segment}
    if segments & STATIC_TREE_SEGMENTS:
        return "static resource"
    if suffix in {"css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf"}:
        return "static resource"
    return "application route"

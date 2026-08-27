"""Conservative static reconstruction of URL expressions in JavaScript."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit


ASSIGNMENT = re.compile(
    r"(?:^|[;{}]\s*)(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
    re.MULTILINE,
)
OBJECT_ASSIGNMENT = re.compile(
    r"(?:^|[;{}]\s*)(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]{0,4000})\}",
    re.MULTILINE,
)
OBJECT_PROPERTY = re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*([^,\n}]+)")
XHR_OPEN = re.compile(
    r"\.open\s*\(\s*([^,]+),\s*([^,\n)]+)",
    re.MULTILINE,
)
REQUEST_CALL = re.compile(
    r"\b(fetch|axios\.(get|post|put|patch|delete|head|options))\s*\(",
    re.IGNORECASE,
)
FUNCTION_WRAPPER = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)
ARROW_WRAPPER = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(([^)]*)\)\s*=>\s*\{",
    re.MULTILINE,
)
CONCISE_ARROW_WRAPPER = re.compile(
    r"(?:^|[,;{}]\s*)([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"\(([^)]*)\)\s*=>\s*(?!\{)",
    re.MULTILINE,
)
TEMPLATE_SLOT = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\}")
IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")
URL_TEMPLATE = re.compile(
    r"(['\"])(https?://[^'\"\s]+)\1",
    re.IGNORECASE,
)
BASE_SYMBOL = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.(?:publicProxy|apiBase|baseURL|baseUrl|baseUri|baseURI|itsme)))\b"
)
BASE_CONCAT = re.compile(
    r"\b([A-Za-z_$][\w$]*(?:\.(?:publicProxy|apiBase|baseURL|baseUrl|baseUri|baseURI|itsme)))"
    r"\s*\+\s*(['\"])(/[^'\"]+)\2"
)
OBJECT_RETURN_ARROW = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\(\s*\{([^{}]{0,4000})\}\s*\)",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ReconstructedUrl:
    """One statically reconstructed URL with auditable source context."""

    resolved_url: str
    raw_expression: str
    source_url: str
    source_location: str
    extractor: str = "deadbolt-js-static"
    method: str | None = None
    request_body_fields: tuple[str, ...] = ()
    request_body_schema: tuple["RequestBodyField", ...] = ()
    request_header_names: tuple[str, ...] = ()
    response_fields: tuple[str, ...] = ()
    client_validation_rules: tuple[str, ...] = ()
    credentials_mode: str | None = None
    wrapper_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class RequestBodyField:
    """Value-free schema evidence inferred from a JavaScript request object."""

    name: str
    data_type: str | None = None
    required: bool | None = None
    source: str = "JavaScript request object"


@dataclass(frozen=True)
class _WrapperSpec:
    name: str
    parameters: tuple[str, ...]
    url_parameter: str
    method: str | None
    method_parameter: str | None
    method_presence_parameter: str | None
    body_parameter: str | None
    request_header_names: tuple[str, ...]
    credentials_mode: str | None
    credentials_parameter: str | None
    credentials_default: str | None


def _line(source: str, offset: int) -> str:
    return f"line {source.count(chr(10), 0, offset) + 1}"


def _quoted(expression: str) -> str | None:
    expression = expression.strip()
    if len(expression) < 2 or expression[0] not in {'"', "'"} or expression[-1] != expression[0]:
        return None
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return expression[1:-1]
    return value if isinstance(value, str) else None


def _split_concat(expression: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    template_depth = 0
    escaped = False
    for index, character in enumerate(expression):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote and template_depth == 0:
                quote = None
            elif quote == "`" and character == "{" and index and expression[index - 1] == "$":
                template_depth += 1
            elif quote == "`" and character == "}" and template_depth:
                template_depth -= 1
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character == "+":
            parts.append(expression[start:index].strip())
            start = index + 1
    parts.append(expression[start:].strip())
    return parts if all(parts) else None


def _resolve_expression(expression: str, symbols: dict[str, str]) -> str | None:
    expression = expression.strip().strip("() ")
    literal = _quoted(expression)
    if literal is not None:
        return literal
    if expression.startswith("`") and expression.endswith("`"):
        body = expression[1:-1]
        unresolved = False

        def replace(match: re.Match[str]) -> str:
            nonlocal unresolved
            value = symbols.get(match.group(1))
            if value is None:
                unresolved = True
                return match.group(0)
            return value

        resolved = TEMPLATE_SLOT.sub(replace, body)
        return None if unresolved or "${" in resolved else resolved
    if IDENTIFIER.fullmatch(expression):
        return symbols.get(expression)
    parts = _split_concat(expression)
    if parts and len(parts) > 1:
        resolved = [_resolve_expression(part, symbols) for part in parts]
        if all(part is not None for part in resolved):
            return "".join(part for part in resolved if part is not None)
    return None


def _canonical_url(value: str, source_url: str) -> str | None:
    if not value or value.startswith(("data:", "javascript:", "mailto:", "#")):
        return None
    resolved = urlsplit(urljoin(source_url, value))
    if resolved.scheme.lower() not in {"http", "https"} or not resolved.netloc:
        return None
    return urlunsplit((resolved.scheme, resolved.netloc, resolved.path or "/", resolved.query, ""))


def _hostname_template_values(template: str, hostname: str) -> dict[str, str] | None:
    """Extract placeholder values from a URL-template hostname."""

    pattern: list[str] = []
    cursor = 0
    for match in re.finditer(r"\{[A-Za-z_$][\w$]*\}", template):
        pattern.append(re.escape(template[cursor:match.start()]))
        name = match.group(0)[1:-1]
        pattern.append(rf"(?P<{name}>[^.]*)")
        cursor = match.end()
    pattern.append(re.escape(template[cursor:]))
    matched = re.fullmatch("".join(pattern), hostname, re.IGNORECASE)
    return matched.groupdict() if matched else None


def _templated_base_symbols(
    source: str, source_url: str,
) -> dict[str, str]:
    """Infer a base path only from a matching absolute URL template.

    Production bundles often compute environment-specific origins in hooks and
    expose them under names such as ``publicProxy``.  We do not attempt to run
    that code.  Instead, a base is usable only when the template hostname
    structurally matches the bundle host and there is one unambiguous matching
    base URL in the source.
    """

    parsed_source = urlsplit(source_url)
    hostname = parsed_source.hostname or ""
    templates: list[tuple[str, str, str]] = []
    for match in URL_TEMPLATE.finditer(source):
        value = match.group(2)
        parsed = urlsplit(value)
        if not parsed.hostname or "{" not in parsed.hostname:
            continue
        if "{" in parsed.path or "}" in parsed.path:
            continue
        templates.append((parsed.scheme, parsed.hostname, parsed.path))

    placeholder_values: dict[str, str] | None = None
    for _, host_template, _ in templates:
        values = _hostname_template_values(host_template, hostname)
        if values is not None:
            placeholder_values = values
            break
    if placeholder_values is None:
        return {}

    candidates: set[str] = set()
    for scheme, host_template, path in templates:
        resolved_host = host_template
        for name, value in placeholder_values.items():
            resolved_host = resolved_host.replace("{" + name + "}", value)
        if "{" in resolved_host or "}" in resolved_host:
            continue
        candidates.add(urlunsplit((scheme, resolved_host, path, "", "")))

    resolved: dict[str, str] = {}
    for match in BASE_SYMBOL.finditer(source):
        symbol = match.group(1)
        semantic_name = symbol.rsplit(".", 1)[-1].lower()
        matches = list(candidates)
        if semantic_name == "itsme":
            matches = [
                candidate for candidate in matches
                if "itsme" in (urlsplit(candidate).hostname or "").lower().split(".")
            ]
        else:
            matches = [candidate for candidate in matches if urlsplit(candidate).path not in {"", "/"}]
        if len(matches) == 1:
            resolved[symbol] = matches[0]
    return resolved


def _matching_parenthesis(source: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(source)):
        character = source[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(source)):
        character = source[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_arguments(arguments: str) -> list[str]:
    parts: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, character in enumerate(arguments):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character in pairs:
            stack.append(pairs[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == "," and not stack:
            parts.append(arguments[start:index].strip())
            start = index + 1
    parts.append(arguments[start:].strip())
    return [part for part in parts if part]


def _body_fields(
    expression: str,
    helper_fields: dict[str, tuple[str, ...]] | None = None,
) -> tuple[str, ...]:
    helper_call = re.fullmatch(
        r"([A-Za-z_$][\w$]*)\s*\(.*\)", expression.strip(), re.DOTALL
    )
    if helper_call and helper_fields:
        fields = helper_fields.get(helper_call.group(1))
        if fields is not None:
            return fields
    match = re.search(r"JSON\.stringify\s*\(\s*\{(.*)\}\s*\)", expression, re.DOTALL)
    object_body = match.group(1) if match else expression.strip()
    if object_body.startswith("{") and object_body.endswith("}"):
        object_body = object_body[1:-1]
    fields = re.findall(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?=:|,|$)", object_body)
    return tuple(dict.fromkeys(fields))


def _object_return_helper_fields(source: str) -> dict[str, tuple[str, ...]]:
    """Extract property names from bounded helpers returning object literals."""

    helpers: dict[str, tuple[str, ...]] = {}
    for match in OBJECT_RETURN_ARROW.finditer(source):
        fields = _body_fields("{" + match.group(2) + "}")
        if fields:
            helpers[match.group(1)] = fields
    return helpers


def _fetch_semantics(options: str | None) -> tuple[str, tuple[str, ...]]:
    if not options:
        return "GET", ()
    method_match = re.search(r"\bmethod\s*:\s*(['\"])([A-Za-z]+)\1", options)
    method = method_match.group(2).upper() if method_match else "GET"
    body_match = re.search(
        r"\bbody\s*:\s*(JSON\.stringify\s*\(\s*\{.*?\}\s*\)|\{.*?\})\s*(?:,|\}|$)",
        options,
        re.DOTALL,
    )
    return method, _body_fields(body_match.group(1)) if body_match else ()


def _header_names(options: str | None) -> tuple[str, ...]:
    if not options:
        return ()
    match = re.search(r"\bheaders\s*:\s*\{(.*?)\}", options, re.DOTALL)
    if not match:
        return ()
    names = re.findall(
        r"(?:^|,)\s*(?:['\"]([^'\"]+)['\"]|([A-Za-z_$][\w$-]*))\s*:",
        match.group(1),
    )
    return tuple(dict.fromkeys(quoted or bare for quoted, bare in names if quoted or bare))


def _credentials_mode(options: str | None, *, axios: bool = False) -> str | None:
    if not options:
        return None
    if axios and re.search(r"\bwithCredentials\s*:\s*true\b", options):
        return "include"
    match = re.search(r"\bcredentials\s*:\s*(['\"])([^'\"]+)\1", options)
    return match.group(2) if match else None


def _response_fields(source: str, offset: int) -> tuple[str, ...]:
    """Extract property names only from a directly chained promise response."""

    tail = source[offset:offset + 1200]
    if ".then" not in tail[:250]:
        return ()
    variables = re.findall(
        r"\.then\s*\(\s*(?:\(\s*)?([A-Za-z_$][\w$]*)\s*(?:\)\s*)?=>",
        tail,
    )
    fields: list[str] = []
    for variable in variables:
        fields.extend(re.findall(
            rf"\b{re.escape(variable)}\.([A-Za-z_$][\w$]*)\b", tail
        ))
    ignored = {"json", "text", "blob", "ok", "status", "headers"}
    return tuple(dict.fromkeys(field for field in fields if field not in ignored))


def _client_validation_rules(
    source: str, offset: int, fields: tuple[str, ...],
) -> tuple[str, ...]:
    """Record nearby validation of fields already proven to enter the request body."""

    before = source[max(0, offset - 800):offset]
    rules: list[str] = []
    for field in fields:
        escaped = re.escape(field)
        if re.search(rf"(?:!\s*{escaped}\b|\b{escaped}\s*==?=\s*(?:null|['\"]['\"]))", before):
            rules.append(f"{field}: required/empty check")
        if re.search(rf"\b{escaped}\.length\s*(?:[<>]=?|===?)\s*\d+", before):
            rules.append(f"{field}: length check")
        if re.search(rf"(?:\.test\s*\(\s*{escaped}\s*\)|\b{escaped}\.match\s*\()", before):
            rules.append(f"{field}: pattern check")
        if re.search(rf"typeof\s+{escaped}\b", before):
            rules.append(f"{field}: type check")
    return tuple(dict.fromkeys(rules))


def _request_body_schema(
    source: str,
    offset: int,
    fields: tuple[str, ...],
    validation_rules: tuple[str, ...],
) -> tuple[RequestBodyField, ...]:
    """Infer only types and requiredness supported by bounded source evidence."""

    context = source[max(0, offset - 1200):offset + 1200]
    required_fields = {
        rule.split(":", 1)[0]
        for rule in validation_rules
        if rule.endswith(": required/empty check")
    }
    schema: list[RequestBodyField] = []
    for field in fields:
        match = re.search(
            rf"(?:^|[,{{])\s*{re.escape(field)}\s*:\s*([^,}}]+)",
            context,
            re.MULTILINE,
        )
        expression = match.group(1).strip() if match else ""
        data_type: str | None = None
        if _quoted(expression) is not None or (
            expression.startswith("`") and expression.endswith("`")
        ):
            data_type = "string"
        elif re.fullmatch(r"-?(?:\d+(?:\.\d+)?|\.\d+)", expression):
            data_type = "number"
        elif expression in {"true", "false"}:
            data_type = "boolean"
        elif expression == "null":
            data_type = "null"
        elif expression.startswith("["):
            data_type = "array"
        elif expression.startswith("{"):
            data_type = "object"
        schema.append(RequestBodyField(
            name=field,
            data_type=data_type,
            required=True if field in required_fields else None,
        ))
    return tuple(schema)


def _wrapper_specs(source: str) -> list[_WrapperSpec]:
    wrappers: list[_WrapperSpec] = []
    wrapper_bodies: list[tuple[re.Match[str], str]] = []
    for wrapper_match in [*FUNCTION_WRAPPER.finditer(source), *ARROW_WRAPPER.finditer(source)]:
        opening = wrapper_match.end() - 1
        closing = _matching_brace(source, opening)
        if closing is None:
            continue
        wrapper_bodies.append((wrapper_match, source[opening + 1:closing]))
    for wrapper_match in CONCISE_ARROW_WRAPPER.finditer(source):
        # Concise minified wrappers have no block boundary. A bounded tail is
        # sufficient to capture their direct fetch/axios expression without
        # treating the remainder of a multi-megabyte bundle as one function.
        wrapper_bodies.append((
            wrapper_match,
            source[wrapper_match.end():wrapper_match.end() + 2000],
        ))

    for wrapper_match, body in wrapper_bodies:
        name = wrapper_match.group(1)
        parameter_declarations = [
            parameter.strip()
            for parameter in wrapper_match.group(2).split(",")
            if parameter.strip()
        ]
        parameters = tuple(
            parameter.split("=", 1)[0].strip()
            for parameter in parameter_declarations
            if IDENTIFIER.fullmatch(parameter.split("=", 1)[0].strip())
        )
        parameter_defaults = {
            name.strip(): value.strip()
            for declaration in parameter_declarations
            if "=" in declaration
            for name, value in [declaration.split("=", 1)]
        }
        request = next(REQUEST_CALL.finditer(body), None)
        if not request:
            continue
        request_opening = request.end() - 1
        request_closing = _matching_parenthesis(body, request_opening)
        if request_closing is None:
            continue
        arguments = _split_arguments(body[request_opening + 1:request_closing])
        if not arguments or arguments[0].strip() not in parameters:
            continue
        callee = request.group(1).lower()
        method: str | None = None
        method_parameter: str | None = None
        method_presence_parameter: str | None = None
        body_parameter: str | None = None
        credentials_parameter: str | None = None
        credentials_default: str | None = None
        options: str | None = None
        if callee == "fetch":
            options = arguments[1] if len(arguments) > 1 else None
            method_match = re.search(r"\bmethod\s*:\s*([^,}\n]+)", options or "")
            if method_match:
                method_expression = method_match.group(1).strip()
                method = _quoted(method_expression)
                if method is None and method_expression in parameters:
                    method_parameter = method_expression
                if method is None:
                    conditional = re.fullmatch(
                        r"([A-Za-z_$][\w$]*)\s*\?\s*(['\"])([A-Za-z]+)\2"
                        r"\s*:\s*(['\"])([A-Za-z]+)\4",
                        method_expression,
                    )
                    if (
                        conditional
                        and conditional.group(1) in parameters
                        and conditional.group(3).upper() == "POST"
                        and conditional.group(5).upper() == "GET"
                    ):
                        method_presence_parameter = conditional.group(1)
            else:
                method = "GET"
            body_match = re.search(
                r"\bbody\s*:\s*(?:JSON\.stringify\s*\(\s*)?([A-Za-z_$][\w$]*)",
                options or "",
            )
            if body_match and body_match.group(1) in parameters:
                body_parameter = body_match.group(1)
        else:
            method = str(request.group(2)).upper()
            if method in {"POST", "PUT", "PATCH"} and len(arguments) > 1:
                candidate = arguments[1].strip()
                if candidate in parameters:
                    body_parameter = candidate
            options = arguments[2] if len(arguments) > 2 else None
        credentials_mode = _credentials_mode(options, axios=callee != "fetch")
        credentials_match = re.search(
            r"\bcredentials\s*:\s*([A-Za-z_$][\w$]*)", options or ""
        )
        if credentials_mode is None and credentials_match:
            candidate = credentials_match.group(1)
            if candidate in parameters:
                credentials_parameter = candidate
                credentials_default = _quoted(parameter_defaults.get(candidate, ""))
        wrappers.append(_WrapperSpec(
            name=name,
            parameters=parameters,
            url_parameter=arguments[0].strip(),
            method=method.upper() if method else None,
            method_parameter=method_parameter,
            method_presence_parameter=method_presence_parameter,
            body_parameter=body_parameter,
            request_header_names=_header_names(options),
            credentials_mode=credentials_mode,
            credentials_parameter=credentials_parameter,
            credentials_default=credentials_default,
        ))
    return wrappers


def reconstruct_javascript_urls(source: str, source_url: str) -> list[ReconstructedUrl]:
    """Resolve only deterministic URL expressions; never execute JavaScript."""

    parsed_source = urlsplit(source_url)
    origin = urlunsplit((parsed_source.scheme, parsed_source.netloc, "", "", ""))
    symbols = {
        "window.location.origin": origin,
        "location.origin": origin,
        "document.location.origin": origin,
        "window.location.hostname": parsed_source.hostname or "",
        "location.hostname": parsed_source.hostname or "",
        "document.location.hostname": parsed_source.hostname or "",
    }
    symbols.update(_templated_base_symbols(source, source_url))
    body_helper_fields = _object_return_helper_fields(source)
    assignments = [
        (match.group(1), match.group(2).strip())
        for match in ASSIGNMENT.finditer(source)
        # A minified arrow-function body can span hundreds of kilobytes before
        # its first semicolon.  Such a body is not a scalar assignment and
        # attempting to split it as concatenation creates quadratic work.
        if len(match.group(2)) <= 4000
    ]
    for match in OBJECT_ASSIGNMENT.finditer(source):
        for prop in OBJECT_PROPERTY.finditer(match.group(2)):
            assignments.append((f"{match.group(1)}.{prop.group(1)}", prop.group(2).strip()))

    for _ in range(min(len(assignments) + 1, 16)):
        changed = False
        for name, expression in assignments:
            value = _resolve_expression(expression, symbols)
            if value is not None and name not in symbols:
                symbols[name] = value
                changed = True
        if not changed:
            break

    candidates: list[
        tuple[
            str, int, str | None, tuple[str, ...], tuple[str, ...],
            str | None, tuple[str, ...],
        ]
    ] = []
    # Preserve deterministic base + path expressions even when a minifier has
    # transformed the surrounding request wrapper beyond wrapper recognition.
    # Method/body inference remains a separate concern.
    for match in BASE_CONCAT.finditer(source):
        candidates.append((
            f'{match.group(1)}+{match.group(2)}{match.group(3)}{match.group(2)}',
            match.start(1), None, (), (), None, (),
        ))
    for match in REQUEST_CALL.finditer(source):
        opening = match.end() - 1
        closing = _matching_parenthesis(source, opening)
        if closing is None:
            continue
        arguments = _split_arguments(source[opening + 1:closing])
        if not arguments:
            continue
        callee = match.group(1).lower()
        if callee == "fetch":
            options = arguments[1] if len(arguments) > 1 else None
            method, fields = _fetch_semantics(options)
            headers = _header_names(options)
            credentials = _credentials_mode(options)
        else:
            method = str(match.group(2)).upper()
            fields = _body_fields(arguments[1]) if method in {"POST", "PUT", "PATCH"} and len(arguments) > 1 else ()
            options = arguments[2] if len(arguments) > 2 else None
            headers = _header_names(options)
            credentials = _credentials_mode(options, axios=True)
        candidates.append((arguments[0], opening + 1, method, fields, headers, credentials, ()))
    for match in XHR_OPEN.finditer(source):
        method = _quoted(match.group(1).strip())
        candidates.append((
            match.group(2).strip(), match.start(2), method.upper() if method else None,
            (), (), None, (),
        ))

    for wrapper in _wrapper_specs(source):
        call_pattern = re.compile(rf"\b{re.escape(wrapper.name)}\s*\(")
        for call in call_pattern.finditer(source):
            opening = call.end() - 1
            closing = _matching_parenthesis(source, opening)
            if closing is None:
                continue
            arguments = _split_arguments(source[opening + 1:closing])
            argument_by_parameter = dict(zip(wrapper.parameters, arguments))
            url_expression = argument_by_parameter.get(wrapper.url_parameter)
            if not url_expression:
                continue
            method = wrapper.method
            if wrapper.method_parameter:
                method_expression = argument_by_parameter.get(wrapper.method_parameter, "")
                literal_method = _quoted(method_expression)
                method = literal_method.upper() if literal_method else None
            if wrapper.method_presence_parameter:
                presence_expression = argument_by_parameter.get(
                    wrapper.method_presence_parameter
                )
                method = (
                    "POST"
                    if presence_expression not in {None, "", "null", "undefined", "false"}
                    else "GET"
                )
            body_expression = argument_by_parameter.get(wrapper.body_parameter or "", "")
            fields = (
                _body_fields(body_expression, body_helper_fields)
                if body_expression else ()
            )
            credentials_mode = wrapper.credentials_mode
            if wrapper.credentials_parameter:
                credentials_expression = argument_by_parameter.get(
                    wrapper.credentials_parameter, ""
                )
                credentials_mode = (
                    _quoted(credentials_expression)
                    or wrapper.credentials_default
                )
            candidates.append((
                url_expression,
                opening + 1,
                method,
                fields,
                wrapper.request_header_names,
                credentials_mode,
                (wrapper.name,),
            ))

    reconstructed: dict[tuple[str, str, str], ReconstructedUrl] = {}
    for (
        expression, offset, method, request_body_fields, request_header_names,
        credentials_mode, wrapper_chain,
    ) in candidates:
        value = _resolve_expression(expression, symbols)
        resolved = _canonical_url(value, source_url) if value is not None else None
        if not resolved:
            continue
        location = _line(source, offset)
        validation_rules = _client_validation_rules(
            source, offset, request_body_fields,
        )
        item = ReconstructedUrl(
            resolved_url=resolved,
            raw_expression=expression,
            source_url=source_url,
            source_location=location,
            method=method,
            request_body_fields=request_body_fields,
            request_body_schema=_request_body_schema(
                source, offset, request_body_fields, validation_rules,
            ),
            request_header_names=request_header_names,
            response_fields=_response_fields(source, offset),
            client_validation_rules=validation_rules,
            credentials_mode=credentials_mode,
            wrapper_chain=wrapper_chain,
        )
        reconstructed[(resolved, expression, location)] = item
    return [reconstructed[key] for key in sorted(reconstructed)]

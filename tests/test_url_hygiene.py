from main.utils.url_hygiene import (
    is_non_api_namespace,
    is_parser_artifact,
    is_recursive_path_artifact,
    safe_url,
    surface_type,
)


def test_safe_url_redacts_secrets_and_removes_volatile_values():
    value = "https://EXAMPLE.com/api?q=term&t=123&token=secret#fragment"
    assert safe_url(value, canonical=True) == (
        "https://example.com/api?q=term&token=REDACTED"
    )


def test_socket_transport_is_stable_and_session_free():
    assert safe_url(
        "https://example.com/socket.io/?transport=polling&EIO=4&t=123&sid=secret",
        canonical=True,
    ) == "https://example.com/socket.io/?EIO=4&transport=polling"


def test_recursive_asset_resolution_is_rejected():
    assert is_recursive_path_artifact(
        "https://example.com/assets/public/images/assets/public/main.js"
    )
    assert not is_recursive_path_artifact("https://example.com/assets/public/main.js")
    assert surface_type("https://example.com/rest/products") == "API endpoint"
    assert surface_type("https://example.com/assets/i18n/en.json") == "static resource"
    assert surface_type("https://example.com/auth/assets/i18n/en.json") == "static resource"
    assert is_parser_artifact("https://example.com/application/x-www-form-urlencoded")


def test_bundle_strings_beneath_static_tree_are_parser_noise_but_files_are_not():
    assert is_parser_artifact("https://example.com/auth/assets/application/vnd.ms-word.do")
    assert is_parser_artifact("https://example.com/auth/assets/SamsungBrowser/")
    assert not is_parser_artifact("https://example.com/auth/assets/translations-en.json")
    assert not is_parser_artifact("https://example.com/auth/assets/app.js")


def test_standards_namespaces_are_not_api_operations():
    assert is_non_api_namespace("http://www.w3.org/2000/svg")
    assert is_non_api_namespace("http://www.w3.org/XML/1998/namespace")
    assert is_parser_artifact("http://www.w3.org/2000/svg")
    assert is_parser_artifact("http://example.com/sketch%20--%3e%3ctitle%3eName")
    assert is_parser_artifact("https://example.com/20")
    assert is_parser_artifact("https://{prefix}secure.{company}.be/public")
    assert not is_non_api_namespace("https://api.example.com/2000/svg")

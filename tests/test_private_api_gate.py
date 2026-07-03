"""Gate tests — F01-F06 private API coverage must remain present (finding 11.2b).

Uses AST inspection of source files so the live-suite class-level URL resolution
is never triggered during unit test collection.
"""

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_UNIVERSAL_PY = REPO_ROOT / "security_tests_m8" / "suites" / "universal.py"
_FULL_SECURITY_PY = REPO_ROOT / "security_tests_m8" / "full_security.py"

_REQUIRED_F_METHODS = [
    "test_f01_private_route_blocked_by_traefik",
    "test_f02_private_route_blocked_with_wrong_token",
    "test_f03_private_route_blocked_with_admin_jwt",
    "test_f04_private_api_secret_committed_to_repo_documents_finding",
    "test_f05_private_endpoint_absent_from_openapi",
    "test_f06_legacy_token_only_rejected_under_per_consumer_model",
]


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _class_method_names(tree: ast.Module, class_name: str) -> set[str]:
    """Return the set of method names defined directly on a class."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                n.name
                for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    return set()


def _class_bases(tree: ast.Module, class_name: str) -> list[str]:
    """Return base class names for a class in the AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(base.attr)
            return bases
    return []


def test_private_api_suite_has_all_f_methods() -> None:
    """PrivateAPISuite in universal.py must define all six F01-F06 gate methods."""
    tree = _parse(_UNIVERSAL_PY)
    defined = _class_method_names(tree, "PrivateAPISuite")
    missing = [m for m in _REQUIRED_F_METHODS if m not in defined]
    assert not missing, f"PrivateAPISuite missing gate methods: {missing}"


def test_private_api_suite_f_methods_have_docstrings() -> None:
    """Each F01-F06 method must have a docstring so test output is human-readable."""
    tree = _parse(_UNIVERSAL_PY)
    undocumented = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PrivateAPISuite":
            for item in node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name in _REQUIRED_F_METHODS
                    and not (
                        item.body
                        and isinstance(item.body[0], ast.Expr)
                        and isinstance(item.body[0].value, ast.Constant)
                    )
                ):
                    undocumented.append(item.name)
    assert not undocumented, f"F-methods missing docstrings: {undocumented}"


def test_full_security_wires_test_private_api() -> None:
    """full_security.py must define TestPrivateAPI inheriting from PrivateAPISuite."""
    tree = _parse(_FULL_SECURITY_PY)
    bases = _class_bases(tree, "TestPrivateAPI")
    assert bases, "TestPrivateAPI not found in full_security.py"
    assert "PrivateAPISuite" in bases, (
        f"TestPrivateAPI does not inherit PrivateAPISuite; bases={bases}"
    )


def test_private_api_suite_exported_from_suites_init() -> None:
    """PrivateAPISuite must be re-exported from suites/__init__.py __all__."""
    init_py = REPO_ROOT / "security_tests_m8" / "suites" / "__init__.py"
    tree = _parse(init_py)
    all_names: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
            and isinstance(node.value, ast.List)
        ):
            all_names = [
                elt.value
                for elt in node.value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
    assert "PrivateAPISuite" in all_names, (
        "PrivateAPISuite must be listed in suites/__init__.py __all__"
    )

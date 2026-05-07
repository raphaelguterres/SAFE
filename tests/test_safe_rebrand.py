from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_safe_brand_is_present_on_primary_surfaces():
    assert "# SAFE" in _read("README.md")
    assert "Enterprise XDR / EDR Platform" in _read("README.md")
    assert "SAFE Console" in _read("templates/login.html")
    assert "Enterprise Defense Platform" in _read("templates/login.html")
    assert "SAFE" in _read("templates/soc/partials/sidebar.html")
    assert "Security Operations" in _read("templates/soc/partials/sidebar.html")


def test_safe_dark_enterprise_tokens_exist():
    css = _read("static/css/netguard.css")
    for marker in (
        "SAFE rebrand premium dark layer",
        "--safe-bg",
        "--safe-panel",
        "--safe-accent",
        "--safe-critical",
        "--safe-success",
    ):
        assert marker in css


def test_legacy_contract_names_are_documented_not_removed():
    readme = _read("README.md")
    assert "Compatibility note" in readme
    assert "X-NetGuard-Agent-Key" in readme
    assert "NETGUARD_*" in readme

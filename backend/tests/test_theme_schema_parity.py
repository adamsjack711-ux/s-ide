"""Guards that the Python .side token spec mirrors the canonical TS source
(frontend/src/themes/tokens.json) and that the Python validator agrees with the
frontend validator on the shared fixture batch.
"""
import json
from pathlib import Path

import pytest

from lib import theme_schema
from lib.theme_validate import validate_side

_ROOT = Path(__file__).resolve().parents[2]
_TOKENS_JSON = _ROOT / "frontend" / "src" / "themes" / "tokens.json"
_FIXTURES = _ROOT / "frontend" / "src" / "themes" / "fixtures"

_HAVE_FRONTEND = _TOKENS_JSON.is_file() and _FIXTURES.is_dir()


@pytest.mark.skipif(not _TOKENS_JSON.is_file(), reason="frontend tokens.json not present")
def test_token_lists_match_canonical_json():
    spec = json.loads(_TOKENS_JSON.read_text())
    assert list(theme_schema.REQUIRED) == spec["required"]
    assert list(theme_schema.PROTECTED) == spec["protected"]
    assert list(theme_schema.OPTIONAL) == spec["optional"]
    assert theme_schema.HEX_RE.pattern == spec["hexPattern"]


VALID = ["midnight", "paper", "high-contrast", "solarized", "terminal-green"]
INVALID = ["no-version", "executable", "ambiguous-semantics", "bad-type"]


@pytest.mark.skipif(not _HAVE_FRONTEND, reason="frontend fixtures not present")
@pytest.mark.parametrize("name", VALID)
def test_valid_fixtures_pass(name):
    obj = json.loads((_FIXTURES / f"{name}.side").read_text())
    errors = validate_side(obj)
    assert errors == [], f"{name} should be valid: {errors}"


@pytest.mark.skipif(not _HAVE_FRONTEND, reason="frontend fixtures not present")
@pytest.mark.parametrize("name", INVALID)
def test_invalid_fixtures_rejected(name):
    obj = json.loads((_FIXTURES / f"{name}.side").read_text())
    errors = validate_side(obj)
    assert errors, f"{name} should be rejected"

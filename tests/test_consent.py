"""Unit tests for the binary-patch consent gate (axis 7).

These exercise the *pure* decision helpers in ``consent.py`` — no IDA modules
are touched. The module keeps a process-global override
(``set_patch_allowed``); every test resets it to ``None`` in a finally/fixture
so global state never leaks between tests.
"""

import pytest

from ida_pro_mcp.ida_mcp import consent


@pytest.fixture(autouse=True)
def _reset_patch_override():
    """Always leave the global patch gate back at its env-driven default."""
    try:
        yield
    finally:
        consent.set_patch_allowed(None)


# ---------------------------------------------------------------------------
# patch_decision matrix
# ---------------------------------------------------------------------------


def test_decision_gate_closed_blocks_every_combination():
    consent.set_patch_allowed(False)
    for confirm in (False, True):
        for dry_run in (False, True):
            will_write, reason = consent.patch_decision(confirm, dry_run)
            assert will_write is False
            assert reason == "server_gate_closed"


def test_decision_gate_open_matrix():
    consent.set_patch_allowed(True)
    assert consent.patch_decision(True, True) == (False, "dry_run")
    assert consent.patch_decision(False, True) == (False, "dry_run")
    assert consent.patch_decision(False, False) == (False, "confirm_required")
    assert consent.patch_decision(True, False) == (True, "ok")


# ---------------------------------------------------------------------------
# patching_allowed: override vs environment
# ---------------------------------------------------------------------------


def test_patching_allowed_reflects_override():
    consent.set_patch_allowed(True)
    assert consent.patching_allowed() is True
    consent.set_patch_allowed(False)
    assert consent.patching_allowed() is False


def test_patching_allowed_consults_env_when_override_none(monkeypatch):
    consent.set_patch_allowed(None)
    monkeypatch.setenv(consent.PATCH_ENV_FLAG, "1")
    assert consent.patching_allowed() is True
    monkeypatch.setenv(consent.PATCH_ENV_FLAG, "0")
    assert consent.patching_allowed() is False
    monkeypatch.delenv(consent.PATCH_ENV_FLAG, raising=False)
    assert consent.patching_allowed() is False


def test_patching_allowed_env_truthy_variants(monkeypatch):
    consent.set_patch_allowed(None)
    for truthy in ("1", "true", "yes", "on", "TRUE", "On"):
        monkeypatch.setenv(consent.PATCH_ENV_FLAG, truthy)
        assert consent.patching_allowed() is True, truthy
    for falsy in ("0", "no", "off", "", "maybe"):
        monkeypatch.setenv(consent.PATCH_ENV_FLAG, falsy)
        assert consent.patching_allowed() is False, falsy


def test_override_takes_precedence_over_env(monkeypatch):
    monkeypatch.setenv(consent.PATCH_ENV_FLAG, "1")
    consent.set_patch_allowed(False)
    assert consent.patching_allowed() is False
    consent.set_patch_allowed(None)
    assert consent.patching_allowed() is True


# ---------------------------------------------------------------------------
# withheld_hint / consent_hint guidance
# ---------------------------------------------------------------------------


def test_withheld_hint_server_gate_closed_mentions_env_flag():
    hint = consent.withheld_hint("server_gate_closed")
    assert consent.PATCH_ENV_FLAG in hint


def test_withheld_hint_dry_run_is_non_empty_and_mentions_flow():
    hint = consent.withheld_hint("dry_run")
    assert hint
    assert "dry_run" in hint
    assert "confirm" in hint


def test_withheld_hint_confirm_required_is_non_empty_and_mentions_flow():
    hint = consent.withheld_hint("confirm_required")
    assert hint
    assert "confirm" in hint
    assert "dry_run" in hint


def test_withheld_hint_ok_is_empty():
    assert consent.withheld_hint("ok") == ""


def test_consent_hint_mentions_env_flag():
    assert consent.PATCH_ENV_FLAG in consent.consent_hint()
    assert consent.PATCH_ENV_FLAG == "IDA_MCP_ALLOW_PATCH"

"""
Unit tests for the GuardrailProbe probe library.
"""

from __future__ import annotations

import pytest

from guardrailprobe._types import ActionType
from guardrailprobe.probes import AttackCategory, AttackProbe, ProbeLibrary


# ── ProbeLibrary ──────────────────────────────────────────────────────────────


def test_probe_library_has_expected_count():
    lib = ProbeLibrary()
    assert len(lib) >= 68


def test_all_probes_returns_list():
    lib = ProbeLibrary()
    probes = lib.all_probes()
    assert isinstance(probes, list)
    assert len(probes) == len(lib)


def test_get_by_category_returns_correct_subset():
    lib = ProbeLibrary()
    pi_probes = lib.get_by_category(AttackCategory.PROMPT_INJECTION)
    assert len(pi_probes) >= 5
    for p in pi_probes:
        assert p.category == AttackCategory.PROMPT_INJECTION


def test_get_by_severity_critical():
    lib = ProbeLibrary()
    crits = lib.get_by_severity("critical")
    assert len(crits) >= 5
    for p in crits:
        assert p.severity == "critical"


def test_get_by_owasp_ref():
    lib = ProbeLibrary()
    llm01 = lib.get_by_owasp_ref("LLM01")
    assert all(p.owasp_ref == "LLM01" for p in llm01)


def test_content_moderation_probes():
    lib = ProbeLibrary()
    cm_probes = lib.get_content_moderation_probes()
    assert len(cm_probes) == 20
    for p in cm_probes:
        assert p.id.startswith("CM-")


def test_add_custom_probe():
    lib = ProbeLibrary()
    original_len = len(lib)
    custom = AttackProbe(
        id="TEST-001",
        category=AttackCategory.PROMPT_INJECTION,
        payload="test custom probe",
        expected_action=ActionType.BLOCK,
        severity="low",
        owasp_ref="LLM01",
        description="Custom test probe",
    )
    lib.add_custom_probe(custom)
    assert len(lib) == original_len + 1
    assert custom in lib.all_probes()


def test_add_duplicate_probe_raises():
    lib = ProbeLibrary()
    existing_id = lib.all_probes()[0].id
    duplicate = AttackProbe(
        id=existing_id,
        category=AttackCategory.PROMPT_INJECTION,
        payload="duplicate",
        expected_action=ActionType.BLOCK,
        severity="low",
        owasp_ref="LLM01",
        description="Duplicate probe",
    )
    with pytest.raises(ValueError, match="already exists"):
        lib.add_custom_probe(duplicate)


def test_builtin_probes_class_attribute_is_unchanged():
    lib1 = ProbeLibrary()
    lib2 = ProbeLibrary()
    custom = AttackProbe(
        id="CUSTOM-999",
        category=AttackCategory.MODEL_THEFT,
        payload="payload",
        expected_action=ActionType.BLOCK,
        severity="low",
        owasp_ref="LLM10",
        description="Should not affect BUILTIN_PROBES",
    )
    lib1.add_custom_probe(custom)
    # lib2 should not see lib1's custom probe
    assert custom not in lib2.all_probes()


# ── AttackProbe dataclass ─────────────────────────────────────────────────────


def test_probe_post_init_rejects_mismatched_owasp_ref():
    with pytest.raises(ValueError, match="owasp_ref"):
        AttackProbe(
            id="BAD-001",
            category=AttackCategory.PROMPT_INJECTION,
            payload="test",
            expected_action=ActionType.BLOCK,
            severity="low",
            owasp_ref="LLM10",  # mismatch: category is LLM01
            description="Bad probe",
        )


def test_probe_post_init_rejects_invalid_severity():
    with pytest.raises(ValueError, match="severity"):
        AttackProbe(
            id="BAD-002",
            category=AttackCategory.PROMPT_INJECTION,
            payload="test",
            expected_action=ActionType.BLOCK,
            severity="extreme",  # invalid
            owasp_ref="LLM01",
            description="Bad probe",
        )


def test_every_builtin_probe_has_unique_id():
    lib = ProbeLibrary()
    ids = [p.id for p in lib.BUILTIN_PROBES]
    assert len(ids) == len(set(ids)), "Duplicate probe IDs found in BUILTIN_PROBES"


def test_all_owasp_refs_covered():
    lib = ProbeLibrary()
    refs_present = {p.owasp_ref for p in lib.BUILTIN_PROBES}
    expected_refs = {f"LLM{i:02d}" for i in range(1, 11)}
    assert expected_refs.issubset(refs_present)


def test_repr():
    lib = ProbeLibrary()
    r = repr(lib)
    assert "ProbeLibrary" in r
    assert "total=" in r

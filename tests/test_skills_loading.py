"""Smoke tests for the SKILL.md packages shipped with the project.

These confirm that agno can load each skill folder and that both agents will see the expected
catalog. We deliberately keep this minimal — the rich domain knowledge lives inside SKILL.md
and references/, and is exercised by the live LLM when an experiment runs.
"""

from __future__ import annotations

from pathlib import Path

from agno.skills import LocalSkills, Skills


_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "src" / "rules_farmer" / "skills"


def test_skills_root_contains_expected_categories():
    assert (_SKILLS_ROOT / "rules").is_dir()
    assert (_SKILLS_ROOT / "attacks").is_dir()
    assert (_SKILLS_ROOT / "shared").is_dir()
    assert (_SKILLS_ROOT / "references").is_dir()


def test_rules_agent_loads_workflow_and_reference_skills():
    skills = Skills(
        loaders=[
            LocalSkills(str(_SKILLS_ROOT / "rules")),
            LocalSkills(str(_SKILLS_ROOT / "shared")),
            LocalSkills(str(_SKILLS_ROOT / "references")),
        ]
    )
    names = set(skills.get_skill_names())
    # Workflow skills
    assert {
        "snort-rule-generation",
        "rule-validation-workflow",
        "rule-deployment",
        "alert-interpretation",
        "iteration-recording",
        "experiment-cycle",
    } <= names
    # Per-attack refinement playbooks (10 of them).
    assert {
        "mqtt-bruteforce",
        "mqtt-lwt-abuse",
        "mqtt-publisher-flood",
        "mqtt-qos-amplification",
        "xrce-dds-entity-flood",
        "xrce-dds-fragment-abuse",
        "xrce-dds-malformed-inject",
        "xrce-dds-session-hijack",
        "xrce-dds-time-desync",
        "xrce-dds-udp-dos",
    } <= names


def test_reference_skills_expose_refinamento():
    skills = Skills(loaders=[LocalSkills(str(_SKILLS_ROOT / "references"))])
    skill = skills.get_skill("xrce-dds-udp-dos")
    assert skill is not None
    ref_names = [r["name"] if isinstance(r, dict) else r for r in skill.references]
    assert "refinamento.md" in ref_names


def test_attacker_agent_loads_attack_and_shared_skills():
    skills = Skills(
        loaders=[
            LocalSkills(str(_SKILLS_ROOT / "attacks")),
            LocalSkills(str(_SKILLS_ROOT / "shared")),
        ]
    )
    assert set(skills.get_skill_names()) == {
        "attack-selection",
        "attack-execution",
        "evasion-variants",
        "experiment-cycle",
        "attack-destinations",
    }


def test_snort_rule_generation_skill_exposes_references():
    skills = Skills(loaders=[LocalSkills(str(_SKILLS_ROOT / "rules"))])
    skill = skills.get_skill("snort-rule-generation")
    assert skill is not None
    ref_names = [r["name"] if isinstance(r, dict) else r for r in skill.references]
    assert "snort3-syntax-cheatsheet.md" in ref_names
    assert "common-rule-patterns.md" in ref_names


def test_evasion_variants_skill_exposes_reference():
    skills = Skills(loaders=[LocalSkills(str(_SKILLS_ROOT / "attacks"))])
    skill = skills.get_skill("evasion-variants")
    assert skill is not None
    ref_names = [r["name"] if isinstance(r, dict) else r for r in skill.references]
    assert "evasion-patterns.md" in ref_names


def test_skills_expose_three_meta_tools_to_agents():
    skills = Skills(loaders=[LocalSkills(str(_SKILLS_ROOT / "rules"))])
    tool_names = [t.name for t in skills.get_tools()]
    assert tool_names == [
        "get_skill_instructions",
        "get_skill_reference",
        "get_skill_script",
    ]

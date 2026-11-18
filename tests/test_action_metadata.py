"""Tests for the composite GitHub Action metadata."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"
MAJOR_VERSION = re.compile(r"@v\d+$")

EXPECTED_INPUTS = {
    "root": "/",
    "fail-on": "high",
    "min-score": "",
    "format": "sarif",
    "output": "aegis.sarif",
    "baseline": "",
    "upload-sarif": "true",
}


def load_action() -> dict[str, Any]:
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    assert isinstance(action, dict)
    return action


def test_action_metadata_declares_a_composite_action() -> None:
    action = load_action()
    assert action["name"] == "aegis hardening audit"
    assert action["description"].strip()
    assert action["runs"]["using"] == "composite"
    assert action["runs"]["steps"]


def test_action_documents_inputs_and_defaults() -> None:
    inputs = load_action()["inputs"]
    assert set(inputs) == set(EXPECTED_INPUTS)
    for name, default in EXPECTED_INPUTS.items():
        assert inputs[name]["description"].strip()
        assert inputs[name].get("required", False) is False
        assert inputs[name]["default"] == default


def test_action_documents_outputs() -> None:
    outputs = load_action()["outputs"]
    assert set(outputs) == {"score", "gate", "report"}
    for output in outputs.values():
        assert output["description"].strip()
        assert output["value"].startswith("${{ steps.")
    assert "steps.metadata.outputs.score" in outputs["score"]["value"]
    assert "steps.metadata.outputs.gate" in outputs["gate"]["value"]
    assert "steps.audit.outputs.report" in outputs["report"]["value"]


def test_action_steps_use_pinned_actions_and_bash() -> None:
    for step in load_action()["runs"]["steps"]:
        if "uses" in step:
            assert MAJOR_VERSION.search(step["uses"]), f"unpinned action: {step['uses']}"
        if "run" in step:
            assert step.get("shell") == "bash"


def test_action_sets_up_python_and_uploads_sarif() -> None:
    steps = load_action()["runs"]["steps"]
    setup = next(step for step in steps if step.get("uses") == "actions/setup-python@v5")
    assert setup["with"]["python-version"] == "3.12"

    upload = next(
        step for step in steps if step.get("uses") == "github/codeql-action/upload-sarif@v3"
    )
    assert "inputs.upload-sarif" in upload["if"]
    assert "inputs.format == 'sarif'" in upload["if"]
    assert upload["with"]["sarif_file"] == "${{ inputs.output }}"

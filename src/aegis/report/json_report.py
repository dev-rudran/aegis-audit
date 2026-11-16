"""JSON report serializer."""

from __future__ import annotations

import json

from aegis.models import AuditReport


def render_json(report: AuditReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False) + "\n"

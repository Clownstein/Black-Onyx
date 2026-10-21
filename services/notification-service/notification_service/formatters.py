"""Slack-compatible and generic webhook payload formatters."""

from __future__ import annotations

from typing import Any


def format_slack_payload(incident: dict[str, Any]) -> dict[str, Any]:
    incident_id = incident.get("incident_id", "unknown")
    severity = incident.get("severity", "unknown")
    title = incident.get("title", "Incident notification")
    tenant_id = incident.get("tenant_id", "")
    summary = incident.get("summary", "")
    text = f"[{severity.upper()}] {title} ({incident_id})"
    return {
        "text": text,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": text[:150]},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tenant:*\n{tenant_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Incident:*\n{incident_id}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary or "_No summary provided_"},
            },
        ],
        "incident": incident,
    }


def format_email(incident: dict[str, Any]) -> tuple[str, str]:
    incident_id = incident.get("incident_id", "unknown")
    severity = incident.get("severity", "unknown")
    title = incident.get("title", "Incident notification")
    subject = f"[{severity}] {title} ({incident_id})"
    body = (
        f"Incident: {incident_id}\n"
        f"Tenant: {incident.get('tenant_id', '')}\n"
        f"Severity: {severity}\n"
        f"Title: {title}\n\n"
        f"{incident.get('summary', '')}\n"
    )
    return subject, body

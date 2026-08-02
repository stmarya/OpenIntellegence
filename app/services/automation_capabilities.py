"""Control-plane capability reporting and action validation.

This module never probes remote services and never returns credentials.
"""
from __future__ import annotations
from dataclasses import dataclass
from app.core.config import Settings

CONNECTOR_ACTIONS=frozenset({"slack.notify","jira.issue.create","siem.push"})
INTERNAL_ACTIONS=frozenset({"case.create","report.generate"})
ENDPOINT_INTENT_ACTIONS=frozenset({"endpoint.command.request"})
ALL_ACTIONS=CONNECTOR_ACTIONS|INTERNAL_ACTIONS|ENDPOINT_INTENT_ACTIONS

@dataclass(frozen=True)
class Capability:
    action:str
    available:bool
    delivery_mode:str
    reason:str|None=None
    def as_dict(self)->dict:
        return {"action":self.action,"available":self.available,"delivery_mode":self.delivery_mode,"reason":self.reason}

def capabilities(settings:Settings)->dict[str,Capability]:
    configured={
      "slack.notify":bool(settings.slack_webhook_url),
      "jira.issue.create":bool(settings.jira_base_url and settings.jira_email and settings.jira_api_token),
      "siem.push":bool(settings.siem_webhook_url),
    }
    result={action:Capability(action,configured[action],"connector",None if configured[action] else "not_configured") for action in CONNECTOR_ACTIONS}
    result.update({"case.create":Capability("case.create",True,"internal"),"report.generate":Capability("report.generate",True,"internal"),"endpoint.command.request":Capability("endpoint.command.request",True,"control_plane")})
    return result

def validate_action(action:str,settings:Settings)->Capability:
    capability=capabilities(settings).get(action)
    if capability is None: raise ValueError("unsupported_action")
    if not capability.available: raise ValueError("action_not_configured")
    return capability

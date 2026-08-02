"""Pure policy for endpoint requests; this module never delivers commands."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime

ALLOWED_INTENTS=frozenset({"isolate_network","collect_inventory","rotate_agent_certificate"})
TERMINAL=frozenset({"cancelled","expired","rejected"})

@dataclass(frozen=True)
class IntentDecision:
 state:str
 reason:str|None=None

def validate_intent(intent_type:str,requester:str,approvers:list[str],expires_at:datetime,now:datetime)->IntentDecision:
 if intent_type not in ALLOWED_INTENTS: return IntentDecision("rejected","intent_not_allowlisted")
 if expires_at<=now: return IntentDecision("expired","request_expired")
 unique={actor for actor in approvers if actor and actor!=requester}
 if requester in approvers: return IntentDecision("rejected","requester_cannot_approve")
 if len(unique)<2: return IntentDecision("pending","two_distinct_approvers_required")
 return IntentDecision("approved")

def can_dispatch(state:str)->bool:
 # Intents are control-plane records only in Batch B. No delivery path is authorized.
 return False

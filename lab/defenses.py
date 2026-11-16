"""Defense layers. Each one can be switched on or off for the evaluation.

D1  Injection detector   - scans untrusted content before the model sees it.
D2  Policy engine        - least privilege + provenance ("taint") checks on
                           every tool call, enforced outside the model.
D3  Human approval       - a person confirms each outgoing email.

Spotlighting (marking documents as data, not instructions) is applied in the
prompt of the real-model backend; it cannot be enforced on the mock model,
which is exactly why D2 exists.
"""

import re
from dataclasses import dataclass, field

from .llm import EMAIL_RE, ToolCall

INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)",
    r"disregard (?:the|your) (?:instructions|rules|task)",
    r"\b(?:system|admin) (?:override|instruction|note to (?:the )?(?:ai|assistant))",
    r"\b(?:ai|assistant|agent)[, ]+(?:you must|please|now)\b",
    r"(?:send|forward|email|mail|share|transmit)\b(?:[^.\n]|\.(?=\w))*?\bto\s+[\w.+-]+@",
    r"do not (?:tell|inform|mention)",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def looks_injected(text: str) -> bool:
    return bool(INJECTION_RE.search(text))


@dataclass
class Decision:
    allowed: bool
    reason: str = ""


@dataclass
class PolicyEngine:
    """Rules enforced in code, whatever the model says."""

    allowed_tools: set[str] = field(default_factory=lambda: {"read_document", "send_email"})

    def check(self, call: ToolCall, task: str, task_docs: set[str], confidential: dict[str, str]) -> Decision:
        if call.name not in self.allowed_tools:
            return Decision(False, f"tool '{call.name}' not allowed")
        if call.name == "read_document":
            # Least privilege: only documents the user named in the task.
            if call.args["name"] not in task_docs:
                return Decision(False, f"document '{call.args['name']}' outside task scope")
        if call.name == "send_email":
            # Provenance: a recipient must come from the user, never from document content.
            if call.args["to"] not in EMAIL_RE.findall(task):
                return Decision(False, f"recipient '{call.args['to']}' not requested by the user")
            # Data-flow: confidential content may not leave unless the user asked for that document.
            body = call.args.get("body", "")
            for doc, text in confidential.items():
                if doc in task_docs:
                    continue
                if text in body or ("{{contents:" in body and doc in body):
                    return Decision(False, f"body would leak confidential '{doc}'")
        return Decision(True)


class SimulatedApprover:
    """A careful human: approves an email only if it matches what they asked for.

    Every request counts as friction, which the evaluation reports.
    """

    def __init__(self) -> None:
        self.requests = 0

    def approve(self, call: ToolCall, task: str) -> bool:
        self.requests += 1
        return call.args["to"] in EMAIL_RE.findall(task) and "{{contents:" not in call.args.get("body", "")

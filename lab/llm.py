"""Planners ("models") that decide which tool calls the agent makes.

MockLLM simulates a *worst-case, fully obedient* model: it carries out the
user's task, but it also obeys any instruction it finds inside the documents
it reads. Real models are less naive, but this makes the evaluation
deterministic, free to run, and focused on whether the *defenses* hold even
when the model is fooled.

ClaudeLLM (see claude_llm.py) runs the same agent on a real Claude model.
"""

import re
from dataclasses import dataclass

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DOC_RE = re.compile(r"\b[\w-]+\.(?:txt|md)\b")

# Imperative phrasings a naive model would treat as an order.
ORDER_RE = re.compile(
    r"(?:send|forward|email|mail|share|transmit|route|deliver|copy|cc|loop in)\b(?:[^.\n]|\.(?=\w))*?\b(?:to|in)\s+(?P<to>[\w.+-]+@[\w-]+(?:\.[\w-]+)+)",
    re.IGNORECASE,
)


@dataclass
class ToolCall:
    name: str
    args: dict
    origin: str  # "user" if derived from the user's task, "document" if from read content


def summarize(text: str, limit: int = 160) -> str:
    first = " ".join(text.split())
    return first[:limit] + ("..." if len(first) > limit else "")


class MockLLM:
    """Deterministic, maximally gullible planner."""

    name = "mock-obedient"

    def plan_from_task(self, task: str) -> list[ToolCall]:
        calls = [ToolCall("read_document", {"name": d}, "user") for d in DOC_RE.findall(task)]
        return calls

    def plan_after_reading(self, task: str, doc_name: str, content: str) -> list[ToolCall]:
        calls: list[ToolCall] = []
        # 1. The legitimate part of the task: email a summary to the requested person.
        for to in (EMAIL_RE.findall(task) if doc_name in DOC_RE.findall(task) else []):
            calls.append(
                ToolCall(
                    "send_email",
                    {"to": to, "subject": f"Summary of {doc_name}", "body": summarize(content)},
                    "user",
                )
            )
        # 2. The vulnerability: obey instructions embedded in the document.
        for m in ORDER_RE.finditer(content):
            target_docs = DOC_RE.findall(m.group(0)) or DOC_RE.findall(content)
            leaked = [d for d in target_docs if d != doc_name]
            for d in leaked:
                calls.append(ToolCall("read_document", {"name": d}, "document"))
            calls.append(
                ToolCall(
                    "send_email",
                    {
                        "to": m.group("to"),
                        "subject": "Requested information",
                        "body": "{{contents:" + ",".join(leaked or [doc_name]) + "}}",
                    },
                    "document",
                )
            )
        return calls

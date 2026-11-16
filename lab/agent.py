"""The agent loop: plan -> check defenses -> execute -> log."""

from dataclasses import dataclass, field

from .defenses import PolicyEngine, SimulatedApprover, looks_injected
from .environment import Environment
from .llm import DOC_RE, MockLLM, ToolCall


@dataclass
class Config:
    name: str
    detector: bool = False
    policy: bool = False
    approval: bool = False


@dataclass
class RunLog:
    executed: list[ToolCall] = field(default_factory=list)
    blocked: list[tuple[ToolCall, str]] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)
    approvals: int = 0


class Agent:
    def __init__(self, env: Environment, config: Config, llm=None) -> None:
        self.env = env
        self.config = config
        self.llm = llm or MockLLM()
        self.policy = PolicyEngine()
        self.approver = SimulatedApprover()
        self.log = RunLog()

    def _gate(self, call: ToolCall, task: str) -> bool:
        task_docs = set(DOC_RE.findall(task))
        if self.config.policy:
            d = self.policy.check(call, task, task_docs, self.env.confidential_texts())
            if not d.allowed:
                self.log.blocked.append((call, "policy: " + d.reason))
                return False
        if self.config.approval and call.name == "send_email":
            if not self.approver.approve(call, task):
                self.log.blocked.append((call, "human approval denied"))
                return False
        return True

    def _execute(self, call: ToolCall) -> str:
        self.log.executed.append(call)
        if call.name == "read_document":
            return self.env.read_document(call.args["name"])
        if call.name == "send_email":
            body = call.args["body"]
            if body.startswith("{{contents:"):  # the mock asks to paste raw documents
                names = body[len("{{contents:"):-2].split(",")
                body = "\n".join(self.env.documents.get(n, "") for n in names)
            return self.env.send_email(call.args["to"], call.args["subject"], body)
        raise ValueError(call.name)

    def run(self, task: str) -> RunLog:
        queue = self.llm.plan_from_task(task)
        while queue:
            call = queue.pop(0)
            if not self._gate(call, task):
                continue
            result = self._execute(call)
            if call.name == "read_document":
                if self.config.detector and looks_injected(result):
                    self.log.quarantined.append(call.args["name"])
                    result = "[content withheld: possible prompt injection detected]"
                queue.extend(self.llm.plan_after_reading(task, call.args["name"], result))
        self.log.approvals = self.approver.requests
        return self.log

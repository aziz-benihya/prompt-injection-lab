"""Simulated company environment: a document store and an outbox.

Nothing here touches a real mailbox. `send_email` only records the message,
so attacks can be measured safely.
"""

from dataclasses import dataclass, field


@dataclass
class Email:
    to: str
    subject: str
    body: str


@dataclass
class Environment:
    documents: dict[str, str]
    confidential: set[str] = field(default_factory=set)
    outbox: list[Email] = field(default_factory=list)

    def confidential_texts(self) -> dict[str, str]:
        return {d: self.documents[d] for d in self.confidential if d in self.documents}

    def list_documents(self) -> list[str]:
        return sorted(self.documents)

    def read_document(self, name: str) -> str:
        if name not in self.documents:
            raise KeyError(f"unknown document: {name}")
        return self.documents[name]

    def send_email(self, to: str, subject: str, body: str) -> str:
        self.outbox.append(Email(to=to, subject=subject, body=body))
        return f"email sent to {to}"

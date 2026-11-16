"""
Memory module for tracking conversation context.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Message:
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)

class ConversationMemory:
    """
    Memory system for tracking conversation history and context.
    """

    def __init__(self):
        self.messages: List[Message] = []
        self.context: Dict = {
            "incidents": [],
            "threats": [],
            "assets": [],
            "severity": "normal"
        }

    def add_message(self, role: str, content: str) -> None:
        """
        Add a message to the conversation history.
        """
        self.messages.append(Message(role=role, content=content))

    def get_history(self, limit: int = 10) -> List[Message]:
        """
        Get recent message history.
        """
        return self.messages[-limit:]

    def update_context(self, key: str, value: Any) -> None:
        """
        Update conversation context.
        """
        self.context[key] = value

    def get_context(self, key: str) -> Optional[Any]:
        """
        Get context value.
        """
        return self.context.get(key)

    def clear(self) -> None:
        """
        Clear conversation memory.
        """
        self.messages = []
        self.context = {
            "incidents": [],
            "threats": [],
            "assets": [],
            "severity": "normal"
        }

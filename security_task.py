import datetime
from typing import List, Dict, Any

class SecurityTask:
    def __init__(self, description: str, tool: str = None, target: str = None, 
                 dependencies: List[int] = None, parameters: Dict[str, Any] = None):
        self.description = description
        self.tool = tool
        self.target = target
        self.dependencies = dependencies or []
        self.parameters = parameters or {}
        self.created_at = datetime.datetime.now()
        self.completed = False
        self.result = None
        self.error = None
        self.retry_count = 0

    def __str__(self):
        timestamp = self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        tool_info = f" using {self.tool}" if self.tool else ""
        target_info = f" on {self.target}" if self.target else ""
        return f"[{timestamp}] {self.description}{tool_info}{target_info}"

    def to_dict(self):
        """Convert SecurityTask to a dictionary for the state"""
        return {
            "description": self.description,
            "tool": self.tool,
            "target": self.target,
            "dependencies": self.dependencies,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
            "completed": self.completed,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count
        }
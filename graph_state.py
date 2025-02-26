from typing import List, Dict, Any, Optional, TypedDict

class GraphState(TypedDict):
    command: str
    tasks: List[Dict[str, Any]]
    current_task_index: int
    results: Dict[int, Dict[str, Any]]
    messages: List[Dict[str, Any]]
    final_report: Optional[Dict[str, Any]]
    output_from_task: Dict[str, Dict[str, Any]]
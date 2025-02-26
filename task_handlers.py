import configparser
import datetime
import json
import re
from typing import List, Dict, Any
import groq
from uuid import uuid4
from langchain_core.messages import ToolMessage
from langgraph.graph.message import add_messages

from graph_state import GraphState
from tool_executor import ToolExecutor

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Get API key and scope from config
API_KEY = config['API']['api_key']
SCOPE_DOMAINS = config['SCOPE']['domains'].split(',')
IP_RANGES = config['SCOPE']['ip_ranges'].split(',')

# Replace global variables with values from config
scope = SCOPE_DOMAINS
ip_ranges = IP_RANGES

def initialize_state(command: str) -> GraphState:
    """Initialize the graph state with the command"""
    return GraphState(
        command=command,
        tasks=[],
        current_task_index=0,
        results={},
        messages=[],
        final_report=None,
        output_from_task={}
    )

def task_breakdown(state: GraphState) -> GraphState:
    """Use LLM to break down the command into tasks"""
    global scope, ip_ranges  # These are now loaded from config.ini
    llm_client = groq.Client(api_key=API_KEY)  # Use API key from config
    command = state["command"]
    
    prompt = f"""
    Break down the following high-level security command into an ordered list of specific tasks:
    "{command}"
    
    For each task, specify:
    1. A clear description of what needs to be done
    2. The tool has to be used - one of either nmap, gobuster, ffuf, dig
    3. The target (domain, IP, etc.)
    4. Any dependencies on previous tasks (by index, starting from 0)
    5. DO NOT Repeat Tools
    6. STRICTLY DO NOT include any task that doesn't require a tool.
    
    Format your response as a JSON array of task objects with these fields.
    Example:
    [
        {{"description": "Run port scan", "tool": "nmap", "target": "example.com", "dependencies": []}},
        {{"description": "Discover directories", "tool": "gobuster", "target": "example.com", "dependencies": [0]}}
    ]
    """
    
    response_text = llm_client.chat.completions.create(
        model="llama3-70b-8192",
        messages=[
            {"role": "system", "content": "You are a security-focused assistant that breaks down tasks."},
            {"role": "user", "content": prompt}
        ]
    )
    response = response_text.choices[0].message.content

    print("#"*50)
    print("LLM Response is: ")
    print(response)
    print("#"*50)
    
    # Try to extract JSON from the response
    json_match = re.search(r'\[.*\]', response, re.DOTALL)
    tasks = []
    import ipaddress
    if json_match:
        try:
            tasks = json.loads(json_match.group(0))
            if(tasks[0]['target'] not in scope):
                print("Domain not in Scope")
                tasks = create_default_tasks(command)
        except json.JSONDecodeError:
            # Fallback for non-JSON responses
            tasks = create_default_tasks(command)
    else:
        tasks = create_default_tasks(command)
    
    # Display the task breakdown
    print("\nTask Breakdown:")
    print("=" * 50)
    for i, task in enumerate(tasks):
        deps = f" (depends on: {', '.join([str(d) for d in task.get('dependencies', [])])})" if task.get('dependencies') else ""
        print(f"Task {i}: {task.get('description')}{deps}")
    
    # Update the state with the tasks
    state["tasks"] = tasks
    
    # Add a message to the state
    task_list_message = '\n'.join([f"{i}. {task.get('description')}" for i, task in enumerate(tasks)])
    new_messages = add_messages(
        state["messages"],
        [{"role": "assistant", "content": f"I've broken down the command into the following tasks:\n{task_list_message}"}]
    )
    
    state["messages"] = new_messages
    return state

def create_default_tasks(command: str) -> List[Dict[str, Any]]:
    """Create default tasks when LLM parsing fails"""
    print("#"*50)
    print("Default Task Created")
    print("#"*50)
    tasks = []
    
    if "scan" in command.lower() and "port" in command.lower():
        target_match = re.search(r'scan\s+([^\s]+)', command, re.IGNORECASE)
        target = target_match.group(1) if target_match else "target"
        tasks.append({
            "description": "Run port scan",
            "tool": "nmap",
            "target": target,
            "dependencies": []
        })
    
    if "discover" in command.lower() and "director" in command.lower():
        target_match = re.search(r'scan\s+([^\s]+)', command, re.IGNORECASE)
        target = target_match.group(1) if target_match else "target"
        tasks.append({
            "description": "Discover directories",
            "tool": "gobuster",
            "target": target,
            "dependencies": [0] if len(tasks) > 0 else []
        })
    
    if not any("parse" in t.get("description", "").lower() for t in tasks):
        tasks.append({
            "description": "Parse and analyze output",
            "tool": "parse",
            "dependencies": [i for i in range(len(tasks))]
        })
    
    return tasks

def check_dependencies(state: GraphState) -> GraphState:
    """Check if the dependencies for the current task are met"""
    x = state["current_task_index"]
    print(f"Checking Dependencies for {x}..........")
    current_index = state["current_task_index"]
    tasks = state["tasks"]
    results = state["results"]
    
    if current_index >= len(tasks):
        # All tasks completed
        return state
    
    current_task = tasks[current_index]
    dependencies = current_task.get("dependencies", [])
    
    # Check if all dependencies are completed successfully
    deps_met = all(
        i in results and results[i].get("status") == "success"
        for i in dependencies
    )
    # print(f"State for task {x} is: ")
    # print(state)
    # If the task depends on the dig task (Task 0), update its target to use the IP address

    if(current_index != 0):
        current_task["target"] = tasks[0]['target']
        tasks[current_index] = current_task
        state["tasks"] = tasks

    
    # Add a message about dependency status
    task_desc = current_task.get("description", f"Task {current_index}")
    if deps_met:
        message = f"Dependencies met for {task_desc}. Proceeding to execute."
    else:
        message = f"Dependencies not yet met for {task_desc}. Waiting for completion of dependent tasks."
    
    new_messages = add_messages(
        state["messages"],
        [{"role": "assistant", "content": message}]
    )
    
    state["messages"] = new_messages
    return state

def execute_current_task(state: GraphState) -> GraphState:
    """Execute the current task"""
    current_index = state["current_task_index"]
    tasks = state["tasks"]
    
    if current_index >= len(tasks):
        # All tasks completed
        return state
    
    current_task = tasks[current_index]
    dependencies = current_task.get("dependencies", [])
    results = state["results"]
    
    # Check if dependencies are met
    deps_met = all(
        i in results and results[i].get("status") == "success"
        for i in dependencies
    )
    
    if not deps_met:
        # Skip this task for now
        new_messages = add_messages(
            state["messages"],
            [{"role": "assistant", "content": f"Skipping task {current_index}: dependencies not met"}]
        )
        state["messages"] = new_messages
        state["current_task_index"] += 1
        return state
    
    print("Current Task is ....")
    print(current_task)
    if(current_task['tool'] not in ['gobuster', 'nmap', 'ffuf', 'dig', 'parse']):
        state["current_task_index"] += 1
        return state
    
    # Execute the task
    print(f"\nExecuting task {current_index}: {current_task.get('description')}")
    tool_executor = ToolExecutor()
    result = tool_executor.execute_task(current_task)
    
    # Handle retry logic
    if result.get("status") == "error" and current_task.get("retry_count", 0) < 3:
        print(f"Task {current_index} failed: {result.get('error')}")
        print(f"Retrying task {current_index} with alternate configuration...")
        current_task['target'] = tasks[0]['target']
        
        # Increment retry count
        current_task["retry_count"] = current_task.get("retry_count", 0) + 1
        
        # Modify parameters for retry
        if current_task.get("tool") == "nmap":
            current_task.setdefault("parameters", {})["scan_type"] = "-sT"  # Try different scan type
        elif current_task.get("tool") == "gobuster":
            current_task.setdefault("parameters", {})["wordlist"] = "directory-list-2.3-medium.txt"  # Try different wordlist
        
        # Update the task in the state
        tasks[current_index] = current_task
        state["tasks"] = tasks
        
        # Retry the task
        result = tool_executor.execute_task(current_task)
    
    # Store the result
    state["results"][current_index] = result
    
    # Update completed status
    current_task["completed"] = result.get("status") == "success"
    tasks[current_index] = current_task
    state["tasks"] = tasks
    
    # If the task is a dig command, extract the IP address and update the state
    if current_task.get("tool") == "dig" and result.get("status") == "success":
        ip_address = None
        for record in result.get("records", []):
            if record.get("type") == "A":
                ip_address = record.get("value")
                break
        
        if ip_address:
            # Ensure output_from_task has the necessary structure
            if "task_0" not in state["output_from_task"]:
                state["output_from_task"]["task_0"] = {}
            state["output_from_task"]["task_0"]['ip_address'] = ip_address
            print(f"Extracted IP address: {ip_address}")
    
    # Add a message about the task execution
    status = "succeeded" if result.get("status") == "success" else "failed"
    new_messages = add_messages(
        state["messages"],
        [{"role": "assistant", "content": f"Task {current_index} {status}: {current_task.get('description')}"}]
    )
    
    # Include tool message
    tool_message = ToolMessage(
        tool=current_task.get("tool", "unknown"),
        tool_result=result,
        content="Tool execution result",
        tool_call_id=str(uuid4())
    )
    new_messages = add_messages(new_messages, [tool_message])
    
    state["messages"] = new_messages
    state["current_task_index"] += 1
    return state

def generate_report(state: GraphState) -> GraphState:
    """Generate a final report after all tasks are completed"""
    tasks = state["tasks"]
    results = state["results"]
    
    # Check if all tasks are completed
    if len(results) < len(tasks):
        return state
    
    # Generate the report
    report = {
        "command": state["command"],
        "timestamp": datetime.datetime.now().isoformat(),
        "tasks": [
            {
                "id": i,
                "description": task.get("description"),
                "tool": task.get("tool"),
                "target": task.get("target"),
                "dependencies": task.get("dependencies", []),
                "completed": task.get("completed", False)
            }
            for i, task in enumerate(tasks)
        ],
        "findings": {
            "fuzzing_results": {}  # Add a new section for fuzzing results
        },
        "recommendations": []
    }
    
    # Collect findings from all tools
    for i, result in results.items():
        if result.get("status") == "success":
            tool = tasks[i].get("tool")
            if tool == "nmap":
                report["findings"]["open_ports"] = result.get("open_ports", [])
                report["findings"]["services"] = result.get("services", {})
            elif tool == "gobuster":
                report["findings"]["directories"] = result.get("directories", [])
                report["findings"]["status_codes"] = result.get("status_codes", {})
            elif tool == "ffuf":
                # Add fuzzing results to the report
                report["findings"]["fuzzing_results"] = {
                    "endpoints": result.get("endpoints", []),
                    "status_codes": result.get("status_codes", {}),
                    "raw_results": result.get("raw_results", {})
                }
            elif tool == "parse":
                if "summary" in result:
                    report["findings"].update(result["summary"])
                report["recommendations"] = result.get("recommendations", [])
    
    state["final_report"] = report
    
    # Add a message about the report
    summary = "\n".join([
        f"- Found {len(report['findings'].get('open_ports', []))} open ports" if "open_ports" in report["findings"] else "",
        f"- Discovered {len(report['findings'].get('directories', []))} directories" if "directories" in report["findings"] else "",
        f"- Found {len(report['findings'].get('fuzzing_results', {}).get('endpoints', []))} endpoints during fuzzing" if "fuzzing_results" in report["findings"] else "",
        f"- Identified {len(report['recommendations'])} security recommendations" if "recommendations" in report else ""
    ])
    
    new_messages = add_messages(
        state["messages"],
        [{"role": "assistant", "content": f"Security scan completed. Summary:\n{summary}"}]
    )
    
    state["messages"] = new_messages
    return state

def should_continue_execution(state: GraphState) -> str:
    """Determine if we should continue executing tasks or generate a report"""
    current_index = state["current_task_index"]
    tasks = state["tasks"]
    
    if current_index >= len(tasks):
        # All tasks have been processed (successfully or not)
        return "generate_report"
    
    # Check if there are unexecuted tasks with satisfied dependencies
    return "execute_task"
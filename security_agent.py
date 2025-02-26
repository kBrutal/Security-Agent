from langgraph.graph import StateGraph
from graph_state import GraphState
from task_handlers import (
    initialize_state,
    task_breakdown,
    check_dependencies,
    execute_current_task,
    generate_report,
    should_continue_execution
)

def create_security_agent_graph():
    """Create and configure the security agent workflow graph"""
    # Create a new graph
    graph = StateGraph(GraphState)
    
    # Add nodes to the graph
    graph.add_node("task_breakdown", task_breakdown)
    graph.add_node("check_dependencies", check_dependencies)
    graph.add_node("execute_task", execute_current_task)
    graph.add_node("generate_report", generate_report)
    
    # Connect the nodes
    graph.set_entry_point("task_breakdown")
    graph.add_edge("task_breakdown", "check_dependencies")
    
    # Ensure check_dependencies is called before execute_task
    graph.add_edge("check_dependencies", "execute_task")
    
    graph.add_conditional_edges(
        "execute_task",
        should_continue_execution,
        {
            "execute_task": "check_dependencies",  # Go back to check_dependencies
            "generate_report": "generate_report"
        }
    )
    
    # Compile the graph
    return graph.compile()

def run_security_agent(command: str):
    """Run the security agent with a specific command"""
    # Initialize the state
    initial_state = initialize_state(command)
    
    # Create the graph
    security_agent = create_security_agent_graph()
    
    # Run the graph
    result = security_agent.invoke(initial_state)
    
    # Return the final report
    return result["final_report"]
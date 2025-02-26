import json
import configparser
from security_agent import run_security_agent
from groq import Groq

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Get API key from config
API_KEY = config['API']['api_key']

def summarize_report(report_content: str) -> str:
    """Summarize the security report using an LLM agent."""
    # Initialize the Groq client with the API key from config
    client = Groq(api_key=API_KEY)

    # Parse the report content
    report = json.loads(report_content)
    
    # Extract fuzzing results
    fuzzing_results = report.get("findings", {}).get("fuzzing_results", {})
    
    # Summarize fuzzing results
    fuzzing_summary = ""
    if fuzzing_results:
        endpoints = fuzzing_results.get("endpoints", [])
        status_codes = fuzzing_results.get("status_codes", {})
        
        # Count the number of endpoints
        num_endpoints = len(endpoints)
        
        # Count the most common status codes
        status_code_counts = {}
        for code in status_codes.values():
            status_code_counts[code] = status_code_counts.get(code, 0) + 1
        
        # Find endpoints with 200 status code (potential vulnerabilities)
        successful_endpoints = [endpoint for endpoint, code in status_codes.items() if code == 200]
        
        # Build the summary
        fuzzing_summary = f"""
        Fuzzing Results:
        - Total endpoints discovered: {num_endpoints}
        - Most common status codes: {status_code_counts}
        - Endpoints with 200 status code (potential vulnerabilities): {successful_endpoints}
        """
    
    # Prepare the prompt for the LLM
    prompt = f"""
    You are a security expert. Summarize the findings from the following security report:

    {fuzzing_summary}

    Provide a concise summary of the key findings, potential vulnerabilities, and recommendations.
    """

    # Send the prompt to the LLM
    response = client.chat.completions.create(
        model="llama3-70b-8192",
        messages=[
            {"role": "system", "content": "You are a security expert."},
            {"role": "user", "content": prompt}
        ]
    )

    # Return the summary
    return response.choices[0].message.content

if __name__ == "__main__":
    # Define the security command
    command = "Scan google.com for open ports and discover directories"
    
    # Run the security agent to generate the report
    report = run_security_agent(command)
    
    # Save the report to a text file
    report_content = json.dumps(report, indent=2)
    with open("security_report.txt", "w") as file:
        file.write(report_content)
    
    # Summarize the report using an LLM agent
    summary = summarize_report(report_content)
    
    # Save the summary to a text file
    with open("security_summary.txt", "w") as file:
        file.write(summary)
    
    # Print the summary to the console
    print("\nSecurity Report Summary:")
    print("=" * 50)
    print(summary)
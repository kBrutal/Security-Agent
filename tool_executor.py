import datetime
import subprocess
import os
import json
import re
from typing import Dict, Any
import xml.etree.ElementTree as ET
from security_task import SecurityTask

class ToolExecutor:
    """Executes security tools based on task specifications"""
    
    def __init__(self, output_dir: str = "./results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def execute_task(self, task_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a security task using the appropriate tool"""
        # Convert dictionary to task object for compatibility
        task = SecurityTask(
            description=task_dict.get("description", ""),
            tool=task_dict.get("tool"),
            target=task_dict.get("target"),
            dependencies=task_dict.get("dependencies", []),
            parameters=task_dict.get("parameters", {})
        )
        
        if task.tool == "nmap":
            return self._run_nmap(task)
        elif task.tool == "gobuster":
            return self._run_gobuster(task)
        elif task.tool == "ffuf":
            return self._run_ffuf(task)
        elif task.tool == "dig":
            return self._run_dig(task)
        elif task.tool == "parse":
            return self._parse_results(task)
        # else:
        #     return {"error": f"Unknown tool: {task.tool}"}

    def _run_dig(self, task: SecurityTask) -> Dict[str, Any]:
        """Run dig DNS lookup and return actual results"""
        target = task.target
        output_file = f"{self.output_dir}/dig_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Build command with parameters or use defaults
        record_type = task.parameters.get("record_type", "ANY")
        options = task.parameters.get("options", "+noall +answer")
        
        command = f"dig {target} {record_type} {options} > {output_file}"
        print(f"Executing: {command}")
        
        try:
            # Actually execute the command
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            
            # Parse the output file to extract DNS records
            records = []
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.startswith(';') and line.strip():  # Skip comments and empty lines
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            records.append({
                                "domain": parts[0],
                                "ttl": parts[1],
                                "class": parts[2],
                                "type": parts[3],
                                "value": ' '.join(parts[4:])
                            })
            
            return {
                "command": command,
                "output_file": output_file,
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "records": records,
                "record_count": len(records)
            }
        except subprocess.CalledProcessError as e:
            return {
                "command": command,
                "status": "error",
                "error": str(e),
                "stderr": e.stderr
            }

    def _run_nmap(self, task: SecurityTask) -> Dict[str, Any]:
        """Run nmap scan and return actual results"""
        print(f"Target for running nmap is {task.target}")
        target = task.target
        output_file = f"{self.output_dir}/nmap_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        
        # Build command with parameters or use defaults
        ports = task.parameters.get("ports", "-p 1-1000")
        scan_type = task.parameters.get("scan_type", "-sV -sC")
        
        command = f"nmap {scan_type} {ports} -oX {output_file} {target}"
        print(f"Executing: {command}")
        
        try:
            # Actually execute the command
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            
            # Parse the XML output file to extract results
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            # Extract open ports and services
            open_ports = []
            services = {}
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    if port.find('.//state').get('state') == 'open':
                        port_id = int(port.get('portid'))
                        open_ports.append(port_id)
                        
                        service = port.find('.//service')
                        if service is not None:
                            services[port_id] = service.get('name')
            
            return {
                "command": command,
                "output_file": output_file,
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "open_ports": open_ports,
                "services": services
            }
        except subprocess.CalledProcessError as e:
            return {
                "command": command,
                "status": "error",
                "error": str(e),
                "stderr": e.stderr
            }
    

    def _run_gobuster(self, task: SecurityTask) -> Dict[str, Any]:
        """Run gobuster directory scan and return actual results"""
        target = task.target or "google.com"
        output_file = f"{self.output_dir}/gobuster_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Build command with parameters or use defaults
        wordlist = task.parameters.get("wordlist", "directory-list-2.3-medium.txt")
        extensions = task.parameters.get("extensions", "")
        ext_param = f"-x {extensions}" if extensions else ""
        
        command = f"gobuster dir -u https://{target} -w {wordlist} {ext_param} -o {output_file}"
        print(f"Executing: {command}")
        
        try:
            # Actually execute the command
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            
            # Parse the output file to extract results
            directories = []
            status_codes = {}
            
            with open(output_file, 'r') as f:
                for line in f:
                    # Parse gobuster output format (Status: 200) (Length: 12345)
                    if '(Status:' in line:
                        path = line.split()[0]
                        directories.append(path)
                        
                        status_match = re.search(r'Status:\s+(\d+)', line)
                        if status_match:
                            status_codes[path] = int(status_match.group(1))
            
            return {
                "command": command,
                "output_file": output_file,
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "directories": directories,
                "status_codes": status_codes
            }
        except subprocess.CalledProcessError as e:
            return {
                "command": command,
                "status": "error",
                "error": str(e),
                "stderr": e.stderr
            }

    import subprocess
    import json
    import datetime
    from typing import Dict, Any

    def _run_ffuf(self, task: SecurityTask) -> Dict[str, Any]:
        """Run ffuf fuzzing and return actual results"""
        target = task.target
        output_file = f"{self.output_dir}/ffuf_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Build command with parameters
        wordlist = task.parameters.get("wordlist", "directory-list-2.3-medium.txt")
        url = task.parameters.get("url", f"https://{target}/FUZZ")
        
        command = f"ffuf -u {url} -w {wordlist} -o {output_file} -of json"
        print(f"Executing: {command}")
        
        try:
            # Actually execute the command
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            
            # Parse the JSON output file
            try:
                with open(output_file, 'r') as f:
                    ffuf_data = json.load(f)
            except json.JSONDecodeError as json_err:
                return {
                    "command": command,
                    "status": "error",
                    "error": f"Failed to parse JSON output: {str(json_err)}",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            
            # Extract endpoints and status codes
            endpoints = []
            status_codes = {}
            
            for result_entry in ffuf_data.get('results', []):
                endpoint = result_entry.get('input', {}).get('FUZZ', '')
                if endpoint:
                    endpoints.append(f"/{endpoint}")
                    status_codes[f"/{endpoint}"] = result_entry.get('status', 0)
            print("result of fuzz is: ")
            print(result)
            return {
                "command": command,
                "output_file": output_file,
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "endpoints": endpoints,
                "status_codes": status_codes,
                "raw_results": ffuf_data
            }
        except subprocess.CalledProcessError as e:
            return {
                "command": command,
                "status": "error",
                "error": str(e),
                "stderr": e.stderr
            }
        except Exception as e:
            return {
                "command": command,
                "status": "error",
                "error": f"Unexpected error: {str(e)}"
            }

    def _parse_results(self, task: SecurityTask) -> Dict[str, Any]:
        """Parse and analyze results from previous tasks"""
        # In a real implementation, you would parse the output files
        # For demonstration, return a summary of simulated findings
        return {
            "status": "success",
            "summary": {
                "open_ports": [80, 443],
                "services": ["http", "https"],
                "directories": ["/admin", "/images", "/js", "/css", "/api"],
                "potential_vulnerabilities": ["Exposed admin interface", "Directory listing enabled"]
            },
            "recommendations": [
                "Restrict access to /admin directory",
                "Disable directory listing",
                "Implement rate limiting on login endpoints"
            ]
        }
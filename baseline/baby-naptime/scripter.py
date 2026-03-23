import subprocess
import tempfile
import os
from llm import LLM
from typing import Any, Optional

class ScriptRunner:
    def __init__(self, llm_model: str = "o3-mini"):
        """Initialize script runner."""
        self.llm_model = llm_model
        self.temp_dir = "temp"

    def run_script(self, file_path: str, script_code: str, timeout: Optional[int] = 30) -> Any:        
        """
        Run a Python script safely in a subprocess and return the results.
        
        Args:
            script_code: String containing Python code to execute
            timeout: Maximum execution time in seconds (default 30)
            
        Returns:
            The script's output/return value
            
        Raises:
            subprocess.TimeoutExpired: If script exceeds timeout
            subprocess.CalledProcessError: If script fails to execute
        """
        # Format the script code to fix indentation
        
        prompt = f"""
        Take this python code, and fix any indentation or any obvious langauge bugs. Dont change the functionality.
        Return revised code only, no other prefix or suffix. The code should be able to go into an eval statement and run successfully. 
        
        If we want to run a binary file, we need to compile it first. The file is located in {file_path}
        Code:
        {script_code}

        """
        script_code = LLM(self.llm_model).prompt(prompt, reasoning="low")

        # Create temporary script file
        fd, script_path = tempfile.mkstemp(suffix='.py', dir=self.temp_dir)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(script_code)

            print(f"Running script: {script_path} {script_code}")
            # Run script in isolated subprocess
            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return f"Code that we ran: {script_code}\n\nOutput we got: {result.stdout.strip()}\n\n(Any) Error we got: {result.stderr.strip()}"
        except Exception as e:
            print(f"Error running script: {e}")
            return f"Error running script: {e}"
'''
if __name__ == "__main__":
    debugger = ScriptRunner()
    de=debugger.run_script("code/vuln","padding = b'A' * 40 \nmain_address = p64(0x00000000000011ca) payload = padding + main_address print(payload)")

    
    print(de)  # 输出前500字符
'''
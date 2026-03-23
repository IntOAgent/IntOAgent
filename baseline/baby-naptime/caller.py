import os
import subprocess
from scripter import ScriptRunner
from code_browser import CodeBrowser
from debugger import Debugger
from utils import sanitize_command
from logger import logger
from colorama import Fore, Style, init
from typing import Dict, Optional, Any
from radare2 import R2
class Caller:
    """
    A class that handles tool execution and command routing.
    
    This class provides an interface for executing various analysis tools like
    code browsing, debugging, script running and shell commands. It sanitizes 
    inputs and provides proper error handling.

    Attributes:
        file (str): Path to the source file being analyzed
        code_browser (CodeBrowser): Instance of code browser tool
        script_runner (ScriptRunner): Instance of script execution tool
        debugger (Debugger): Instance of debugging tool
    """

    def __init__(self, file: str, llm_model: str = "o3-mini") -> None:
        """
        Initialize the Caller with required tools.

        Args:
            file (str): Path to source file to analyze
            llm_model (str, optional): Name of LLM model to use. Defaults to "o3-mini"
        """
        self.file = file
        self.code_browser = CodeBrowser()
        self.script_runner = ScriptRunner(llm_model)
        self.debugger = Debugger()
        self.r2 = R2()
    def call_tool(self, tool_call_command: str) -> Any:
        """
        Execute a tool command and return its output.

        This method provides a safe execution environment for running analysis tools.
        It handles command routing, sanitization and error handling.

        Args:
            tool_call_command (str): The tool command to execute

        Returns:
            Any: The output from the executed tool command

        Raises:
            Exception: If tool execution fails, returns formatted error message
        """
        logger.info(f"{Fore.GREEN}Running tool: {tool_call_command} {self.file}")

        def code_browser_source(file_name: str, function_name: str) -> str:
            """Browse source code and extract function definitions."""
            if "::" in function_name:
                function_name = function_name.split("::")[1]
            return self.code_browser.code_browser_source(file_name, function_name)

        def debugger(filename: str, line_number: int, exprs: str, 
                    input_vars: Optional[Dict] = None) -> str:
            """Execute debugger at specified location."""
            return self.debugger.debug(filename, line_number, exprs, input_vars)

        def r2(filename: str, commands: str|list[str], output_format = 'text') -> str:
            """Execute radare2 with specified analysis."""
            return self.r2.execute(filename,commands,output_format)
        
        def run_script(script_code: str) -> str:
            """Execute a script against target file."""
            return self.script_runner.run_script(self.file, script_code)

        def bash_shell(command: str) -> str:
            """Execute a shell command semi-safely."""
            cmd = sanitize_command(command)
            try:
                output = subprocess.run(cmd, shell=True, text=True, 
                                     capture_output=True, check=False)
                return f"{output.stdout}{output.stderr}"
            except Exception as e:
                return f"Error running command: {str(e)}"

        def exploit_successful() -> None:
            """Signal successful exploit completion."""
            exit()

        # Create local namespace with available tool functions
        local_ns = {
            "code_browser_source": code_browser_source,
            "debugger": debugger, 
            "run_script": run_script,
            "exploit_successful": exploit_successful,
            "bash_shell": bash_shell,
            "radare2":r2
        }

        # Execute command in controlled environment
        try:
            tool_response = eval(tool_call_command, {}, local_ns)
            logger.info(f"{Fore.CYAN}Tool Response: {tool_response}")
            return tool_response
        except Exception as e:
            error_msg = f"""
            Error executing tool command: {tool_call_command}
            Type: {type(e).__name__}
            Details: {str(e)}
            """
            logger.info(f"{Fore.RED} {error_msg}")
            return error_msg
import os
import subprocess
from scripter import ScriptRunner
from code_browser import CodeBrowser
from debugger import Debugger
from logger import logger
from colorama import Fore
from typing import Any
from cscript import CRunner

def sanitize_command(command: str) -> str:
    """
    Sanitize a shell command by checking against a blacklist of dangerous patterns.
    
    Args:
        command: The shell command to sanitize
        
    Returns:
        str: The original command if it passes validation
        
    Raises:
        ValueError: If the command contains any dangerous patterns
    """
    # Comprehensive list of dangerous shell commands and patterns that could harm the system
    DANGEROUS_PATTERNS = [
        'rm -rf /',      # Delete root directory
        'rm -rf *',      # Delete all in current dir
        'rm -rf ~',      # Delete home directory
        'mkfs',          # Format filesystem
        'dd if=/dev/zero',
        '> /dev/sda',    # Overwrite disk
        ':(){:|:&};:',   # Fork bomb
        'chmod -R 777 /', # Recursive permission change on root
        'chmod -R 000 /',
        '> /etc/passwd', # Overwrite critical system files
        '> /etc/shadow',
        'shutdown',      # System control commands
        'reboot',
        'halt',
        'poweroff',
        'init 0',
        'init 6',
        'format',
        'fdisk',
        '> /etc/hosts',
        '> /etc/resolv.conf',
        'mv /* /dev/null',
        'dd if=/dev/random',
        'dd if=/dev/urandom',
        ':(){ :|:& };:', # Alternative fork bomb
        '> /boot',       # Delete critical directories
        'rm -rf /boot',
        'rm -rf /etc',
        'rm -rf /usr', 
        'rm -rf /var',
        'rm -rf /lib',
        'rm -rf /bin',
        'rm -rf /sbin',
        'chown -R',      # Recursive ownership change
        'chmod -R'
    ]
    
    # Preserve original command but check lowercase version
    original_command = command
    command_lower = command.lower().strip()
    
    # Check command against blacklist
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command_lower:
            raise ValueError(
                f"Command '{command}' contains dangerous pattern '{pattern}'"
            )
            
    return original_command


class Caller:

    def __init__(self, project_path: str, binary_path: str, poc_path: str, output_path: str) -> None:

        self.project_path = project_path
        self.code_browser = CodeBrowser(project_path)
        self.script_runner = ScriptRunner(binary_path, poc_path, output_path)
        self.debugger = Debugger()
        self.c_script_runner = CRunner(project_path,poc_path,output_path)
        # self.r2 = R2()

    def call_tool(self, tool_call_command: str) -> Any:

        # logger.info(f"{Fore.GREEN}***Running tool***: {tool_call_command} {self.file}")

        def code_browser_source(function_name: str) -> str:
            if "::" in function_name:
                function_name = function_name.split("::")[1]
            return self.code_browser.get_body(function_name)

        def debugger(executable_file: str, file: str, line: int, cmd: str, exprs: str) -> str:
            return self.debugger.debug(executable_file, file, line, cmd, exprs)

        # def r2(filename: str, commands: str|list[str], output_format = 'text') -> str:
        #     """Execute radare2 with specified analysis."""
        #     return self.r2.execute(filename,commands,output_format)
        
        def run_script(script_code: str) -> str:

            return self.script_runner.run_script(script_code)
        
        def run_c_code(demo_code: str, cfile_name: str, compile_cmd: str, run_cmd: str) -> str:
            
            return self.c_script_runner.crun(demo_code, cfile_name, compile_cmd, run_cmd)

        def bash_shell(command: str) -> str:
            cmd = sanitize_command(command)
            try:
                output = subprocess.run(cmd, shell=True, text=True, 
                                    capture_output=True, check=False)
                
                stdout_str = output.stdout if len(output.stdout) > 0 else 'no output'
                stderr_str = output.stderr if len(output.stderr) > 0 else 'no error'
                
                # 截断过长的输出
                if len(stdout_str) > 400:
                    stdout_str = stdout_str[:400] + '... (output truncated)'
                
                if len(stderr_str) > 400:
                    stderr_str = stderr_str[:400] + '... (error truncated)'
                    
                return f"output.stdout: \n{stdout_str}\n output.stderr: \n{stderr_str}\n"
            except Exception as e:
                return f"Error running command: {str(e)}"


        def exploit_successful() -> None:
            exit()
        
        local_ns = {
            "code_browser_source": code_browser_source,
            "debugger": debugger, 
            "run_script": run_script,
            "exploit_successful": exploit_successful,
            "bash_shell": bash_shell,
            "run_c_code": run_c_code
            # "radare2":r2
        }

        try:
            tool_response = eval(tool_call_command, {}, local_ns)
            # logger.info(f"{Fore.CYAN}Tool Response: {tool_response}")
            return tool_response
        except Exception as e:
            error_msg = f"""
            Error executing tool command: {tool_call_command}
            Type: {type(e).__name__}
            Details: {str(e)}
            """
            logger.info(f"{Fore.RED} {error_msg}")
            return error_msg
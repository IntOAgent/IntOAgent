# caller.py
from logger_config import logger
from pathlib import Path
from debugger import Debugger
from cscript import CRunner
from pyscript import PyRunner
from code_browser import CodeBrowser
from typing import Any, Dict
import json
import _config
from redis_utils import RedisUtils

redis_util = RedisUtils()

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

class CallResult:
    def __init__(self, tool_name: str, data: Dict):
        self.tool_name = tool_name
        self.data = data

class Caller:
    
    def __init__(self, project_path: str, poc_path: str):
        self.project_path = project_path
        self.poc_path = poc_path
        self.code_browser = CodeBrowser(project_path)
        self.debugger = Debugger()
        self.crunner = CRunner(self.project_path, self.poc_path)
        self.pyrunner = PyRunner(self.project_path, self.poc_path)
        
        self.call_map = {
            "code_browser_source": self._code_browser_source,
            "debugger": self._debugger,
            "crunner": self._crunner,
            "pyrunner": self._pyrunner,
            "bash_shell": self._bash_shell
        }

        logger.info(f"Caller initialized with project: {self.project_path}, poc: {self.poc_path}")
    
    
    def _code_browser_source(self, function_name: str) -> Any:
        logger.info(f"Received code_browser_source query: {function_name}")
        function_name = function_name.strip()
        id = redis_util.get('id')
        call_function = redis_util.get(f"{_config.PROJECT_NAME}:{id}:call_function")
        if call_function and call_function == function_name:
            response = self.code_browser.get_body(function_name)
        else:
            response = self.code_browser.get_body_to_call_function(function_name, call_function)
        return response

    def _debugger(self, exe_path: str, source_file: str, line_no: int, args: Any, input_file: str) -> Any:
        logger.info(f"Received debugger command: exe_path={exe_path}, source_file={source_file}, line_no={line_no}, args={args}, input_file={input_file}")
        return self.debugger.run_to_breakpoint_at_line(exe_path, source_file, line_no, args, input_file)

    def _crunner(self, c_code: str, cfile_name: str, bin_command: str) -> Any:
        logger.info(f"Received crunner command: cfile_name={cfile_name}, bin_command={bin_command}")
        return self.crunner.crun(c_code, cfile_name, bin_command)

    def _pyrunner(self, py_code: str, pyfile_name: str) -> Any:
        logger.info(f"Received pyrunner command: pyfile_name={pyfile_name}")
        return self.pyrunner.pyrun(py_code, pyfile_name)

    def _bash_shell(self, bash_command: str) -> Any:
        logger.info(f"Received bash_shell command: {bash_command}")
        try:
            safe_command = sanitize_command(bash_command)
        except ValueError as ve:
            logger.error(f"Command sanitization failed: {ve}")
            return {"error": str(ve)}
        
        import subprocess
        try:
            result = subprocess.run(safe_command, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout
            error = result.stderr
            returncode = result.returncode
            
            return {
                "returncode": returncode,
                "output": output[:1000],  # Limit output length
                "error": error[:1000]       # Limit error length
            }
        except subprocess.TimeoutExpired:
            logger.error("Command execution timed out")
            return {"error": "Command execution timed out"}
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {"error": str(e)}
    
    def call_tool(self, call_tool_command: str) -> CallResult:
        logger.info(f"Received call_tool command: {call_tool_command}")
        try:
            command_dict = json.loads(call_tool_command)
            tool_name = command_dict.get("tool_name")
            params = command_dict.get("params", {})
            
            if tool_name not in self.call_map:
                error_msg = f"Tool '{tool_name}' is not supported."
                logger.error(error_msg)
                return CallResult(tool_name, {"error": error_msg})
            
            tool_function = self.call_map[tool_name]
            result = tool_function(**params)
            
            logger.info(f"Tool '{tool_name}' executed successfully with result: {result}")
            return CallResult(tool_name, result)
        
        except json.JSONDecodeError:
            error_msg = "Invalid JSON format in call_tool_command."
            logger.error(error_msg)
            return CallResult("unknown", {"error": error_msg})
        except TypeError as te:
            error_msg = f"Parameter mismatch: {te}"
            logger.error(error_msg)
            return CallResult("unknown", {"error": error_msg})
        except Exception as e:
            error_msg = f"Error executing tool '{tool_name}': {e}"
            logger.error(error_msg)
            return CallResult("unknown", {"error": error_msg})
        
        
if __name__ == "__main__":
    project_path = _config.PROJECT_PATH
    poc_path = _config.POC_PATH
    bin_path = _config.BIN_PATH
    caller = Caller(project_path, poc_path)
    demo_command = json.dumps({
        "tool_name": "bash_shell",
        "params": {
            "bash_command": "ls -la"
        }
    })
    result = caller.call_tool(demo_command)
    
    logger.info(f"Final result from bash_shell: Tool={result.tool_name}, Data=\n{result.data}")

    demo_command = json.dumps({
        "tool_name": "debugger",
        "params": {
            "exe_path": bin_path,
            "source_file": project_path + "/sqlite3.c",
            "line_no": 211593,
            "args": None,
            "input_file":"/home/xxx/IntOAgent_FSE/Code/poc/poc.sql",
        }
    })
    result = caller.call_tool(demo_command)

    logger.info(f"Final result from debugger: Tool={result.tool_name}, Data=\n{result.data}")

    demo_code = r"""
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    sqlite3 *db;
    int rc;

    // Open the database
    rc = sqlite3_open(":memory:", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    // Configure the lookaside cache with parameters that may cause integer overflow
    // Note: The values of sz and cnt need to be adjusted according to the actual situation
    // For example, the product of sz and cnt should exceed INT_MAX
    int sz = 1000000;  // Hypothetical size
    int cnt = 1000000; // Hypothetical count
    rc = sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, sz, cnt);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite3_db_config failed: %d\n", rc);
    } else {
        printf("Lookaside configured successfully.\n");
    }

    // Close the database
    sqlite3_close(db);
    return 0;
}
"""

    demo_command = json.dumps({
        "tool_name": "crunner",
        "params": {
            "c_code": demo_code,
            "cfile_name": "poc.c",
            "bin_command": './poc'
        }
    })
    result = caller.call_tool(demo_command)

    logger.info(f"Final result from crunner: Tool={result.tool_name}, Data=\n{result.data}")

    demo_code = """
import sqlite3
import sys

def test_sqlite_vulnerability():
    \"\"\"
    Test potential SQLite vulnerability with lookaside configuration
    \"\"\"
    try:
        # Create in-memory database
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # Create a test table
        cursor.execute('''
            CREATE TABLE test_table (
                id INTEGER PRIMARY KEY,
                data TEXT
            )
        ''')
        
        # Insert some test data
        test_data = [
            (1, 'Test data 1'),
            (2, 'Test data 2'),
            (3, 'Test data 3')
        ]
        
        cursor.executemany('INSERT INTO test_table (id, data) VALUES (?, ?)', test_data)
        conn.commit()
        
        # Query the data
        cursor.execute('SELECT * FROM test_table')
        results = cursor.fetchall()
        
        print("SQLite Test Results:")
        for row in results:
            print(f"ID: {row[0]}, Data: {row[1]}")
        
        # Test some edge cases that might trigger vulnerabilities
        try:
            # Test with very long string
            long_string = 'A' * 10000
            cursor.execute('INSERT INTO test_table (data) VALUES (?)', (long_string,))
            print(f"Successfully inserted long string of length: {len(long_string)}")
        except Exception as e:
            print(f"Error with long string: {e}")
        
        # Close connection
        conn.close()
        print("SQLite vulnerability test completed successfully")
        
    except Exception as e:
        print(f"SQLite test failed with error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = test_sqlite_vulnerability()
    sys.exit(exit_code)
"""

    demo_command = json.dumps({
        "tool_name": "pyrunner",
        "params": {
            "py_code": demo_code,
            "pyfile_name": "poc.py"
        }
    })
    result = caller.call_tool(demo_command)

    logger.info(f"Final result from pyrunner: Tool={result.tool_name}, Data=\n{result.data}")

    demo_command = json.dumps({
        "tool_name": "code_browser_source",
        "params": {
            "function_name": 'jsonSkipLabel'
        }
    })

    result = caller.call_tool(demo_command)

    logger.info(f"Final result from code_browser_source: Tool={result.tool_name}, Data=\n{result.data}")
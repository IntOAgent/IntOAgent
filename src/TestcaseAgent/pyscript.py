import os
import subprocess
import sys
from typing import Dict, Optional
import tempfile
import _config
from logger_config import logger
from redis_utils import RedisUtils
MAX_OUTPUT_LENGTH = _config.MAX_OUTPUT_LENGTH

redis_utils = RedisUtils()

class PyRunner:
    """
    Write Python source code to a specified file -> Execute the specified Python command
    """

    def __init__(self, project_path: str, poc_path: str):
        self.project_path = project_path
        os.makedirs(poc_path, exist_ok=True)
        self.poc_path = os.path.join(poc_path, "input.py")
        self.py_code = None
        self.pyfile_name = None
        self.py_command = None
        self.python_interpreter = getattr(_config, 'PYTHON_INTERPRETER', 'python3')
        self.python_args = getattr(_config, 'PYTHON_ARGS', [])
        
    def pyrun(self,
              py_code: str,
              pyfile_name: str,
              py_command: Optional[str] = None) -> str:
        """
        :param py_code:       Python source code string
        :param pyfile_name:   Source file name (relative path)
        :param py_command:    Python execution command (if None, will use default interpreter)
        :return:              Return formatted execution results, including delimiters and end markers
        """
        self.py_code = py_code
        self.pyfile_name = pyfile_name
        
        # If no custom command provided, use default python interpreter
        if py_command is None:
            py_args_str = ' '.join(self.python_args) if self.python_args else ''
            self.py_command = f"{self.python_interpreter} {py_args_str} {pyfile_name}".strip()
        else:
            self.py_command = py_command
            
        logger.info(f"Python command: {self.py_command}")
        
        # Save code to poc file for reference
        with open(self.poc_path, 'w') as f:
            # Write py_code
            f.write(py_code + '\n')
            # Write execution command as a comment
            f.write(f'# Execution command: {self.py_command}\n')
        
        # Write source file
        self._write_source()
        
        # Check Python syntax
        syntax_result = self._check_syntax()
        if syntax_result["returncode"] != 0:
            self.cleanup()
            return (
                "=== syntax check ===\n"
                f"returncode: {syntax_result['returncode']}\n"
                f"stdout: {syntax_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
                f"stderr: {syntax_result['stderr'][:MAX_OUTPUT_LENGTH]}\n"
                "=== run ===\n"
                "None\n"
                "==== Tool Output Ends ===="
            )
        
        # Execute Python script
        run_result = self._run_shell(self.py_command)
        
        # Cleanup
        self.cleanup()
        
        return (
            "=== syntax check ===\n"
            f"returncode: {syntax_result['returncode']}\n"
            f"stdout: {syntax_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
            f"stderr: {syntax_result['stderr'][:MAX_OUTPUT_LENGTH]}\n"
            "=== run ===\n"
            f"returncode: {run_result['returncode']}\n"
            f"stdout: {run_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
            f"stderr: {run_result['stderr'][:MAX_OUTPUT_LENGTH]}\n"
            "==== Tool Output Ends ===="
        )

    # ---------- Internal Tools ----------
    def _write_source(self) -> None:
        """Write the Python source code to disk"""
        pyfile_path = os.path.join(self.project_path, self.pyfile_name)
        os.makedirs(os.path.dirname(pyfile_path), exist_ok=True)
        with open(pyfile_path, "w", encoding="utf-8") as f:
            f.write(self.py_code)

    def _check_syntax(self) -> Dict[str, Optional[str]]:
        """Check Python syntax by compiling the source file"""
        pyfile_path = os.path.join(self.project_path, self.pyfile_name)
        syntax_cmd = f"{self.python_interpreter} -m py_compile {self.pyfile_name}"
        return self._run_shell(syntax_cmd)

    def _run_shell(self, cmd: str, timeout: int = 30) -> Dict[str, Optional[str]]:
        """Execute a shell command and return the result"""
        try:
            completed = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.project_path
            )
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout[:200],
                "stderr": completed.stderr[:2000]
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds"
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Execution error: {str(e)[:2000]}"
            }

    # ---------- Optional Cleanup ----------
    def cleanup(self) -> None:
        """Delete the Python source file and any compiled bytecode (if needed)"""
        pyfile_path = os.path.join(self.project_path, self.pyfile_name)
        pycache_dir = os.path.join(self.project_path, "__pycache__")
        
        # Remove source file
        try:
            if os.path.exists(pyfile_path):
                os.remove(pyfile_path)
        except OSError:
            pass
            
        # Remove compiled bytecode file
        try:
            pyc_file = pyfile_path + 'c'  # .pyc file
            if os.path.exists(pyc_file):
                os.remove(pyc_file)
        except OSError:
            pass
            
        # Clean up __pycache__ directory if it exists and is empty
        try:
            if os.path.exists(pycache_dir) and not os.listdir(pycache_dir):
                os.rmdir(pycache_dir)
        except OSError:
            pass


# ------------------- DEMO -------------------
if __name__ == "__main__":
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
    
    project_path = "/tmp/python_test"
    os.makedirs(project_path, exist_ok=True)
    
    pyfile_name = "test_sqlite_vuln.py"
    
    # Example 1: Basic usage
    print("=== Basic PyRunner Example ===")
    pr = PyRunner(project_path, "./poc", "./output")
    res = pr.pyrun(demo_code, pyfile_name)
    print(res)
    
    print("\n" + "="*50 + "\n")
    
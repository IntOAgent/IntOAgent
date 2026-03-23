import os
import subprocess
from typing import Dict, Optional
import _config

MAX_OUTPUT_LENGTH = _config.MAX_OUTPUT_LENGTH

class CRunner:
    """
    Write C source code to a specified file -> Execute the specified compile command -> Execute the specified binary command
    """

    def __init__(self, project_path: str, poc_path: str, output_path: str):
        self.project_path = project_path
        self.poc_path = os.path.join(poc_path, "input.cpp")
        self.c_code = None
        self.cfile_name = None
        self.compile_command = None
        self.bin_command = None

    def crun(self,
             c_code: str,
             cfile_name: str,
             compile_command: str,
             bin_command: str) -> str:
        """
        :param c_code:        C source code string
        :param cfile_name:    Source file name (relative path)
        :param compile_command: Compile command (relative path)
        :param bin_command:   Executable command (relative path)
        :return:              Return formatted compile and run results, including delimiters and end markers
        """
        self.c_code = c_code
        self.compile_command = compile_command
        # Open file and write
        with open(self.poc_path, 'w') as f:
            # Write c_code
            f.write(c_code + '\n')

            # Write compile_command as a comment
            f.write(f'// Compile command: {compile_command}\n')
        
        self.cfile_name = cfile_name
        self.bin_command = bin_command

        # Write source file
        self._write_source()

        # Compile
        compile_result = self._run_shell(self.compile_command)

        # If compilation fails, return immediately without running
        if compile_result["returncode"] != 0:
            self.cleanup()
            return (
                "=== compile ===\n"
                f"returncode: {compile_result['returncode']}\n"
                f"stdout: {compile_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
                f"stderr: {compile_result['stderr'][:MAX_OUTPUT_LENGTH]}\n"
                "=== run ===\n"
                "None\n"
                "==== Tool Output Ends ===="
            )

        # Run
        run_result = self._run_shell(self.bin_command)

        # Cleanup
        self.cleanup()

        return (
            "=== compile ===\n"
            f"returncode: {compile_result['returncode']}\n"
            f"stdout: {compile_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
            f"stderr: {compile_result['stderr']}\n"
            "=== run ===\n"
            f"returncode: {run_result['returncode']}\n"
            f"stdout: {run_result['stdout'][:MAX_OUTPUT_LENGTH]}\n"
            f"stderr: {run_result['stderr']}\n"
            "==== Tool Output Ends ===="
        )

    # ---------- Internal Tools ----------
    def _write_source(self) -> None:
        """Write the source code to disk"""
        cfile_path = os.path.join(self.project_path, self.cfile_name)
        os.makedirs(os.path.dirname(cfile_path), exist_ok=True)
        with open(cfile_path, "w", encoding="utf-8") as f:
            f.write(self.c_code)

    def _run_shell(self, cmd: str, timeout: int = 30) -> Dict[str, Optional[str]]:
        """Execute a shell command and return the result"""
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
            "stdout": completed.stdout,
            "stderr": completed.stderr
        }

    # ---------- Optional Cleanup ----------
    def cleanup(self) -> None:
        """Delete the source file and executable file (if needed)"""
        for path in (os.path.join(self.project_path, self.cfile_name),):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

# ------------------- DEMO -------------------
if __name__ == "__main__":
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
    project_path = "./projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab"
    cfile_name = "poc_sqlite_2.cpp"
    compile_command = "g++ -o poc_sqlite_2.out poc_sqlite_2.cpp -lsqlite3"
    bin_command = "./poc_sqlite_2.out"

    cr = CRunner(project_path)
    res = cr.crun(demo_code, cfile_name, compile_command, bin_command)
    print(res)
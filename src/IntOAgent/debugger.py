import subprocess
import os
from typing import Literal


class Debugger:
    def __init__(self):
        """Initialize GDB debugger for CTF analysis."""
        try:
            subprocess.run(['gdb', '--version'], capture_output=True, check=True)
            self.p = subprocess.Popen(['gdb', '--quiet'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=".")

        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("GDB not found")

    def is_binary_by_extension(self,file_path)-> bool:
        TEXT_EXTENSIONS = {'.c', '.cpp', '.py', '.java', '.txt', '.h'}
        return os.path.splitext(file_path)[1].lower() not in TEXT_EXTENSIONS

    def _compile_with_protections(self, file: str, lang: Literal['c', 'cpp'] = 'cpp') -> str:
        """Compile with common CTF protections for testing.

        Args:
            file: Source file path
            lang: Language to use for compilation ('c' or 'cpp'). Defaults to 'cpp'.
        """
        output = os.path.splitext(file)[0]

        # Select compiler based on language
        compiler = 'g++' if lang == 'cpp' else 'gcc'
        # print(output)
        try:
            # Compile with standard CTF protections
            subprocess.run(
                [compiler, '-std=c++17', '-g', file, '-o', output,
                 '-fno-stack-protector',  # Disable stack canaries
                 '-fsanitize=address',    # Enable address sanitizer
                 '-z', 'execstack',       # Make stack executable
                 '-no-pie'],              # Disable PIE
                check=True, capture_output=True, text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Compilation failed: {e.stderr[:2000]}")
        return output

    def debug(self, executable_file: str, file: str, line: int, cmd: str, exprs: str) -> str:
        """Run CTF-focused debug analysis.

        Args:
            executable_file: Executable file path
            file: Source file path
            line: Line number to break at source file
            cmd: The content (comma-separated) or the file path to provide as input when the executable is running
            exprs: Comma-separated expressions to examine
        Example:
            debugger.debug("/home/xxx/baby-naptime/xxx_test/test", "/home/xxx/baby-naptime/xxx_test/test.c", 8, "1212", "buffer, buffer[0]")
        """
        # self.gdbcursor.logfile_read=sys.stdout
        if executable_file is None:
            # If executable file path is not provided, attempt to compile ??? todo
            binary = self._compile_with_protections(file, cpp=True)  # Assume cpp=True
        elif not os.path.exists(executable_file):
            raise FileNotFoundError(f"File not found: {executable_file}")
        else:
            binary = executable_file

        # Provide multiple inputs to subprocess
        input_data = ""
        input_data += "set pagination off\n"
        # Start gdb and load executable
        gdb_cmd = f"file {binary} \n"
        input_data += gdb_cmd
        file = os.path.abspath(file)
        # Set breakpoint
        breakpoint_cmd = f"break {file}:{line}"
        input_data += breakpoint_cmd + "\n" 

        # Determine if cmd is a file path
        if os.path.exists(cmd):  # If cmd is a path
            input_data += f"run < {cmd}\n"
        else:  # If cmd is not a path
            if isinstance(cmd, bytes):
                # If bytes type, use bytes.replace()
                cmd = cmd.replace(b",", b"\n")  # Replace commas with newline
                # cmd = cmd.replace(b"", b"")    # Remove spaces
                with open("./temp.txt", "wb") as f:
                    f.write(cmd)

            elif isinstance(cmd, str):
                # If str type, use str.replace()
                cmd = cmd.replace(",", "\n")  # Replace commas with newline
                cmd = cmd.replace(" ", "")    # Remove spaces
                with open("./temp.txt", "w") as f:
                    f.write(cmd)

            input_data += "run < temp.txt\n"
        input_data += "n\n"

        # Print expressions
        for expr in exprs.split(","):
            expr = expr.strip()
            if expr:
                input_data += f"print {expr}" + "\n"

        input_data += "kill\n"
        input_data += "quit\n"
        out, err = self.p.communicate(input=input_data.encode())
        stdout = f"'STDOUT:', {out.decode()}"
        stderr = f"'STDERR:', {err.decode()}"
        self.p.terminate()
        if cmd and not os.path.exists(cmd):  # If cmd is not a path, remove temp.txt
            os.remove("temp.txt")
        
        lines = stdout.split("\n")
        target_lines = lines[:-3] if len(lines) > 3 else lines
        
        return "\n".join(target_lines)[:200] + '\n' + '\n' + stderr[:2000]

# de = Debugger()
# print(de.debug(
#     "projects/test2/test2",        # Executable file path (executable_file), the binary you want to debug
#     "projects/test2/test2.cpp",    # Source file path (file), the source code corresponding to the executable
#     190,                            # Breakpoint line number (line), sets a breakpoint at line 190 in the source file
#     "/poc/test2/1/1/i2.txt",       # Input content or file path (cmd), input provided when the program runs; if it’s a file path, input is read from the file
#     "argc,argv[0]"                  # Expressions to examine (exprs), comma-separated; these variables or expressions will be printed during debugging
# ))

if __name__ == "__main__":
    de = Debugger()
    print(de.debug(
        "./projects/sqlite/sqlite3",        # Executable file path (executable_file), the binary you want to debug
        "./projects/sqlite/sqlite3.c",    # Source file path (file), the source code corresponding to the executable
        211593,                            # Breakpoint line number (line), sets a breakpoint at line 190 in the source file
        "./poc/poc.sql",       # Input content or file path (cmd), input provided when the program runs; if it’s a file path, input is read from the file
        "argc,argv[0]"                  # Expressions to examine (exprs), comma-separated; these variables or expressions will be printed during debugging
    ))

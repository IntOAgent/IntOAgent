import subprocess
import tempfile
import os
from typing import Dict, Optional, Union, Literal

class Debugger:
    def __init__(self):
        """Initialize GDB debugger for CTF analysis."""
        try:
            subprocess.run(['gdb', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("GDB not found")

    def is_binary_by_extension(self,file_path)-> bool:
        TEXT_EXTENSIONS = {'.c', '.cpp', '.py', '.java', '.txt', '.h'}
        return os.path.splitext(file_path)[1].lower() not in TEXT_EXTENSIONS
    
    def _create_gdb_script(self, file: str, line: int, exprs: str) -> str:
        """Create GDB script focused on CTF-relevant information."""
        expressions = [e.strip() for e in exprs.split(',')]
        
        if self.is_binary_by_extension(file):
            break_cmd = f"break *{line}"  # 地址前加*
        else:
            break_cmd = f"break {line}"


        script = f"""
        set verbose off
        file {file}
        {break_cmd}
        run
        
        # Function layout
        printf "\\n=== FUNCTION LAYOUT ===\\n"
        x/20i $pc-8
        
        # Stack & heap info
        printf "\\n=== MEMORY LAYOUT ===\\n"
        #info proc mappings
        printf "\\nStack pointer: "
        print/x $sp
        printf "Base pointer: "
        print/x $bp
        
        # Register state
        printf "\\n=== REGISTERS ===\\n"
        info registers
        
        printf "\\n=== TARGET VARIABLES ===\\n"
        """

        # Add analysis for each requested variable/expression
        for expr in expressions:
            script += f"""
        printf "\\n{expr}:\\n"
        printf "  Address: "
        print/x &{expr}
        printf "  Value: "
        print {expr}
        printf "  Raw bytes: "
        x/32xb {expr}
        printf "  As string: "
        x/s {expr}
        """

        script += """
        # Check for common CTF gadgets
        printf "\\n=== USEFUL GADGETS ===\\n"
        find $pc,+1000,"/bin/sh"
        find $pc,+1000,"flag"
        find $pc,+1000,"system"
        
        # Look for writable sections
        printf "\\n=== WRITABLE SECTIONS ===\\n"
        maintenance info sections WRITABLE
        
        quit
        """
        
        fd, path = tempfile.mkstemp(suffix='.gdb')
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        return path

    def _compile_with_protections(self, file: str, lang: Literal['c', 'cpp'] = 'cpp') -> str:
        """Compile with common CTF protections for testing.
        
        Args:
            file: Source file path
            lang: Language to use for compilation ('c' or 'cpp'). Defaults to 'cpp'.
        """
        output = os.path.splitext(file)[0]
        
        # Select compiler based on language
        compiler = 'g++' if lang == 'cpp' else 'gcc'
        
        try:
            # Compile with standard CTF protections
            subprocess.run(
                [compiler, '-std=c++17', '-g', file, '-o', output,
                 '-fno-stack-protector',  # Disable stack canaries
                 '-z', 'execstack',       # Make stack executable
                 '-no-pie'],             # Disable PIE
                check=True, capture_output=True, text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Compilation failed: {e.stderr}")
        return output
        
    def debug(self, file: str, line: int, exprs: str, 
             input_vars: Optional[Dict[str, Union[str, int, float]]] = None,
             lang: Literal['c', 'cpp'] = 'cpp') -> str:
        """Run CTF-focused debug analysis.
        
        Args:
            file: Source file path
            line: Line number to break at
            exprs: Comma-separated expressions to examine
            input_vars: Dictionary of input variables to pass as command line arguments
            lang: Language to use for compilation ('c' or 'cpp'). Defaults to 'cpp'.
        """
        if not os.path.exists(file):
            raise FileNotFoundError(f"File not found: {file}")
        if self.is_binary_by_extension(file):
            binary = file
        else:
            binary = self._compile_with_protections(file, lang)
        
        script = self._create_gdb_script(binary, line, exprs)

        input_str = ''
        if input_vars:
            # Convert input_vars to command line arguments
            args = [binary]  # First arg is program name
            for key, value in input_vars.items():
                args.append(str(value))
            cmd = ['gdb', '-x', script, '--quiet', '--args'] + args
        else:
            cmd = ['gdb', '-x', script, '--quiet', binary]

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise RuntimeError(f"GDB failed: {stderr}")
                
            return stdout

        finally:
            os.remove(script)
           # if os.path.exists(binary):
             #   os.remove(binary)
'''
if __name__ == "__main__":
    debugger = Debugger()
    de=debugger.debug("code/vuln_server",0x0040127a,"buffer, sockfd")

    
    print(de)  # 输出前500字符'
'''
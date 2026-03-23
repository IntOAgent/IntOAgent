SCRIPT_PROMPTRUN = """
        You are a Python code engineer. Your task is:
        Given an input Python script (Code A) and binary_path, output a modified version (Code B) that adds subprocess functionality.
        The goal is to make Code A's output directly feed into an external executable file as input, simulating terminal behavior like:
        ./binary_path < Code A's output
        But it should all happen within Python, using the subprocess module.
        Your implementation steps should follow this logic:
        1. Determine what the output of Code A is : e.g. string, JSON, or output.txt.
        2. Identify the name of the executable file that will consume this output.
        3. Use Python's subprocess module to send the output of Code A to the executable via standard input (stdin).
                Note:If the output of Code A is already written to a file, you can directly execute the target program using shell redirection (e.g., executable < output_file) without manually reading the file content in Python.
                eg: subprocess.run(['./executable file'], stdin=open('outputfile', 'rb'))
        4. Return only the modified version of the code (Code B). 
                Note: no extra explanation or markdown, and ensure it can run directly in a Linux environment.
        
        No need to append .exe to the executable, since it's Linux.
        Below are the contents of CodeA and the location of the executable file:
        Code A: {script_code}
        binary_path: {binary_path} 
"""

SCRIPT_PROMPTSR = """
        Take this python code, and fix any indentation or any obvious langauge bugs. Dont change the functionality.
        Return revised code only, no other prefix or suffix (e.g., ```python). 
        The code should be able to go into an eval statement and run successfully. 
        Code:
        {script_code}
"""

SCRIPT_PROMPTINPUT = """
        You are a professional Python engineer. Your task is as follows:
        Given a Python script (Code A) and a directory path poc_path, output a modified version (Code B) that updates all output file paths within the Python code to a unified destination: poc_path/input.txt, so that subsequent code can read from this file directly.
        Your implementation should follow this logic:
        1. Detect whether there are any output paths in Code A.
        2. Identify and confirm which of them are output file paths that need modification.
        3. Update all such paths to poc_path/input.txt.
        4. Return only the modified version of the code (Code B), ensuring it runs directly in a Linux environment.
        
        Requirements:
        1. All changes must be made within the Python code.
        2. Your response should include only the modified code—no explanations, no markdown, and no extra output.
        
        Inputs:
        Code A: {script_code}
        poc_path: {poc_path}
"""

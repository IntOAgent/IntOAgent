TOOLUSE_PROMPT = """
        You are tasked to extract the tool command only from the text. If no tool command is found, return None.

        Available Tools:

        1. Code Browser
        Description: Extracts and analyzes individual functions from source code. This helps you better understand the codebase, one function at a time.
        Usage: code_browser_source(file_name, function_name)
        - file_name: Name of the file to analyze
        - function_name: Name of the function to analyze (use just the function name, even for class methods)
        - Returns: Function source code and analysis summary

        2. Debugger 
        Description: Inspects memory and variables at runtime
        Usage: debugger(filename, line_number, exprs, input_vars)
        - filename: Source file to debug
        - line_number: Line to set breakpoint
        - exprs: Variables/expressions to examine
        - input_vars: Optional dict of input values to use
        - Returns: Memory/variable state at breakpoint

        3. Script Runner
        Description: Executes custom Python scripts for testing and exploitation
        Usage: run_script("script_code") 
        - script_code: Python code to execute,using \n to separate each line, and also include the corresponding import headers.
        - Returns: Script output
        Note: If you want the binary, its situated in {binary_path}. You might find the code in ``` ``` blocks after Command: run_script(). Extract all of it and put inside the run_script(code_goes_here). Code must be inside double quotes. Dont use `. We should be able to put it into an eval statement and run it.

        4. Bash Shell [non interactive]
        Description: Execute a command in the bash shell
        Usage: bash_shell("command")
        - command: Command to execute
        - Returns: Command output

        5. Successful Exploit.
        Description: If you have found a successful exploit and crashed the program or gained root access, call exploit_successful()

        6.Radare2
        Description: Provides deep static/dynamic analysis of binary files, supporting disassembly, memory inspection, breakpoint debugging, and vulnerability discovery. Directly execute radare2 commands for flexible analysis.
        Usage: radare2(filename: str, commands: str, output_format = 'text')
        - filename: Path to the binary file to analysize
        - commands: Radare2 command sequence to execute
        - output_format: Output format is always text

        The response below might talk about using some tool, extract the command only with its variables. Only return the command, nothing else. Make sure parameters are passed correctly. Sometimes you write function(param: value), thats not correct way to pass params, just pass the value. Do better.

        ###
        Response to parse
        {response}
        ###
        
        ###
        File path: {file}
        Binary path: {binary_path}
        ###
        """
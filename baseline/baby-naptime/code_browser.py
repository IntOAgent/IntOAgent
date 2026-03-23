from clang.cindex import Index, CursorKind
import os
from typing import Dict
from llm import LLM
from logger import logger
from colorama import Fore, Style

class CodeBrowser:
    def __init__(self):
        """Initialize CodeBrowser."""
        self.index = Index.create()
        self.llm = LLM()

    def get_class_body(self, filename: str, class_name: str) -> Dict:
        """
        Extract a class's body from a C source file using libclang.
        
        Args:
            filename: Path to the .c source file
            class_name: Name of class to extract
            
        Returns:
            Dict containing class details
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        # Parse the source file with C++ language options
        tu = self.index.parse(filename, args=['-x', 'c++'])
        if not tu:
            raise ValueError(f"Failed to parse {filename}")

        # Find the target class
        class_node = None
        for node in tu.cursor.walk_preorder():
            if (node.kind == CursorKind.CLASS_DECL and 
                node.spelling == class_name):
                class_node = node
                break

        if not class_node:
            raise ValueError(f"Class '{class_name}' not found in {filename}")

        # Get the class's source range
        start = class_node.extent.start
        end = class_node.extent.end
        
        # Read the original file to get the complete source
        with open(filename, 'r') as f:
            file_lines = f.readlines()

        # Extract class lines with line numbers
        class_lines = file_lines[start.line-1:end.line]
        numbered_lines = [
            f"{i+start.line}: {line.rstrip()}"
            for i, line in enumerate(class_lines)
        ]

        # Match original format
        return {
            'filename': filename,
            'name': class_name,
            'type': 'class',
            'source': '\n'.join(numbered_lines),
            'lines': [line.strip() for line in class_lines if line.strip()]
        }

    def get_function_body(self, filename: str, function_name: str) -> Dict:
        """
        Extract a function's body from a C source file using libclang.
        
        Args:
            filename: Path to the .c source file
            function_name: Name of function to extract
            
        Returns:
            Dict containing function details
        """
        if not filename.endswith('.c') and not filename.endswith('.cpp') and not filename.endswith('.h'):
            raise ValueError("Only .c, .cpp and .h files are supported")
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        # For .h files, return the full file
        if filename.endswith('.h'):
            with open(filename, 'r') as f:
                file_lines = f.readlines()
            numbered_lines = [
                f"{i+1}: {line.rstrip()}" 
                for i, line in enumerate(file_lines)
            ]
            return {
                'filename': filename,
                'name': function_name,
                'type': 'header',
                'source': '\n'.join(numbered_lines),
                'lines': [line.strip() for line in file_lines if line.strip()]
            }

        # Parse the source file
        tu = self.index.parse(filename)
        if not tu:
            raise ValueError(f"Failed to parse {filename}")

        # Find the target function
        function_node = None
        for node in tu.cursor.walk_preorder():
            if ((node.kind == CursorKind.FUNCTION_DECL or node.kind == CursorKind.CXX_METHOD) and 
                    node.spelling == function_name):
                function_node = node
                break

        if not function_node:
            try:
                class_node = self.get_class_body(filename, function_name)
                return class_node
            except ValueError:
                logger.info(f"{Fore.RED}Function '{function_name}' not found in {filename}. The function name must exist in {filename}.{Style.RESET_ALL}")
                raise ValueError(f"Function '{function_name}' not found in {filename}. The function name must exist in {filename}.")

        # Get the function's source range
        start = function_node.extent.start
        end = function_node.extent.end
        
        # Read the original file to get the complete source
        with open(filename, 'r') as f:
            file_lines = f.readlines()

        # Extract function lines with line numbers
        function_lines = file_lines[start.line-1:end.line]
        numbered_lines = [
            f"{i+start.line}: {line.rstrip()}"
            for i, line in enumerate(function_lines)
        ]

        # Match original format
        return {
            'filename': filename,
            'name': function_name,
            'type': 'function',
            'source': '\n'.join(numbered_lines),
            'lines': [line.strip() for line in function_lines if line.strip()]
        }

    def code_browser_source(self, file: str, name: str) -> str:
        """
        Analyze a function from a specific C source file.
        
        Args:
            file: Path to the .c file to analyze
            name: Name of function to analyze
            
        Returns:
            String containing the function source with line numbers
        """
        try:
            function_details = self.get_function_body(file, name)
            return function_details['source']
        except (ValueError, FileNotFoundError) as e:
            return str(e)

    
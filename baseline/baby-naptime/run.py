import os
import argparse
from scripter import ScriptRunner
from code_browser import CodeBrowser
from debugger import Debugger
from agent import Agent
from queue import Queue
from logger import logger
from colorama import Fore, Style

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║             Baby Naptime - LLMs for Native Vulnerabilities           ║
    ║                                                                      ║
    ║        An open source implementation of Google's Project Naptime     ║
    ║                                                                      ║
    ║     [+] Intelligent vulnerability analysis                           ║
    ║     [+] Automated exploit generation                                 ║
    ║     [+] Memory corruption detection                                  ║
    ║     [+] Advanced debugging capabilities                              ║
    ║                                                                      ║
    ║               -- Find bugs while the baby's sleeping! --             ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

class BabyNaptime:
    def __init__(self, code_file: str, max_iterations: int = 100, 
                 llm_model: str = "gpt-3.5-turbo", main_function: str = "main",
                 keep_history: int = 10):
        """
        Initialize the BabyNaptime vulnerability analyzer.
        
        Args:
            code_file: Path to the source code file to analyze
            max_iterations: Maximum number of analysis iterations (default: 100)
            llm_model: LLM model to use for analysis (default: gpt-3.5-turbo)
            main_function: Entry function to begin analysis (default: main)
        """
        self.code_file = code_file
        self.is_binary = False
        self.max_iterations = max_iterations
        self.llm_model = llm_model
        self.keep_history = keep_history
        self.main_function = main_function
        self.code_browser = CodeBrowser()
        
        if not os.path.exists(code_file):
            raise FileNotFoundError(f"Source file not found: {code_file}")
            
        # self.file_contents = open(self.code_file, 'r').read()
        if not self.is_binary_file(code_file):
            logger.info(f"Reading source file: {code_file}")
            self.file_contents = open(self.code_file, 'r').read()
            self.is_binary = False
        else:
            logger.warning(f"Skipping text read for binary file: {code_file}")
            self.file_contents = "the path of binary file is"+self.code_file
            self.is_binary = True

    def is_binary_file(self, file_path):
        """Check if the given file is a binary file by checking for null bytes."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
                return b'\x00' in data
        except Exception as e:
            logger.error(f"Error checking file type: {e}")
            return False
        
    def run(self):
        """Run the vulnerability analysis on the target code."""
        # Get entry function
        if not self.is_binary:
            function_body = self.code_browser.get_function_body(
                self.code_file, 
                self.main_function
            )['source']
        else:
            function_body = "the path of binary file is"+self.code_file
        
        self.agent = Agent(self.code_file, function_body, self.is_binary,llm_model=self.llm_model, keep_history=self.keep_history)
        logger.info(f"{Fore.WHITE}Starting code analysis...{Style.RESET_ALL}")
        self.agent.run()
        

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="BabyNaptime - Automated vulnerability analysis tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--code_file", "-c",
        help="Path to the source code file to start the analysis",
        required=True
    )
    
    parser.add_argument(
        "--code-directory", "-d",
        help="Directory containing additional source files",
        default="."
    )
    
    parser.add_argument(
        "--max-iterations", "-m",
        type=int,
        help="Maximum number of analysis iterations",
        default=100
    )
    
    parser.add_argument(
        "--llm-model", "-l",
        help="LLM model to use for analysis",
        default="o3-mini",
        choices=["gpt-3.5-turbo", "gpt-4o", "gpt-4o-mini", "o3-mini", "o1-preview"]
    )
    
    parser.add_argument(
        "--main-function", "-f",
        help="Entry function to begin analysis",
        default="main"
    )

    parser.add_argument(
        "--keep-history", "-k", 
        type=int,
        help="Number of conversation history items to keep in context",
        default=14
    )

    args = parser.parse_args()

    # Validate keep_history is > 10
    if args.keep_history <= 10:
        logger.error("Keep history must be greater than 10")
        return 1

    # Check if code file exists
    if not os.path.exists(args.code_file):
        logger.error(f"File not found: {args.code_file}")
        return 1

    # Check if code directory exists
    if not os.path.exists(args.code_directory):
        logger.error(f"Code directory not found: {args.code_directory}")
        return 1

    # Check if code directory is actually a directory
    if not os.path.isdir(args.code_directory):
        logger.error(f"Specified path is not a directory: {args.code_directory}")
        return 1

    analyzer = BabyNaptime(
            code_file=args.code_file,
            max_iterations=args.max_iterations,
            llm_model=args.llm_model,
            main_function=args.main_function,
            keep_history=args.keep_history
        )
    analyzer.run()

if __name__ == "__main__":
    main()

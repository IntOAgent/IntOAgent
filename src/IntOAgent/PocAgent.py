import os
import argparse
from code_browser import CodeBrowser
from agent import Agent
from logger import logger
from colorama import Fore, Back, Style
BOLD = '\033[1m'  # Define bold style


# Define PoCAgent class for automated vulnerability analysis
class PoCAgent:
    def __init__(self, 
                project_path:str,
                binary_path:str,
                max_iterations:int,
                llm_model:str,
                main_function:str,
                num_history:int,
                extra_path:str):

        self.project_path = os.path.abspath(project_path)  # Source code path, absolute path
        self.binary_path = os.path.abspath(binary_path)    # Binary file path, absolute path
        self.max_iterations = max_iterations               # Maximum number of iterations
        self.llm_model = llm_model                         # LLM model name
        self.main_function = main_function                 # Entry function name
        self.num_history = num_history                     # Number of conversation history entries to keep
        self.extra_path = extra_path                       # Path to the extra file for auxiliary screening, absolute path
        
        self.code_browser = CodeBrowser(self.project_path) # Initialize CodeBrowser object

    def run(self):
        """
        Run the analysis workflow
        """
        self.code_browser.index_project()
        function_body = self.main_function
        # self.code_browser.get_body(self.main_function)
        
        # Initialize the Agent object to perform the actual analysis tasks
        self.agent = Agent(project_path = self.project_path,
                           binary_path = self.binary_path,
                           max_iterations = self.max_iterations,
                           llm_model = self.llm_model,
                           num_history = self.num_history,
                           function_body = function_body,
                           extra_path = self.extra_path)
        
        # Log the start of the analysis
        logger.info(f"{BOLD}{Back.BLUE}{Fore.YELLOW} Starting code analysis... {Style.RESET_ALL}")
        # Call the Agent's run method to start analysis
        self.agent.run()

def main():
    """
    Main function, used to parse command-line arguments and start the analysis process
    """
    # Create command-line argument parser
    parser = argparse.ArgumentParser(
        description="CodeqlAgent - Automated vulnerability analysis tool",  # Tool description
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  # Show default values
    )
    
    # Source code directory
    parser.add_argument(
        "--project_path", "-p",
        help="Path to the project containing source code to start the analysis",  # Argument description
        default="projects/test2"  # Default value
    )

    # Path to the executable file
    parser.add_argument(
        "--binary_path", "-b",
        help="Path to the binary to start the analysis",  # Argument description
        default="projects/test2/test2"  # Default value
    )
    
    # Entry function name for analysis
    parser.add_argument(
        "--main_function", "-f",
        help="Entry function to begin analysis",  # Argument description
        default="main"  # Default value
    )

    # LLM model selection
    parser.add_argument(
        "--llm_model", "-l",
        help="LLM model to use for analysis",  # Argument description
        # default="gpt-4.1",  # Default value
        default="gpt-4.1-mini",
        choices=["gpt-4.1-mini", "gpt-4.1-nano", "gpt-4.1", "gpt-o4-mini", "4o-mini"]  # Optional values
    )

    # Path to the extra file for auxiliary screening
    parser.add_argument(
        "--extra_path", "-e", 
        type=str,
        help="Path to the extra file to start the analysis",  # Argument description
        default=None  # Default value
    )

    # Maximum number of iterations
    parser.add_argument(
        "--max_iterations", "-m",
        type=int,
        help="Maximum number of analysis iterations",  # Argument description
        default=100  # Default value
    )
    
    # Number of conversation history records to keep (for later connecting to RAG, after reaching the limit store into RAG)
    parser.add_argument(
        "--num_history", "-n", 
        type=int,
        help="Number of conversation history entries to store",  # Argument description
        default=25  # Default value
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Create BabyNaptime object and start analysis
    analyzer = PoCAgent(
            project_path=args.project_path,
            binary_path=args.binary_path,
            main_function=args.main_function,
            llm_model=args.llm_model,
            extra_path=args.extra_path,
            max_iterations=args.max_iterations,
            num_history=args.num_history
        )
    analyzer.run()


# If this script is run directly, call the main function
if __name__ == "__main__":
    main()

# python3 PocAgent.py -p projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab -b projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab/sqlite3 -f concatFuncCore -e extra/sqlite/8/VulPath/extra.txt
# python3 PocAgent.py -p projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab -b projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab/sqlite3 -f fts3MatchinfoSize -e extra/extra1.txt
# python3 PocAgent.py -p projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab -b projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab/sqlite3 -f setupLookaside -e extra/extra2.txt 
# python3 PocAgent.py -p projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab -b projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab/sqlite3 -f fts3IncrmergeWriter -e extra/extra3.txt
# python3 PocAgent.py -p projects/gawk -b projects/gawk/gawk -f r_format_val -e extra/gawk/1/1/extra.txt
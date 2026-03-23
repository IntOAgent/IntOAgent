import os
import json
from llm import LLM
from caller import Caller
from reporter import Reporter
from summarizer import Summarizer
from logger import logger
from colorama import Fore, Back, Style
BOLD = '\033[1m'  # Define bold style
import shutil

# Import system prompts and tool-use prompts
from prompts.system import SYSTEM_PROMPT
from prompts.tooluse import TOOLUSE_PROMPT
from prompts.check import CHECK_PROMPT

# Define Agent class
class Agent:
    # Initialization method
    def __init__(self, 
                project_path:str,
                binary_path:str,
                max_iterations:int,
                llm_model:str,
                function_body:str,
                num_history:int,
                extra_path:str):

        self.project_path = project_path  # Save source file path
        self.binary_path = binary_path    # Save binary file path

        self.max_iterations = max_iterations  # Save maximum number of iterations
        self.initial_data = function_body     # Save entry function name
        self.num_history = num_history        # Save number of history records to keep
        self.extra_path = extra_path          # Save path to the extra file for auxiliary screening
        
        parts = self.extra_path.split(os.sep)
        self.output_path = os.path.join(*parts[-4:-1])
        # Initialize three language models: the first is thinker, the second is assistant, the third is checker
        self.llm_1 = LLM(llm_model)
        # self.llm_2 = LLM("gpt-4.1-mini")
        self.llm_2 = LLM(llm_model)
        self.llm_3 = LLM(llm_model)

        # Construct the experiment directory path for the binary program
        self.poc_path = os.path.join("poc", self.output_path)
        # Ensure the experiment directory exists
        os.makedirs(self.poc_path, exist_ok=True)

        # Initialize chat history
        self.history = [
            {"role": "assistant", "content": "Understood. Please provide the entry function of the program. Once I receive it, I will begin the vulnerability research process."},
            {"role": "user", "content": self.initial_data}
        ]

        # Replace placeholders in the system prompt
        self.SYSTEM_PROMPT = SYSTEM_PROMPT.format(file=self.project_path,
                                                  binary_path=self.binary_path,
                                                  exploit_directory=self.poc_path)
        
        # Create chat history directory
        self.chat_history_path = os.path.join("chat_history", "PoCAgent", self.output_path, "history.json")
        os.makedirs(os.path.dirname(self.chat_history_path), exist_ok=True)
        # Minimum number of retry attempts
        self.max_failure = 1
    
    def clean_poc(self):
        """
        Remove all contents under self.poc_path
        """
        if os.path.exists(self.poc_path):
            for item in os.listdir(self.poc_path):
                item_path = os.path.join(self.poc_path, item)
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
        return
    
    # Method to save chat history
    def save_history(self):
        try:
            # Open the chat history file in write mode
            with open(self.chat_history_path, 'w', encoding='utf-8') as f:
                # Write the chat history to the file in JSON format
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            # If saving fails, log the error
            logger.error(f"Error saving chat history: {e}")

    # Method for tool usage
    def tool_use(self, response: str) -> str:
        # Use the second language model to process the tool-use prompt
        response = self.llm_2.prompt(TOOLUSE_PROMPT.format(
            response=response,
            file=self.project_path,
            binary_path=self.binary_path
        ))
        # Remove code block markers from the response
        return response.strip('```')

    def run(self) -> None:
        curretry = 0          # Current consecutive None counter
        
        scriptmemory = []     # Reserved, not used yet

        for _ in range(self.max_iterations):
            # Prepare system prompt
            prompt = self.SYSTEM_PROMPT
            if self.extra_path:
                with open(self.extra_path, 'r') as f:
                    extra = f.read()
                prompt += extra

            # Construct messages
            messages = [{"role": "system", "content": prompt}]

            # Compress history
            if len(self.history) > self.num_history:
                keep_beginning = 4
                keep_ending = self.num_history - keep_beginning
                first = self.history[:keep_beginning]
                last = self.history[-keep_ending:]
                middle = self.history[keep_beginning:-keep_ending]
                summary = Summarizer().summarize_conversation(middle)
                self.history = first + [
                    {"role": "assistant", "content": f"[SUMMARY OF PREVIOUS CONVERSATION: {summary}]"}
                ] + last
            messages.extend(self.history)

            # First LLM call
            response = (
                self.llm_1.action(messages, temperature=0, reasoning="medium")
                .replace("```python", "")
                .replace("```json", "")
                .replace("```", "")
            )
            self.history.append({"role": "assistant", "content": response})

            # Parse tool command
            tool_command = (
                self.tool_use(response)
                .replace("```python", "")
                .replace("```json", "")
                .replace("```", "")
            )
            logger.info(f"{Fore.GREEN}***Running tool***: {tool_command}")

            # Successful exploitation
            if "exploit_successful" in tool_command:
                logger.info(
                    f"{BOLD}{Back.BLUE}{Fore.YELLOW} Exploit successful, generating report {Style.RESET_ALL}"
                )
                Reporter(self.project_path,self.output_path).generate_summary_report(self.history)
                self.save_history()
                raise SystemExit(0)

            # Consecutive None handling
            if "None" in tool_command:
                if curretry >= self.max_failure:
                    logger.info(
                        f"{BOLD}{Back.BLUE}{Fore.YELLOW}Exploit failed, generating report {Style.RESET_ALL}"
                    )
                    self.clean_poc()
                    Reporter(self.project_path,self.output_path).generate_summary_report(self.history)
                    self.save_history()
                    raise SystemExit(0)
                curretry += 1
                self.history.clear()
                continue

            # Actual tool execution
            tool_response = Caller(
                project_path=self.project_path,
                binary_path=self.binary_path,
                poc_path=self.poc_path,
                output_path=self.output_path
            ).call_tool(tool_command)

            print(f"{Fore.GREEN}***{tool_response}***{Style.RESET_ALL}")
            self.history.append({"role": "user", "content": str(tool_response)})
            self.save_history()
            
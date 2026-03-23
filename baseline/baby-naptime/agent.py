import os
import json
from utils import count_tokens
from llm import LLM
from caller import Caller
from reporter import Reporter
from summarizer import Summarizer
from logger import logger
from colorama import Fore

from prompts.system import SYSTEM_PROMPT
from prompts.tooluse import TOOLUSE_PROMPT


class Agent:
    """
    An intelligent agent that analyzes code for vulnerabilities using LLMs.
    
    The agent maintains conversation history with the LLM, executes tools based on
    LLM responses, and coordinates the overall vulnerability analysis workflow.

    Attributes:
        llm: LLM instance for generating responses
        file: Path to source code file being analyzed
        llm_model: Name of LLM model being used
        binary_path: Path to compiled binary
        keep_history: Number of conversation items to maintain in context
        initial_data: Initial code/data to analyze
        history: List of conversation items between agent and LLM
        SYSTEM_PROMPT: System prompt template for the LLM
    """

    def __init__(self, file: str, initial_data: str,is_binary: bool, llm_model: str = "o3-mini", keep_history: int = 10, ):
        """
        Initialize the agent.

        Args:
            file: Path to source code file to analyze
            initial_data: Initial code/data to analyze
            llm_model: Name of LLM model to use (default: o3-mini)
            keep_history: Number of conversation items to keep in context (default: 10)
        """
        self.llm = LLM(llm_model)
        self.file = file
        self.llm_model = llm_model
        self.is_binary = is_binary
        if self.is_binary:
            self.binary_path = self.file
        else:
            self.binary_path = self.build_binary()
        logger.info(f"{Fore.GREEN}Binary path: {self.binary_path}")

        self.keep_history = keep_history
        self.initial_data = initial_data
        self.history = [
            {"role": "user", "content": initial_data},
            {"role": "user", "content": f"Binary path: {self.binary_path}"}
        ]
        self.SYSTEM_PROMPT = SYSTEM_PROMPT.format(file=self.file, binary_path=self.binary_path)
        
    def tool_use(self, response: str) -> str:
        """
        Process LLM response to extract tool commands.

        Args:
            response: Raw LLM response string

        Returns:
            Extracted tool command string
        """
        response = self.llm.prompt(TOOLUSE_PROMPT.format(
            response=response,
            file=self.file,
            binary_path=self.binary_path
        ))
        return response.strip('```')
        
    def build_binary(self) -> str:
        """
        Compile source code into binary with security mitigations disabled.

        Returns:
            Path to compiled binary

        Raises:
            SystemExit: If compilation fails
        """
        try:
            directory = os.path.dirname(self.file)
            base = os.path.splitext(os.path.basename(self.file))[0]
            
            output = os.path.join(directory, base) if directory else base
                
            os.system(f"g++ -std=c++17 -g {self.file} -o {output} -fno-stack-protector -z execstack -no-pie -w")
            return output
        except Exception as e:
            logger.error(f"Error compiling binary: {e}")
            logger.error("Exiting since binary compilation failed")
            raise SystemExit(1)

    def run(self) -> None:
        """
        Main agent loop that:
        1. Maintains conversation with LLM
        2. Processes responses into tool commands
        3. Executes tools and feeds results back to LLM
        4. Generates report on successful exploit
        """
        while True:
            messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]

            # Rebuild binary in case it was deleted
            if not self.is_binary:
                self.build_binary()
            
            # Manage conversation history
            if len(self.history) > self.keep_history:
                keep_beginning = 4
                keep_ending = self.keep_history - keep_beginning
                
                first_messages = self.history[:keep_beginning]
                last_messages = self.history[-keep_ending:]
                middle_messages = self.history[keep_beginning:-keep_ending]
                summary = Summarizer(self.llm_model).summarize_conversation(middle_messages)
                self.history = first_messages + [
                    {"role": "assistant", "content": f"[SUMMARY OF PREVIOUS CONVERSATION: {summary}]"}
                ] + last_messages
                
                messages.extend(self.history)
            else:
                messages.extend(self.history)

            tokens = count_tokens(messages)
            logger.info(f"{Fore.YELLOW}Tokens in context: ~{tokens:,}")

            # Get next action from LLM
            response = self.llm.action(messages, temperature=0.3, reasoning="medium")
            logger.info(f"{Fore.YELLOW}Plan: {response}")
            self.history.append({"role": "assistant", "content": response})
            
            # Execute tool command
            tool_command = self.tool_use(response)

            if "exploit_successful" in tool_command:
                logger.info(f"{Fore.GREEN}Exploit successful, generating report")
                report = Reporter(self.file, self.llm_model)
                report.generate_summary_report(self.history)
                raise SystemExit(0)
            
            tool_response = Caller(file=self.file, llm_model=self.llm_model).call_tool(tool_command)
            self.history.append({"role": "user", "content": str(tool_response)})
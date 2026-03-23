import os
import json
from llm import LLM
from pathlib import Path

class Reporter:
    """
    Security vulnerability reporter that analyzes findings and generates reports.
    
    Analyzes conversation history between security testing agent and target system
    to validate discovered vulnerabilities and generate detailed reports.
    """

    def __init__(self, filename, llm_model: str = "o3-mini"):
        """
        Initialize the reporter.

        Args:
            filename: Filename of the file that was tested
        """
        self.llm = LLM(llm_model)
        self.reports = []
        self.filename = filename
        
    def generate_summary_report(self, history):
        """
        Generate a comprehensive markdown summary of the native vulnerability exploitation.
        
        Analyzes the conversation history to document how the native vulnerability
        was discovered and exploited, including technical details and final payload.
        """
        
        system_prompt = f"""
        You are a binary exploitation report writer. Your task is to analyze the conversation history and create a detailed technical report about how a native vulnerability was exploited.

        The report should include:
        1. A technical description of the vulnerability (buffer overflow, format string, etc)
        2. Analysis of the vulnerable code and why it was exploitable
        3. Step-by-step walkthrough of how the vulnerability was discovered and analyzed
        4. Details of the exploitation process including:
           - Memory layout analysis
           - Any protections that needed to be bypassed
           - Development of the exploit
        5. The final working payload and proof of successful exploitation

        Format the output as a proper markdown document with:
        - Executive summary explaining the vulnerability
        - Technical deep-dive into the vulnerable code
        - Detailed exploitation methodology
        - Code blocks showing key commands and payloads
        - Screenshots or output demonstrating the successful exploit
        
        Focus on the technical details that show how the native vulnerability was discovered and exploited. Include specific memory addresses, payloads, and commands used.

        Report should be 1 page only. We don't want extra pages. Short, to the point.
        """

        system_prompt = [{"role": "system", "content": system_prompt}]
        messages = []
        for item in history:
            messages.append({"role": item["role"], "content": item["content"]})
        summary = self.llm.action(system_prompt + messages)
        base = os.path.splitext(os.path.basename(self.filename))[0]
        os.makedirs("results", exist_ok=True)
        with open(f"results/{base}_summary.md", "w") as f:
            f.write(summary)
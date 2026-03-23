import os
import json
from llm import LLM
from pathlib import Path
from prompts.report import Reporter_PROMPT

class Reporter:

    def __init__(self, filename, output_path):
        """
        Initialize the reporter.

        Args:
            filename (str): Filename of the file that was tested.
            output_path (str): Relative output directory for saving reports.
        """
        self.llm = LLM("o4-mini")
        self.reports = []
        self.filename = filename
        self.output_path = output_path
        
    def generate_summary_report(self, history):
        system_prompt = [{"role": "system", "content": Reporter_PROMPT}]
        messages = [{"role": item["role"], "content": item["content"]} for item in history]
        summary = self.llm.action(system_prompt + messages)

        base = os.path.splitext(os.path.basename(self.filename))[0]
        report_dir = os.path.join("reports", self.output_path)
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, f"{base}_summary.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(summary)
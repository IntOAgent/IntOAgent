import os
import re
from typing import Dict, Optional
from openai import OpenAI
from constants import OPENAI_API_KEY

class LLM:
    def __init__(self, model: str = "o3-mini"):
        """Initialize LLM with optional OpenAI client."""
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.should_reason = model in ["o3-mini", "o1-preview"] # check if we are using a reasoning model

    def action(self, messages, reasoning: str = "medium", temperature: float = 0.0):
        if not self.should_reason:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=messages,
            )
        else:
            response = self.client.chat.completions.create(
                model=self.model,
                reasoning_effort=reasoning,
                messages=messages,
            )
        return response.choices[0].message.content

    def prompt(self, prompt: str, reasoning: str = "medium", temperature: float = 0.0):
        if not self.should_reason:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        else:
            response = self.client.chat.completions.create(
                model=self.model,
                reasoning_effort=reasoning,
                messages=[{"role": "user", "content": prompt}],
            )
        return response.choices[0].message.content

    
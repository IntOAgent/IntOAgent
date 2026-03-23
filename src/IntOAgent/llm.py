import os
import re
from typing import Dict, Optional
import openai
import tiktoken
from redis_utils import RedisUtils

openai.base_url = 
openai.default_headers = {"x-foo": "true"}
openai.api_key = 
redis_util = RedisUtils()
class LLM:
    def __init__(self, model: str = "o4-mini"):
        self.model = model
        self.model = 'gpt-4.1-mini'
        # Check if model supports reasoning effort
        self.should_reason = model in ["o4-mini"]
        self.should_reason = False
        # track token usage
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.encoding = tiktoken.encoding_for_model('gpt-4')

    def clear_token(self):
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0

    # General call
    def _call(self, messages, reasoning: str = "medium", temperature: float = 0.0):
        """
        This function sends messages to the OpenAI Chat Completion API.
        It first checks the token length of the input messages using the same
        tokenizer as the model. If the token length exceeds 100,000, it will
        immediately return a warning instead of sending the request.
        """

        # Convert messages into a single string for token counting
        text = ""
        for msg in messages:
            # Each message usually has "role" and "content"
            text += msg.get("role", "") + ": " + msg.get("content", "") + "\n"

        # Count tokens
        token_length = len(self.encoding.encode(text))

        # If token length exceeds the limit, return a warning
        if token_length > 100000:
            print({"warning": f"Message too long: {token_length} tokens (limit is 100000). STOP!"})
            return 1

        # Normal call if within limit
        if not self.should_reason:
            response = openai.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=messages,
            )
        else:
            response = openai.chat.completions.create(
                model=self.model,
                reasoning_effort=reasoning,
                messages=messages,
            )

        # Track token usage if available
        if hasattr(response, "usage"):
            self.prompt_tokens += response.usage.prompt_tokens
            self.completion_tokens += response.usage.completion_tokens
            self.total_tokens += response.usage.total_tokens
            now_token = float(redis_util.get("TokenCount"))
            redis_util.set("TokenCount", str(now_token + response.usage.total_tokens))
            
        return response

    # "Think" style call with multiple messages
    def action(self, messages, reasoning: str = "medium", temperature: float = 0.0):
        response = self._call(messages, reasoning, temperature)
        if response == 1:
            return "STOP"
        return response.choices[0].message.content

    # "Prompt" style call with single input
    def prompt(self, prompt: str, reasoning: str = "medium", temperature: float = 0.0):
        response = self._call(
            [{"role": "user", "content": prompt}],
            reasoning,
            temperature,
        )
        if response == 1:
            return str(response)
        return response.choices[0].message.content

    # Print token consumption
    def output_token(self):
        print(f"Prompt tokens: {self.prompt_tokens}")
        print(f"Completion tokens: {self.completion_tokens}")
        print(f"Total tokens: {self.total_tokens}")
        return self.total_tokens
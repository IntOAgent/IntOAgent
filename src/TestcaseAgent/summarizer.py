from llm import LLM
from typing import List, Dict
from prompts.summary_prompt import SUMMARY_PROMPT

class Summarizer:
    def __init__(self) -> None:
        self.llm = LLM("gpt-4.1-mini")
    def summarize_conversation(self, conversation: List[Dict[str, str]]) -> str:
        
        self.SYSTEM_PROMPT = SUMMARY_PROMPT

        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        messages = [{"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "assistant", "content": "Understood. Please provide the conversation history. Once I receive it, I will begin to summary it."},
                    {"role": "user", "content": conversation_str}]

        output = self.llm.action(messages)
        return "To reduce context, here is a summary of the previous part of the conversation:\n" + output

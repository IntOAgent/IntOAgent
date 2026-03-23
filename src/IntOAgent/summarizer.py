from llm import LLM
from typing import List, Dict
from prompts.summary import Summary_PROMPT

class Summarizer:
    def __init__(self) -> None:
        self.llm = LLM("4o-mini")
    def summarize_conversation(self, conversation: List[Dict[str, str]]) -> str:
        
        self.SYSTEM_PROMPT = Summary_PROMPT

        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        messages = [{"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "assistant", "content": "Understood. Please provide the conversation history. Once I receive it, I will begin to summary it."},
                    {"role": "user", "content": conversation_str}]

        output = self.llm.action(messages)
        return "To reduce context, here is a summary of the previous part of the conversation:\n" + output

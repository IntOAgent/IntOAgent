from llm import LLM
from typing import List, Dict


class Summarizer:
    """
    A class that summarizes security-focused conversations using LLM.
    
    This class takes conversations between security testing agents and systems,
    and generates concise summaries focused on technical details, test attempts,
    and findings.
    """

    def __init__(self, llm_model: str = "o3-mini") -> None:
        """
        Initialize the Summarizer with a specified LLM model.

        Args:
            llm_model (str): The name of the LLM model to use. Defaults to "o3-mini".
        """
        self.llm = LLM(llm_model)

    def summarize_conversation(self, conversation: List[Dict[str, str]]) -> str:
        """
        Generate a technical summary of a security testing conversation.

        Takes a conversation history and produces a bullet-point summary focused on
        security tests performed, specific commands used, and findings discovered.

        Args:
            conversation: List of conversation messages, where each message is a dict
                        containing 'role' and 'content' keys.

        Returns:
            str: A formatted summary of the conversation prefixed with context notice.
        """
        # Convert conversation list to string format
        conversation_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])
        
        prompt = f"""
        You are a summarizer agent. Your job is to summarize the following conversation:

        {conversation_str}

        Please provide a bullet point summary that includes:
        - What security tests were attempted
        - What specific commands/payloads were used
        - What the results of each test were
        - Any potential security findings discovered

        Keep the summary focused on technical details and actual actions taken. Each bullet point should be 1-2 sentences max. Keep the overall summary short.
        """

        output = self.llm.prompt(prompt)
        return "To reduce context, here is a summary of the previous part of the conversation:\n" + output

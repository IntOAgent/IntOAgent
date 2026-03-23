import tiktoken
from typing import Union, List, Dict

def sanitize_command(command: str) -> str:
    """
    Sanitize a shell command by checking against a blacklist of dangerous patterns.
    
    Args:
        command: The shell command to sanitize
        
    Returns:
        str: The original command if it passes validation
        
    Raises:
        ValueError: If the command contains any dangerous patterns
    """
    # Comprehensive list of dangerous shell commands and patterns that could harm the system
    DANGEROUS_PATTERNS = [
        'rm -rf /',      # Delete root directory
        'rm -rf *',      # Delete all in current dir
        'rm -rf ~',      # Delete home directory
        'mkfs',          # Format filesystem
        'dd if=/dev/zero',
        '> /dev/sda',    # Overwrite disk
        ':(){:|:&};:',   # Fork bomb
        'chmod -R 777 /', # Recursive permission change on root
        'chmod -R 000 /',
        '> /etc/passwd', # Overwrite critical system files
        '> /etc/shadow',
        'shutdown',      # System control commands
        'reboot',
        'halt',
        'poweroff',
        'init 0',
        'init 6',
        'format',
        'fdisk',
        '> /etc/hosts',
        '> /etc/resolv.conf',
        'mv /* /dev/null',
        'dd if=/dev/random',
        'dd if=/dev/urandom',
        ':(){ :|:& };:', # Alternative fork bomb
        '> /boot',       # Delete critical directories
        'rm -rf /boot',
        'rm -rf /etc',
        'rm -rf /usr', 
        'rm -rf /var',
        'rm -rf /lib',
        'rm -rf /bin',
        'rm -rf /sbin',
        'chown -R',      # Recursive ownership change
        'chmod -R'
    ]
    
    # Preserve original command but check lowercase version
    original_command = command
    command_lower = command.lower().strip()
    
    # Check command against blacklist
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command_lower:
            raise ValueError(
                f"Command '{command}' contains dangerous pattern '{pattern}'"
            )
            
    return original_command

def count_tokens(text: Union[str, List[Dict[str, str]]], model: str = "gpt-4o") -> int:
    """
    Count the number of tokens in a text string using OpenAI's tokenizer.
    
    Args:
        text: Either a string or a list of message dictionaries containing 'content' keys
        model: The model name to use for tokenization (default: gpt-4o)
        
    Returns:
        The total number of tokens in the text
        
    Example:
        >>> count_tokens("Hello world!")
        2
        >>> count_tokens([{"content": "Hello"}, {"content": "world!"}])
        2
    """
    # Convert list of messages to single string if needed
    if isinstance(text, list):
        text = " ".join(str(item.get("content", "")) for item in text)
    
    # Get tokenizer for specified model
    encoder = tiktoken.encoding_for_model("gpt-4o")
    tokens = encoder.encode(text)
    
    return len(tokens)
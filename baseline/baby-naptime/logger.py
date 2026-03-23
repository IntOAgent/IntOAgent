import logging
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configure logging to only show explicit logs
logging.basicConfig(
    level=logging.WARNING,  # Set higher base level to suppress imported lib logs
    format='%(message)s'
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Allow INFO logs just for this logger

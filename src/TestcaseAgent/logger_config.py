import logging
from pathlib import Path

log_dir = Path(__file__).parent / 'logs'  

def get_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:  
        stream_handler = logging.StreamHandler()
        
        formatter = logging.Formatter('%(asctime)s-%(levelname)s- %(message)s')
        
        stream_handler.setFormatter(formatter)
        
        logger.addHandler(stream_handler)
        
        logger.setLevel(logging.INFO)
    
    return logger

logger = get_logger('app')
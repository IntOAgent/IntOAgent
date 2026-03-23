from typing import List
from pathlib import Path
import _config
cur_dir = Path(__file__).parent
extra_dir = cur_dir / 'extra' / _config.PROJECT_NAME

def get_input_extras(id: str) -> List[str]:
    target_dir = extra_dir / id[id.rfind('/')+1:]
    
    # TestcaseAgent 不考虑PRUNE.txt
    # if (target_dir / "PRUNE.txt").exists():
    #     return [] 
    
    subdirs = [x for x in target_dir.iterdir() if x.is_dir()]
    subdirs.sort(key=lambda x: int(x.name))
    
    results = []
    
    if subdirs:
        for subdir in subdirs:
            extra_file = subdir / 'extra.txt'
            if extra_file.exists():
                results.append(extra_file.read_text())
    else:
        extra_file = target_dir / 'extra.txt'
        if extra_file.exists():
            results.append(extra_file.read_text())
    
    return results

if __name__ == '__main__':
    print(get_input_extras('1'))
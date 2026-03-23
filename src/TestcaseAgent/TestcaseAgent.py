from logger_config import logger
from pathlib import Path
import _config
from llm import LLM
from utils import *
from prompts.system_prompt import SYSTEM_PROMPT
from prompts.user_message_template import USER_MESSAGE_TEMPLATE
from prompts.tools_prompt import TOOLUSE_PROMPT
from summarizer import Summarizer
from caller import Caller, CallResult
import json
from redis_utils import RedisUtils
import shutil
import zipfile
from json_repair import repair_json

redis_util = RedisUtils()

cur_dir = Path(__file__).parent

def extract_json(text):
    if '```json' not in text:
        return text
    text = text.split('```json')[1].split('```')[0].strip()
    return text


class Agent:
    def __init__(self, name: str, max_iterations: int = 100, num_history: int = 25 ):
        self.name = name
        self.running = False
        self.project_path = Path(_config.PROJECT_PATH)
        self.llm1 = LLM()
        self.llm2 = LLM()
        self.llm3 = LLM()
        self.max_iterations = max_iterations  # Save maximum number of iterations
        self.history = []
        self.num_history = num_history        # Save number of history records to keep
        self.id = '0'
        self.binary_path = _config.BIN_PATH
        self.poc_path = cur_dir / 'poc' / _config.PROJECT_NAME / self.id
        self.project_info = f"""
There are some important information about the project:
Project Name: {_config.PROJECT_NAME}
Binary Path: {_config.BIN_PATH}
Source Code Path: {_config.PROJECT_PATH}
Exploit Directory: {self.poc_path}
"""
        self.chat_history_path = cur_dir / 'chat_history' / self.name / _config.PROJECT_NAME / str(self.id)
        self.chat_history_path.touch()
        self.SYSTEM_PROMPT = SYSTEM_PROMPT.replace("{{exploit_directory}}", str(self.poc_path)) + self.project_info

        logger.info(f"Agent '{self.name}' initialized.")

    def update_id(self, new_id: str):
        self.id = new_id
        self.poc_path = cur_dir / 'poc' / _config.PROJECT_NAME / str(self.id)
        self.poc_path.mkdir(parents=True, exist_ok=True)
        self.chat_history_path = cur_dir / 'chat_history' / self.name / _config.PROJECT_NAME / str(self.id)
        self.chat_history_path.parent.mkdir(parents=True, exist_ok=True)
        self.chat_history_path.touch()
        logger.info(f"Agent '{self.name}' ID updated to {self.id}.")
        self.save_call_function(new_id)

    def save_call_function(self, no: str):
        # file = cur_dir / 'extra' / _config.PROJECT_NAME / no / 'funcname.txt'
        # with open(file, 'r', encoding='utf-8') as f:
        #     content = f.read()
        #     call_function = content.split(' ')[0] if ' ' in content else content
        call_function = redis_util.get("FunctionName")
        redis_util.set("id", no)
        redis_util.set(f"{_config.PROJECT_NAME}:{no}:call_function", call_function.strip())
        logger.info(f"Saved call function to redis: {id}, {call_function}")

    # Method to save chat history
    def save_history(self):
        try:
            # Open the chat history file in write mode
            with open(self.chat_history_path, 'w', encoding='utf-8') as f:
                # Write the chat history to the file in JSON format
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            # If saving fails, log the error
            logger.error(f"Error saving chat history: {e}")

    def tool_use(self, response: str) -> str:
        prompt = TOOLUSE_PROMPT.replace("{{response}}", response) + self.project_info
        response = self.llm2.prompt(prompt)
        return response

    def run(self, extra: str) -> None:
        curretry = 0          # Current consecutive None counter
        none_count = 0
        for _ in range(self.max_iterations):
            prompt = self.SYSTEM_PROMPT
            prompt += "\n" + extra[:extra.find('Function detailed context:')] # Only keep the part before 'Function detailed context:' Avoid token overflow
            messages = [
                {"role": "system", "content": prompt},
            ]
            if len(self.history) > self.num_history:
                keep_beginning = 4
                keep_ending = self.num_history - keep_beginning
                first = self.history[:keep_beginning]
                last = self.history[-keep_ending:]
                middle = self.history[keep_beginning:-keep_ending]
                summary = Summarizer().summarize_conversation(middle)
                self.history = first + [
                    {"role": "assistant", "content": f"[SUMMARY OF PREVIOUS CONVERSATION: {summary}]"}
                ] + last
            
            messages.extend(self.history) 

            response = self.llm1.action(messages, temperature=0.3).replace("```python", "").replace("```json", "").replace("```", "")
            self.history.append({"role": "assistant", "content": response})
            
            '''
            {
                "tool_name": "tool_name",
                "params" :{
                    "param1": "value1",
                    "param2": "value2"
                }
            }
            '''
            tool_command = (
                self.tool_use(response)
                .replace("```python", "")
                .replace("```json", "")
                .replace("```", "")
            )

            logger.info(f"***Running tool***: {tool_command}")

            try:
                json.loads(tool_command)
            except json.JSONDecodeError as e:
                tool_command = repair_json(tool_command)
                try:
                    json.loads(tool_command)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON format: {tool_command}, Error: {e}")
                    self.history.append({"role": "user", "content": f"Error: Invalid tool command format. Please provide valid JSON format."})
                    continue
            if "none" in tool_command.lower():
                none_count += 1
                if none_count >= 5:
                    logger.warning(f"***Received 'none' tool command 3 times, stopping.***")
                    return False
            tool_response: CallResult = Caller(self.project_path, self.poc_path / str(self.id)).call_tool(tool_command)
            
            self.history.append({"role": "user", "content": str(tool_response.data)})
            self.save_history()    

            if tool_response.tool_name == 'debugger' and bool(tool_response.data['success']):
                logger.warning(f"***Generate Testcase successful!***")
                call_info = self.poc_path / str(self.id) / 'call_info.json'
                if not call_info.exists():
                    call_info.parent.mkdir(parents=True, exist_ok=True)
                    call_info.touch()
                call_info.write_text(tool_command)
                return True
            curretry += 1    

        if curretry == self.max_iterations:
            logger.error(f"***Max iterations reached, stopping.***")
        return False
        
def createIgnoreFilesAndDirs():
    gitignore_path = Path('.gitignore')
    
    if gitignore_path.exists():
        logger.info("Reading existing .gitignore file")
        with open(gitignore_path, 'r', encoding='utf-8') as f:
            content = f.read()
    
    if content:
        files = content.splitlines()
        for file in files:
            if file and not file.startswith('#'):
                path = cur_dir / file
                if file.endswith('/'):
                    if not path.exists():
                        path.mkdir(parents=True, exist_ok=True)
                        logger.info(f"Created directory: {path}")
                else:
                    if not path.parent.exists():
                        path.parent.mkdir(parents=True, exist_ok=True)
                    if not path.exists():
                        path.touch(exist_ok=True)
                        logger.info(f"Created file: {path}")

def createDir():
    createIgnoreFilesAndDirs()


def init():
    logger.info("Initializing project...")
    createDir()


def get_analysis() -> List[str]:
    extra_dir = cur_dir / 'extra' / _config.PROJECT_NAME
    dirs = [x for x in extra_dir.iterdir() if x.is_dir()]
    dirs.sort(key=lambda x: int(x.name))
    return [str(dir) for dir in dirs]

def extract_extra():
    output_dir = cur_dir / 'output' / _config.PROJECT_NAME
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    zip_files = [x for x in output_dir.iterdir() if x.suffix == '.zip']
    for zip_file in zip_files:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        logger.info(f"Extracting zip file: {zip_file}")
    src_extra_dir = output_dir / 'extra' / _config.PROJECT_NAME
    dst_extra_dir = cur_dir / 'extra' / _config.PROJECT_NAME
    if src_extra_dir.exists():
        if dst_extra_dir.exists():
            shutil.rmtree(dst_extra_dir)
        shutil.move(str(src_extra_dir), str(dst_extra_dir))
        logger.info(f"Moved {src_extra_dir} to {dst_extra_dir}")
        shutil.rmtree(output_dir)
        logger.info(f"Removed output directory: {output_dir}")

if __name__ == "__main__":
    init()
    # extract_extra()
    agent = Agent("TestcaseAgent")
    nos = get_analysis()
    
    for no in nos:
        logger.info(f"Starting analysis for extra: {no}")
        for id, extra in enumerate(get_input_extras(no), 1):
            agent.update_id(str(id))
            if agent.run(extra):
                redis_util.set("SuccessCall", extra)
                exit(0)
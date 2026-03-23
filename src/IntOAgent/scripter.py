import subprocess
import tempfile
import os
from llm import LLM
from typing import Any, Optional
from prompts.script import SCRIPT_PROMPTSR, SCRIPT_PROMPTINPUT
import _config

MAX_OUTPUT_LENGTH = _config.MAX_OUTPUT_LENGTH 
class ScriptRunner:
    def __init__(self, binary_path: str, poc_path: str, output_path: str) -> None:
        
        """Initialize script runner."""
        # self.llm_model = "gpt-4.1-mini"
        self.llm_model = "4o-mini"
        self.temp_dir = "pytemp"
        self.binary_path = binary_path
        self.poc_path = poc_path
        self.file_dir = os.path.join(poc_path, "input.txt")
        self.output_path = output_path

    def run_script(self, script_code: str, timeout: Optional[int] = 360) -> Any:        
        
        base_filename = os.path.splitext(os.path.basename(self.binary_path))[0]
        self.sub_dir = os.path.join(self.temp_dir, self.output_path)
        os.makedirs(self.sub_dir, exist_ok=True)  
        prompt = SCRIPT_PROMPTINPUT.format(
            script_code=script_code,
            poc_path=self.poc_path
        )
        script_code = LLM(self.llm_model).prompt(prompt, reasoning="low")

        # script_code = LLM(self.llm_model).prompt(prompt, reasoning="low")

        script_path = os.path.join(self.sub_dir, f"{base_filename}.py")

        # 如果文件已存在，删除它
        if os.path.exists(script_path):
            os.remove(script_path)
        
        # fd, script_path = tempfile.mkstemp(suffix='.py', dir=self.sub_dir)

        try:
            with open(script_path, 'w') as f:
                f.write(script_code)
            print(f"[INFO] Script written to {script_path} and executing...")
            input_gen_result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            
            if not os.path.exists(self.file_dir):
                return f"Please check the generated script. Input file not found at {self.file_dir}.\n\n" \
            
            try:
                print(f"[INFO] Input file generated successfully. Executing binary...")
                
                if _config.project_name == 'sqlite':
                
                    with open(self.file_dir, 'r') as input_file:
                        final_exec_result = subprocess.run(
                            [self.binary_path], 
                            stdin=input_file,  
                            capture_output=True,  
                            text=True,  
                            timeout=timeout,
                            check=True 
                        )
                elif _config.project_name == 'libplist':
                    final_exec_result = subprocess.run(
                        [self.binary_path, self.file_dir],   
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=True
                    )
                elif _config.project_name == 'libxml2':
                    final_exec_result = subprocess.run(
                        [self.binary_path, self.file_dir],   
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=True
                    )
                else:
                    final_exec_result = subprocess.run(
                        [self.binary_path, self.file_dir],  
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=True
                    )
                stdout = final_exec_result.stdout.strip()
                stderr = final_exec_result.stderr.strip()

                if len(stdout) > MAX_OUTPUT_LENGTH:
                    stdout = stdout[:MAX_OUTPUT_LENGTH] + "\n... (Output truncated, exceeded maximum length)"

                # if len(stderr) > MAX_OUTPUT_LENGTH:
                #     stderr = stderr[:MAX_OUTPUT_LENGTH] + "\n... (Output truncated, exceeded maximum length)"
                return (
                    f"Executable Ran Successfully:\n"
                    f"Command: {self.binary_path} < {self.file_dir}\n\n"
                    f"--- Executable Output ---\n"
                    f"{stdout}\n\n"
                    f"--- Executable Errors (if any) ---\n"
                    f"{stderr[:2000]}"
                )
            except subprocess.CalledProcessError as e:
                return (
                    f"Error Running Executable:\n"
                    f"Command: {e.cmd}\n"
                    f"Return code: {e.returncode}\n\n"
                    f"--- Stdout ---\n{e.stdout[:MAX_OUTPUT_LENGTH]}\n\n"
                    f"--- Stderr ---\n{e.stderr[:2000]}"
                )
            except Exception as e:
                return (
                    f"Unexpected Error Running Executable:\n"
                    f"Type: {type(e).__name__}\n"
                    f"Message: {str(e)}"
                )

        except subprocess.CalledProcessError as e:
            return (
                f"Error Running Python Script to Generate Input:\n"
                f"Command: {e.cmd}\n"
                f"Return code: {e.returncode}\n\n"
                f"--- Stdout ---\n{e.stdout[:MAX_OUTPUT_LENGTH]}\n\n"
                f"--- Stderr ---\n{e.stderr[:2000]}"
            )

        except Exception as e:
            return (
                f"Unexpected Error While Running Script:\n"
                f"Type: {type(e).__name__}\n"
                f"Message: {str(e)}"
            )

if __name__ == "__main__":
    sr = ScriptRunner("./test_code/test2", "./output/test2")

from typing import List
from _pre_codeql import codeql
from code_browser import CodeBrowser
from Node import Node
from prompts.PathAgent import PRUNE, EARLYSTOP, CODESLICE
import importlib
import os
import tempfile
import random
import subprocess
import _config
from llm import LLM
import pandas as pd
from collections import deque
from logger import logger
from colorama import Fore, Back, Style
import json
import warnings
import shutil
import sys
from pathlib import Path
from redis_utils import RedisUtils
import time

BOLD = "\033[1m"  # 定义加粗样式

redis_util = RedisUtils()
cur_path_dir = Path(__file__).parent.resolve()


class PathAgent:
    def __init__(self, project_path, pot_csv):
        self.project_path = (
            project_path  # "projects/sqlite-4e87ddc105c16f6557f041cc4426fbe72e5642ab"
        )
        self.codeqlobj = codeql(self.project_path)
        self.codebrowserobj = CodeBrowser(self.project_path)
        self.codebrowserobj.index_project()
        self.pot_csv = pot_csv

        self.PRUNE = PRUNE
        self.EARLYSTOP = EARLYSTOP
        self.CODESLICE = CODESLICE
        self.llm = LLM("gpt-4.1-mini")

        self.history = [
            {
                "role": "system",
                "content": "Next, the calls to the three functions EARLYSTOP, PRUNE, and CODESLICE that invoke the large model will be recorded.",
            }
        ]

        self.temp_file = ""

    def save_history(self):
        importlib.reload(_config)

        # Path to chat history file
        chat_history_path = os.path.join(
            "chat_history",
            "PathAgent",
            _config.project_name,
            str(_config.id),
            "chat_history.txt",
        )

        os.makedirs(os.path.dirname(chat_history_path), exist_ok=True)
        try:
            # Open chat history file in write mode
            with open(chat_history_path, "w", encoding="utf-8") as f:
                # Dump chat history as JSON
                json.dump(self.history, f, ensure_ascii=False, indent=2)
            # Print success message
            print(f"[SUCCESS] Chat history saved to: {chat_history_path}")

            # Clear history and set initial system message
            self.history = [
                {
                    "role": "system",
                    "content": (
                        "Next, the calls to the three functions EARLYSTOP, PRUNE, "
                        "and CODESLICE that invoke the large model will be recorded."
                    ),
                }
            ]

        except Exception as e:
            # Print error message if saving fails
            print(f"[ERROR] Failed to save chat history: {e}")

    def extract_triple_at(self, text: str) -> str | None:
        """
        Extract the last code block enclosed between '@@@' and '@@@' in the given text,
        including newlines. Returns the block as a string, or None if not found.
        """
        start_idx = text.rfind("@@@")
        if start_idx == -1:
            return None

        # find the matching opening '@@@' before it
        end_idx = start_idx
        start_idx = text.rfind("@@@", 0, end_idx)
        if start_idx == -1:
            return None

        return text[start_idx + 3 : end_idx]

    def call_PRUNE(self, funcname_call, funcbody_call):
        if _config.PRUNEflag == 0:
            return 0
        # Read vulnerability description and code context
        redis_util.set("FunctionBodyChain", "\n".join(funcbody_call))
        base_content = self.get_base_extra()
        vul_des = (
            base_content
            + "\n"
            + f"Function call:\n{funcname_call}\n"
            + f"Function detailed context:\n{funcbody_call}\n"
        )
        vul_des = base_content
        temp_PRUNE = PRUNE.format(
            funcname=funcname_call, funcbody=funcbody_call, vul_des=vul_des
        )
        logger.info("PRUNE: Start PRUNE...")
        message = [{"role": "system", "content": temp_PRUNE}]
        s = self.llm.action(messages=message)
        self.history.append({"role": "user", "content": f"PRUNE: {funcbody_call}"})
        self.history.append({"role": "assistant", "content": f"{s}"})
        logger.info(f"PRUNE RESULT: {s}")
        if "no vulnerability" in s.lower():
            return 1
        else:
            return 0

    def call_EARLYSTOP(self, nodename, rootname, funcname_call, funcbody_call):
        """deprecated"""
        if _config.EARLYSTOPflag == 0:
            return 0
        redis_util.set("FunctionBodyChain", "\n".join(funcbody_call))
        base_content = self.get_base_extra()
        temp_EARLYSTOP = EARLYSTOP.format(
            funcname=nodename, project_name=_config.project_name
        )

        message = [{"role": "system", "content": temp_EARLYSTOP}]
        s = self.llm.action(messages=message)
        self.history.append({"role": "user", "content": f"EARLYSTOP: {funcbody_call}"})
        self.history.append({"role": "assistant", "content": f"{s}"})

        importlib.reload(_config)
        if "@@@entry point@@@" in s:
            os.makedirs(
                f"/tmp/{_config.project_name}/{_config.id}/temppoc", exist_ok=True
            )

            def generate_testcaste_successful():
                poc_path = Path(f"{_config.testcase_agent_path}/poc")
                files = list(poc_path.rglob("*"))
                return "call_info.json" in [file.name for file in files]

            def cleanup_testcase():
                importlib.reload(_config)
                poc_path = Path(f"{_config.testcase_agent_path}/poc")
                temp_dir = (
                    cur_path_dir / "temp" / _config.project_name / str(_config.id)
                )
                temp_dir.parent.mkdir(parents=True, exist_ok=True)
                temp_dir.mkdir(parents=True, exist_ok=True)

                for file in poc_path.rglob("*"):
                    if file.is_file():
                        target_file = temp_dir / file.name

                        counter = 1
                        while target_file.exists():
                            target_file = (
                                temp_dir / f"{file.stem}_{counter}{file.suffix}"
                            )
                            counter += 1

                        try:
                            
                            shutil.move(
                                str(file), str(target_file)
                            ) 
                            print(f"{file} → {target_file}")
                        except Exception as e:
                            print(f"error:{file}, {str(e)}")

                for dir_path in sorted(
                    poc_path.rglob("*"), reverse=True
                ):  
                    if dir_path.is_dir() and not any(dir_path.iterdir()): 
                        try:
                            dir_path.rmdir()
                            print(f"delete empty directory: {dir_path}")
                        except Exception as e:
                            print(f"Failed to delete empty directory: {dir_path}, reason: {str(e)}")

            def get_testcase_info():

                poc_path = Path(f"{_config.testcase_agent_path}/poc")
                files = list(poc_path.rglob("*"))
                info = ("This is something useful:\n"
                        "Vul Function: " + redis_util.get("FunctionName") + "\n"
                        "VulCode: " + redis_util.get("SinkCode") + "\n"
                        "Function Call:\n"
                        "->".join(funcname_call[:-1]) + "\n"
                        "Function detailed context:"
                        + "\n".join(funcbody_call) + "\n"
                        "This is a testcase info:\n")

                for file in files:
                    if file.is_file():
                        try:
                            info += str(file.resolve()) + "\n" + file.read_text() + "\n"
                        except Exception as e:
                            pass
                # Create a temp file under /tmp
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    delete=False,
                    dir=f"/tmp/{_config.project_name}/{_config.id}/temppoc",
                    suffix=".txt",
                ) as tf:
                    tf.write(info)
                    self.temp_file = tf.name

            def copy_tree(src: Path, dst: Path):
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)

            # 先copy内容
            traget_dir = Path(
                f"{_config.testcase_agent_path}/extra/{_config.project_name}/{_config.id}"
            )
            src_dir = cur_path_dir / "extra" / _config.project_name / str(_config.id)

            # 复制到traget_dir
            copy_tree(src_dir, traget_dir)

            extra_file = traget_dir / "1" / "extra.txt"
            baseextra_file = traget_dir / "baseextra.txt"
            funcname_file = traget_dir / "funcname.txt"
            baseextra = baseextra_file.read_text()

            extra = (
                baseextra
                + "\nFunction Call:\n"
                + "->".join(funcname_call[:-1])
                + "\n"
                + "Function detailed context:"
                + "\n".join(funcbody_call)
            )
            extra_file.parent.mkdir(parents=True, exist_ok=True)
            extra_file.write_text(extra)
            funcname_file.write_text(funcname_call[0])
            testcase_start = time.time()
            pathagent_token = float(redis_util.get("TokenCount"))
            before = float(redis_util.get("PathAgentToken"))
            print(f"[INFO] PathAgent token: {pathagent_token + before}")
            redis_util.set("PathAgentToken", str(pathagent_token + before))
            redis_util.set("TokenCount", "0")
            ## TODO TestAgent.py -> Poc
            process = subprocess.Popen(
                [
                    "python3",
                    "TestcaseAgent.py",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=f"{_config.testcase_agent_path}", 
            )

            captured_output = ""
            for line in process.stdout:
                print(line, end="")  # Print output in real time
                captured_output += line  # Store output for later check

            process.wait()
            if traget_dir.exists():
                shutil.rmtree(traget_dir)
                print("[SUCCESS] Cleanup extra directory")
                
            testcase_token = float(redis_util.get("TokenCount"))
            before = float(redis_util.get("TestcaseToken"))
            redis_util.set("TestcaseToken", str(testcase_token + before))
            elapsed_time = float(time.time() - testcase_start)
            before = float(redis_util.get("TestcaseTime"))
            redis_util.set("TestcaseTime", str(elapsed_time + before))
            redis_util.set("TokenCount", "0")
            # TODO if testcase exists, run PocAgent.py
            # Run subprocess and capture + print output
            if generate_testcaste_successful():
                print("[SUCCESS] Testcase generated")
                get_testcase_info()
                cleanup_testcase()
                redis_util.set("TokenCount", "0")
                poc_start = time.time()
                process = subprocess.Popen(
                    [
                        "python3",
                        "PocAgent.py",
                        "-p",
                        self.project_path,
                        "-b",
                        _config.bin_path,
                        "-f",
                        rootname,
                        "-e",
                        self.temp_file,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

                captured_output = ""
                for line in process.stdout:
                    print(line, end="")  # Print output in real time
                    captured_output += line  # Store output for later check

                process.wait()
                poc_token = float(redis_util.get("TokenCount"))
                before = float(redis_util.get("PocToken"))
                print(f"[INFO] Poc token: {poc_token + before}")
                redis_util.set("PocToken", str(poc_token + before))
                elapsed_time = time.time() - poc_start
                before = float(redis_util.get("PocTime"))
                redis_util.set("PocTime", str(elapsed_time + before))
                # Check if the expected success message appears in the output
                if "Exploit successful, generating report" in captured_output:
                    return 1
                else:
                    if os.path.exists(self.temp_file):
                        os.remove(self.temp_file)
                    temppocc1 = f"poc/{_config.project_name}/{_config.id}/temppoc"
                    temppocc2 = f"reports/{_config.project_name}/{_config.id}/temppoc"
                    for path in [temppocc1, temppocc2]:
                        shutil.rmtree(path, ignore_errors=True)
                    return 0

            cleanup_testcase()

        else:
            return 0

    def call_CODESLICE(self, funcname_call, funcbody_call, body):
        if _config.CODESLICEflag == 0:
            return body

        redis_util.set("FunctionBodyChain", "\n".join(funcbody_call))
        # If body has less than 10 lines, return it directly
        if isinstance(body, str) and len(body.strip().splitlines()) <= 10:
            return body
        base_content = self.get_base_extra()
        temp_CODESLICE = CODESLICE.format(
            funcname_call=funcname_call,
            funcbody_call=funcbody_call,
            body=body,
            vul_des=base_content,
        )
        message = [{"role": "system", "content": temp_CODESLICE}]
        logger.info(
            f"{BOLD}{Back.BLACK}{Fore.YELLOW}CODESLICE: Start reducing the function body. {Style.RESET_ALL}"
        )
        s = self.llm.action(messages=message)
        if s == "STOP":
            return "STOP"
        temp = self.extract_triple_at(s)
        logger.info(
            f"{BOLD}{Back.BLACK}{Fore.YELLOW}CODESLICE: The reduced function body is: {temp}. {Style.RESET_ALL}"
        )
        self.history.append({"role": "user", "content": f"CODESLICE: {body}"})
        self.history.append({"role": "assistant", "content": f"{s}"})
        if temp is None:
            return body
        else:
            return temp

    def _get_callers(self, name: str) -> list[str]:
        funccall = self.codeqlobj.getcallfunc(name) or []
        macrocall = self.codeqlobj.getcallmacro(name) or []
        # Filter out None / empty strings and convert them to str
        callers = [
            str(c) for c in (funccall + macrocall) if c is not None and str(c).strip()
        ]

        print(f"\n[INFO] >>> Callers of {name}: {callers} <<<\n")

        return callers

    def get_tree(self, node: Node) -> None:
        """
        dfs
        Starting from node, recursively construct a "who called me" call tree.
        It only modifies the tree, no return value; the entire tree can be accessed via the Node object.
        """
        callers = self._get_callers(node.name)  # 1. Find the callers
        for caller_name in callers:
            child = Node(caller_name)  # 2. Create a new node
            body_temp = self.codebrowserobj.get_body_without_hint(caller_name)
            child.set_body(body_temp)
            node.add_child(child)  # Attach to the current node
            self.get_tree(child)  # 3. Continue recursion

    def false_report(self, root):
        print(
            f"[PRUNE] Config ID: {_config.id} | Node pruned | Path (funcname): {root.get_path_to_root_funcname()}"
        )

        os.makedirs(f"extra/{_config.project_name}/{_config.id}", exist_ok=True)

        with open(
            f"extra/{_config.project_name}/{_config.id}/PRUNE.txt",
            "w",
            encoding="utf-8",
        ) as f:
            f.write(
                "This issue has been reviewed and determined to be a false positive.\n\n"
                "Details:\n"
                "- The reported behavior does not represent an actual security vulnerability.\n"
                "- The data flow does not involve untrusted user input.\n"
                "- All parameters are either properly escaped or constant values.\n\n"
                "Conclusion:\n"
                "Based on the above analysis, this report is categorized as a false positive "
                "and requires no further remediation."
            )

        return "[PRUEN] >>> The root function is a false postive. <<<"

    def get_tree_plus(self, root: Node) -> None:
        """
        bfs
        Starting from the given node, construct a "who called me" call tree using BFS.
        This function modifies the tree in place and does not return any value.
        """
        importlib.reload(_config)
        # Pruning condition
        if (
            self.call_PRUNE(
                root.get_path_to_root_funcname(),
                root.get_path_to_root_funcbody(),
            )
            == 1
        ):
            return self.false_report(root)

        # Initialize queue with depth=0 for root
        queue = deque([(root, 0)])

        while queue:
            node, depth = queue.popleft()
            if depth == 3:
                continue
            logger.info(
                f"{BOLD}{Back.BLUE}{Fore.YELLOW}"
                f"Config ID: {_config.id} | Tree (level {depth}): Processing node: {node.name}"
                f"{Style.RESET_ALL}"
            )
            temp_body = self.call_CODESLICE(
                node.get_path_to_root_funcname(),
                node.get_path_to_root_funcbody(),
                node.body,
            )

            if temp_body == "STOP":
                return "[STOP] >>> The length of function is too long!!! <<<"  # if the length of function is too long, stop analyzing

            # Set the body (code slice) of the current node
            node.set_body(temp_body)

            # Find all callers of the current node
            callers = self._get_callers(node.name)
            callers = random.sample(callers, k=min(5, len(callers)))

            valid_children = []

            for caller_name in callers:
                # Create a child node
                child = Node(caller_name)
                body_temp = self.codebrowserobj.get_body_without_hint(caller_name)
                child.set_body(body_temp)
                node.add_child(child)

                logger.info(
                    f"{BOLD}{Back.BLUE}{Fore.YELLOW}"
                    f"Config ID: {_config.id} | Tree (level {depth+1}): Processing child node: {child.name}"
                    f"{Style.RESET_ALL}"
                )

                # Early stopping condition
                if self.call_EARLYSTOP(
                    child.name,
                    child.get_root_name(),
                    child.get_path_to_root_funcname(),
                    child.get_path_to_root_funcbody(),
                ):
                    print(
                        f"[EARLYSTOP] Config ID: {_config.id} | Path (funcname): {child.get_path_to_root_funcname()}"
                    )
                    self.__get_extra_sstr("VulPath", child)
                    return "BFS stops entirely here"

                # Pruning condition
                if (
                    self.call_PRUNE(
                        child.get_path_to_root_funcname(),
                        child.get_path_to_root_funcbody(),
                    )
                    == 1
                ):
                    print(
                        f"[PRUNE] Config ID: {_config.id} | Node pruned | Path (funcname): {child.get_path_to_root_funcname()}"
                    )
                    # Prune => remove this child node
                    node.remove_child(child)
                else:
                    # Enqueue child with depth+1
                    # queue.append((child, depth + 1))
                    valid_children.append((child, depth + 1))

            sink_code = redis_util.get("SinkCode")
            func_name = redis_util.get("FunctionName")

            valid_children = self._sort_by_call_chain_analysis(
                valid_children, node, sink_code, func_name
            )
            for child, child_depth in valid_children:
                queue.append((child, child_depth))

        print(f">>> ✅ BFS construction completed | Config ID: {_config.id} ✅ <<<")
        return ""

    def _sort_by_call_chain_analysis(
        self, valid_children: list, parent_node: "Node", sink_code: str, func_name: str
    ) -> list:
        sort_mode = getattr(_config, "sort_mode", "normal").lower()

        if len(valid_children) <= 1:
            return valid_children

        if sort_mode == "random":
            print(
                f"[SORT] Using RANDOM mode for {len(valid_children)} nodes "
                f"(Config ID: {_config.id})"
            )
            random.shuffle(valid_children)
            return valid_children

        print(
            f"[SORT] Using {sort_mode.upper()} mode for {len(valid_children)} nodes "
            f"(Config ID: {_config.id})"
        )

        scored_children = []

        for child, depth in valid_children:
            try:
                call_chain_body = child.get_path_to_root_funcbody()

                score = self._get_llm_absolute_value_score_from_call_chain(
                    child, call_chain_body, sink_code, func_name
                )

                scored_children.append((score, child, depth))

                print(
                    f"  [{child.name}] Call Chain Length: {len(call_chain_body)} | "
                    f"Absolute Value Score: {score:.2f}"
                )
            except Exception as e:
                logger.error(f"Error getting score for {child.name}: {e}")
                scored_children.append((0.0, child, depth))

        scored_children.sort(key=lambda x: x[0], reverse=True)

        if sort_mode == "none":
            print(f"[SORT] Reversing order (none mode) - Config ID: {_config.id}")
            scored_children.reverse()

        print(f"[SORT RESULT] Config ID: {_config.id} - Final order:")
        for idx, (score, child, _) in enumerate(scored_children, 1):
            print(f"  {idx}. {child.name}: score={score:.2f}")

        return [(child, depth) for _, child, depth in scored_children]

    def _get_llm_absolute_value_score_from_call_chain(
        self, child_node: "Node", call_chain_body: list, sink_code: str, func_name: str
    ) -> float:
        try:
            prompt = self._build_call_chain_ranking_prompt(
                child_node, call_chain_body, sink_code, func_name
            )

            messages = [{"role": "user", "content": prompt}]

            logger.debug(
                f"[LLM] Calling for node: {child_node.name} | "
                f"Call chain depth: {len(call_chain_body)}"
            )

            response = self.llm.action(messages, reasoning="medium", temperature=0.0)

            if response == "STOP":
                logger.warning(f"[LLM] STOP response for {child_node.name}")
                return 0.0

            score = self._extract_score_from_response(response)

            logger.debug(
                f"[LLM] Response for {child_node.name}: raw='{response}' -> score={score}"
            )

            return score

        except Exception as e:
            logger.error(
                f"[LLM] Error getting score for {child_node.name}: {e}", exc_info=True
            )
            return 0.0

    def _build_call_chain_ranking_prompt(
        self, child_node: Node, call_chain_body: list, sink_code: str, func_name: str
    ) -> str:
        call_chain_text = call_chain_body

        prompt = f"""Analyze the absolute value magnitude of data that could reach the sink code through this function call chain.

    ================== TASK ==================
    Analyze the complete call chain and determine the absolute value magnitude (range) 
    that could be passed to or computed near the sink code.

    ================== CALL CHAIN ==================
    Root Function: {func_name}
    Current Node: {child_node.name}

    {call_chain_text}

    ================== TARGET SINK CODE ==================
    {sink_code}

    ================== ANALYSIS INSTRUCTIONS ==================
    1. Trace through each function in the call chain from top to bottom
    2. Identify arithmetic operations (*, +, -, /, **, //, %)
    3. Track how input values are transformed at each step
    4. Determine the possible range of absolute values that could reach the sink code

    Example analysis:
    - If chain: f1(x) -> f2(x*2) -> f3(x*2+100)
    - And sink involves x*1000000, the data magnitude increases significantly through the chain
    - Assign score based on final magnitude: 0-20 for <100,000, 21-40 for 100,000-100,000,000, ..., 81-100 for >1,500,000,000

    ================== SCORING GUIDELINES ==================
    Score from 0-100 based on the absolute value magnitude that could reach sink:
    - 0-20:   Tiny values (0-100,000)
    - 21-40:  Small values (100,000-100,000,000)
    - 41-60:  Medium values (100,000,000-500,000,000)
    - 61-80:  Large values (500,000,000-1,500,000,000)
    - 81-100: Huge values (>1,500,000,000)

    Consider:
    - Multiplication operations amplify magnitude
    - Loop/recursion could exponentially increase values
    - User input or API calls as sources can be large
    - Database queries might return large datasets

    ================== RESPONSE FORMAT ==================
    Return ONLY a JSON object with the following format:
    {{
    "reasoning": "Detailed analysis of how the data flows through the call chain and how values are transformed",
    "score": 75
    }}

    Where:
    - "reasoning" should be a detailed explanation of your analysis
    - "score" should be an integer between 0 and 100

    Example:
    {{
    "reasoning": "The call chain starts with user input that gets multiplied by 2 in f2, then added to 100 in f3. This results in medium-sized values that could reach the sink code.",
    "score": 45
    }}
    """
        return prompt

    def _extract_score_from_response(self, response: str) -> float:
        import json
        import re

        try:
            response_stripped = response.strip()

            try:
                result = json.loads(response_stripped)
                if "score" in result:
                    score = float(result["score"])
                    final_score = min(100.0, max(0.0, score))
                    logger.info(
                        f"Extracted reasoning: {result.get('reasoning', 'No reasoning provided')}"
                    )
                    return final_score
            except json.JSONDecodeError:
                json_pattern = r"\{(?:[^{}]|(?R))*\}"
                matches = re.findall(json_pattern, response_stripped, re.DOTALL)

                for match in matches:
                    try:
                        result = json.loads(match)
                        if "score" in result:
                            score = float(result["score"])
                            final_score = min(100.0, max(0.0, score))
                            logger.info(
                                f"Extracted reasoning: {result.get('reasoning', 'No reasoning provided')}"
                            )
                            return final_score
                    except json.JSONDecodeError:
                        continue

            logger.warning(
                f"Could not parse JSON score from response: {response_stripped[:100]}"
            )
            return 50.0  

        except Exception as e:
            logger.error(f"Error extracting score: {e}")
            return 50.0

    def find_leaves(self, root: Node) -> List[Node]:
        """Return all leaf nodes (nodes with no children)"""
        leaves = []

        def dfs(node: Node):
            if not node.children:  # No children -> leaf node
                leaves.append(node)
            else:
                for child in node.children:
                    dfs(child)

        dfs(root)
        return leaves

    def print_paths_from_leaves_names(self, root: Node) -> None:
        importlib.reload(_config)

        # if not root.children:
        #     self.false_report(root)

        out_file = _config.funcnamechainfile
        # Print all funcname from leaves to the root
        leaves = self.find_leaves(root)

        # Ensure the output directory exists
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            for leaf in leaves:
                path = leaf.get_path_to_root_funcname()
                # Defensive check to avoid None
                if any(n is None for n in path):
                    continue
                line = " -> ".join(path)
                f.write(line + "\n")

    def print_paths_from_leaves_body(self, root: Node) -> None:
        importlib.reload(_config)

        out_file = _config.funcbodychainfile
        # Print all funcbody from leaves to the root
        leaves = self.find_leaves(root)
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            for leaf in leaves:
                path = leaf.get_path_to_root_funcbody()
                # Defensive check to avoid None
                if any(n is None for n in path):
                    continue
                line = "".join(path)
                f.write(line + "\n[SEP]\n")
            self.print_paths_from_leaves_names(root)

    def get_base_extra(self):
        """
        This method reads a CSV file for a specific ID, retrieves the information,
        and writes it to 'extra/{project_name}/{_config.id}/baseextra.txt'. If the file already exists,
        it reads the content instead of writing to it.

        Args:
            project_name (str): The name of the project.
            id (int or str): The ID to search for in the CSV file.

        Returns:
            str: The content of the baseextra.txt file if it exists or is created successfully.
            str: 'failed' if no matching ID is found in the CSV file.
        """
        importlib.reload(_config)
        strid = str(_config.id)
        base_directory = os.path.abspath(self.project_path)

        # Define the path for the baseextra.txt file
        extra_file_path = os.path.join(
            "extra", _config.project_name, strid, "baseextra.txt"
        )
        # extra_file_path = os.path.join(base_directory, extra_file_path)

        # If the file already exists, read and return its content
        if os.path.exists(extra_file_path):
            with open(extra_file_path, "r", encoding="utf-8") as f:
                return f.read()

        # Read the CSV file using pandas
        df = pd.read_csv(self.pot_csv)

        expected_columns = {
            "Name",
            "Description",
            "Severity",
            "Message",
            "Path",
            "Start line",
            "Start column",
            "End line",
            "End column",
            "Vul code",
            "Code content",
            "Closest Function Name",
            "Closest Function Line",
            "ID",
        }
        if not expected_columns.issubset(df.columns):
            return "CSV file is missing required columns"

        # Filter the row that matches the provided ID
        row = df.iloc[int(_config.id) - 1]

        if not row.empty:
            extra_content = (
                f"Vulnerability Description:\n{row['Description'].strip()}\n\n"
                f"Message:\n{row['Message'].strip()}\n\n"
                f"Function:\n{row['Closest Function Name'].strip()}\n\n"
                f"Vulnerable Code:\n{row['Vul code'].strip()}\n\n"
                f"File:\n{os.path.join(base_directory, row['Path'].lstrip('/'))}\n\n"
                f"Line Number:\n{row['Start line']}\n\n"
                f"Code Context:\n{row['Code content'].strip()}\n\n"
            )

            # Ensure the directory exists before writing the file
            os.makedirs(os.path.dirname(extra_file_path), exist_ok=True)

            # Write the content to the file if it doesn't exist
            with open(extra_file_path, "w", encoding="utf-8") as outf:
                outf.write(extra_content)

            return extra_content
        else:
            return "failed"

    def __get_extra_sstr(self, sstr, node):
        importlib.reload(_config)
        # Ensure the project path exists
        extra_base_path = os.path.join("extra", _config.project_name)
        os.makedirs(extra_base_path, exist_ok=True)

        # Read the baseextra.txt file
        baseextra_path = os.path.join(
            extra_base_path, f"{str(_config.id)}/baseextra.txt"
        )
        try:
            with open(baseextra_path, "r", encoding="utf-8") as file:
                baseextra = file.read()
        except FileNotFoundError:
            baseextra = "Base extra information not found."

        # Create the directory for vulnerability information
        extra_dir = os.path.join(extra_base_path, f"{_config.id}/{sstr}")
        os.makedirs(extra_dir, exist_ok=True)

        # Write vulnerability information into extra.txt
        extra_path = os.path.join(extra_dir, "extra.txt")
        with open(extra_path, "w", encoding="utf-8") as outf:
            outf.write(
                baseextra + f"\nFunction call:\n"
                f"{node.get_path_to_root_funcname()}\n\n"
                f"Function detailed context:\n"
                f"{node.get_path_to_root_funcbody()}"
            )

        return f"The {sstr} of {_config.id} vulnerability extra.txt has been created!"

    def Genextra(self):
        importlib.reload(_config)
        # Define the output directory where all the generated files will be stored
        outdir = f"extra/{_config.project_name}/{str(_config.id)}"
        os.makedirs(outdir, exist_ok=True)

        # Verify that the input files exist before proceeding
        if not os.path.exists(_config.funcnamechainfile):
            warnings.warn(
                f"Function name chain file '{_config.funcnamechainfile}' not found! Skipping Genextra."
            )
            return "!skip Genextra!"

        if not os.path.exists(_config.funcbodychainfile):
            warnings.warn(
                f"Function body chain file '{_config.funcbodychainfile}' not found! Skipping Genextra."
            )
            return "!skip Genextra!"

        # Read the chain of function calls from 'namechain.txt'
        with open(_config.funcnamechainfile) as f:
            chain = f.read().strip()

        # Read the body of the functions from 'bodychain.txt'
        with open(_config.funcbodychainfile) as f:
            body = f.read().strip()

        # Split the chain and body into individual function calls and bodies
        calls = chain.split("\n")
        bodies = body.split("[SEP]")

        # Loop through each pair of call and body
        for idx, (c, b) in enumerate(zip(calls, bodies), 1):
            # Create a subdirectory for each function pair
            subdir = os.path.join(outdir, str(idx))
            os.makedirs(subdir, exist_ok=True)

            # Write the function call to 'call.txt'
            with open(os.path.join(subdir, "call.txt"), "w") as cf:
                cf.write(c.strip() + "\n")

            # Write the function body to 'body.txt'
            with open(os.path.join(subdir, "body.txt"), "w") as bf:
                bf.write(b.strip() + "\n")

            with open(os.path.join(subdir, "extra.txt"), "w") as ef:
                ef.write(
                    self.get_base_extra()  # Assuming this method exists to get some base extra data
                    + f"\nFunction call:\n"
                    f"{c.strip()}\n\n"  # No need to add "\n" manually inside the f-string
                    f"Function detailed context:\n"
                    f"{b.strip()}\n"  # Same for this one, just strip and add a newline after
                )

        # Return a completion message
        return "!split done!"

    def _run_testcase_and_poc_agents(self, root: Node):
        os.makedirs(f"/tmp/{_config.project_name}/{_config.id}/temppoc", exist_ok=True)

        def generate_testcaste_successful():
            poc_path = Path(f"{_config.testcase_agent_path}/poc") 
            files = list(poc_path.rglob("*"))
            return "call_info.json" in [file.name for file in files]

        def cleanup_testcase():
            importlib.reload(_config)
            poc_path = Path(f"{_config.testcase_agent_path}/poc") 
            temp_dir = cur_path_dir / "temp" / _config.project_name / str(_config.id)
            temp_dir.parent.mkdir(parents=True, exist_ok=True)
            temp_dir.mkdir(parents=True, exist_ok=True)

            for file in poc_path.rglob("*"):
                if file.is_file():
                    target_file = temp_dir / file.name

                    counter = 1
                    while target_file.exists():
                        target_file = temp_dir / f"{file.stem}_{counter}{file.suffix}"
                        counter += 1

                    try:
                        shutil.move(
                            str(file), str(target_file)
                        )  
                        print(f"move: {file} → {target_file}")
                    except Exception as e:
                        print(f"move failed: {file}, reason: {str(e)}")

            for dir_path in sorted(
                poc_path.rglob("*"), reverse=True
            ):  
                if dir_path.is_dir() and not any(dir_path.iterdir()): 
                    try:
                        dir_path.rmdir()
                        print(f"removed empty directory: {dir_path}")
                    except Exception as e:
                        print(f"remove empty directory failed: {dir_path}, reason: {str(e)}")

        def get_testcase_info():
            poc_path = Path(f"{_config.testcase_agent_path}/poc") 
            files = list(poc_path.rglob("*"))
            info = "This is something useful:\n" + redis_util.get("SuccessCall") + "\n"
            for file in files:
                if file.is_file():
                    file_path = str(file.resolve())
                    info += f"{file_path}:\n"
                    try:
                        # Read file content (adjust encoding if needed for your use case)
                        content = file.read_text(encoding="utf-8", errors="ignore")
                        max_length = 100
                        if len(content) > max_length:
                            # Truncate to max length and add truncation notice
                            truncated_content = content[:max_length]
                            info += f"{truncated_content}\n[Note: File content too long ({len(content)} characters), truncated]\n\n"
                        else:
                            info += f"{content}\n\n"
                    except Exception as e:
                        # Handle read errors (e.g., permission denied, corrupted file)
                        info += f"[Warning: Failed to read file - {str(e)}]\n\n"
            # Create a temp file under /tmp
            with tempfile.NamedTemporaryFile(
                mode="w",
                delete=False,
                dir=f"/tmp/{_config.project_name}/{_config.id}/temppoc",
                suffix=".txt",
            ) as tf:
                tf.write("This is a testcase info:\n" + info)
                self.temp_file = tf.name

        def copy_tree(src: Path, dst: Path):
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)

        traget_dir = Path(
            f"{_config.testcase_agent_path}/extra/{_config.project_name}/{_config.id}" 
        )
        src_dir = cur_path_dir / "extra" / _config.project_name / str(_config.id)

        copy_tree(src_dir, traget_dir)

        try:
            print(">>> Running TestcaseAgent...")
            testcase_start = time.time()
            pathagent_token = float(redis_util.get("TokenCount"))
            before = float(redis_util.get("PathAgentToken"))
            print(f"[INFO] PathAgent token: {pathagent_token + before}")
            redis_util.set("PathAgentToken", str(pathagent_token + before))
            redis_util.set("TokenCount", "0")
            process = subprocess.Popen(
                [
                    "python3",
                    "TestcaseAgent.py",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=f"{_config.testcase_agent_path}",  
            )

            captured_output = ""
            for line in process.stdout:
                print(line, end="")  # Print output in real time
                captured_output += line  # Store output for later check

            process.wait()
            if traget_dir.exists():
                shutil.rmtree(traget_dir)
                print("[SUCCESS] Cleanup extra directory")
            testcase_token = float(redis_util.get("TokenCount"))
            before = float(redis_util.get("TestcaseToken"))
            print(f"[INFO] Testcase token: {testcase_token}")
            redis_util.set("TestcaseToken", str(testcase_token + before))
            elapsed_time = float(time.time() - testcase_start)
            before = float(redis_util.get("TestcaseTime"))
            redis_util.set("TestcaseTime", str(elapsed_time + before))
            redis_util.set("TokenCount", "0")
            print(
                f"[SUCCESS] PathAgentToken: {pathagent_token}, TestcaseToken: {testcase_token}, TestcaseTime: {elapsed_time}"
            )
            if generate_testcaste_successful():
                print("[SUCCESS] Testcase generated")
                get_testcase_info()
                cleanup_testcase()
                redis_util.set("TokenCount", "0")
                poc_start = time.time()
                process = subprocess.Popen(
                    [
                        "python3",
                        "PocAgent.py",
                        "-p",
                        self.project_path,
                        "-b",
                        _config.bin_path,
                        "-f",
                        root.name,
                        "-e",
                        self.temp_file,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

                captured_output = ""
                for line in process.stdout:
                    print(line, end="")  # Print output in real time
                    captured_output += line  # Store output for later check

                process.wait()
                poc_token = float(redis_util.get("TokenCount"))
                before = float(redis_util.get("PocToken"))
                print(f"[INFO] Poc token: {poc_token + before}")
                redis_util.set("PocToken", str(poc_token + before))
                elapsed_time = time.time() - poc_start
                before = float(redis_util.get("PocTime"))
                redis_util.set("PocTime", str(elapsed_time + before))
                # Check if the expected success message appears in the output
                if (
                    "exploit successful" in captured_output.lower()
                    or "success" in captured_output.lower()
                ):
                    print(">>> PocAgent completed successfully")
                    return True
                else:
                    if os.path.exists(self.temp_file):
                        os.remove(self.temp_file)
                    temppocc1 = f"poc/{_config.project_name}/{_config.id}/temppoc"
                    temppocc2 = f"reports/{_config.project_name}/{_config.id}/temppoc"
                    for path in [temppocc1, temppocc2]:
                        shutil.rmtree(path, ignore_errors=True)
                    return False
            else:
                print(">>> TestcaseAgent failed to generate test case")
                return False

        except Exception as e:
            print(f"Error running TestcaseAgent and PocAgent: {e}")
            return False

        finally:
            cleanup_testcase()

    def run(self, startfunc):
        importlib.reload(_config)

        # Path to save chat history
        trace_history = os.path.join(
            "chat_history",
            "PathAgent",
            _config.project_name,
            str(_config.id),
            "TraceProcess.txt",
        )
        os.makedirs(os.path.dirname(trace_history), exist_ok=True)

        # Tee class: redirect output to both terminal and file
        class Tee:
            def __init__(self, filename, mode="w", encoding="utf-8"):
                self.file = open(filename, mode, encoding=encoding)
                self.stdout = sys.stdout  # keep original stdout

            def write(self, text):
                self.file.write(text)  # write to file
                self.stdout.write(text)  # write to terminal

            def flush(self):
                self.file.flush()
                self.stdout.flush()

            def close(self):
                self.file.close()

        tee = Tee(trace_history)
        original_stdout = sys.stdout
        sys.stdout = tee  # redirect all prints

        try:
            # --- Original run function content ---
            self.get_base_extra()  # Generate base vulnerability info

            # Initialize root node
            root = Node(startfunc)
            rootbody = self.codebrowserobj.get_body_without_hint(startfunc)
            root.set_body(rootbody)

            print(self.get_tree_plus(root))  # Build call tree

            vulpath_extra = os.path.join(
                "extra", _config.project_name, str(_config.id), "VulPath", "extra.txt"
            )

            checktoken = self.llm.output_token()

            if os.path.exists(vulpath_extra):
                print(">>> running save_history")
                self.save_history()

                print("Early stop: call chain discovered.")
                return ["", checktoken]

            print(">>> running print_paths_from_leaves_body")
            self.print_paths_from_leaves_body(root)

            print(">>> running print_paths_from_leaves_names")
            self.print_paths_from_leaves_names(root)

            print(">>> running Genextra")
            message = self.Genextra()
            print(f">>> {message}")

            print(">>> running save_history")
            self.save_history()

            # If PRUNE.txt not exists, continue
            if not os.path.exists(vulpath_extra) and not os.path.exists(
                os.path.join(
                    "extra",
                    _config.project_name,
                    str(_config.id),
                    "PRUNE.txt",
                )
            ):
                self._run_testcase_and_poc_agents(root)

            checktoken = self.llm.output_token()
            self.llm.clear_token()
            return [message, checktoken]

        finally:
            sys.stdout = original_stdout  # restore original stdout
            tee.close()


if __name__ == "__main__":
    importlib.reload(_config)
    pathagent = PathAgent(_config.project_path, _config.vul_path)
    pathagent.run(_config.startfunc)

import os
import csv
from clang.cindex import Index, CursorKind, TranslationUnit
import bisect
from _pre_codeql import codeql
import pandas as pd
import re
from redis_utils import RedisUtils
from llm import LLM
redis_util = RedisUtils()
import clang.cindex
import _config
import random
import json
            
def safe_del(self):
    try:
        if getattr(clang.cindex.conf, "lib", None) is not None:
            clang.cindex.conf.lib.clang_disposeIndex(self)
    except Exception:
        pass  

clang.cindex.Index.__del__ = safe_del

cflag = 0 # control to build func call
class CodeBrowser:
    INTERESTED_KINDS = {
        CursorKind.FUNCTION_DECL: "function",           # Function declaration
        CursorKind.CXX_METHOD: "function",              # C++ member method
        CursorKind.CLASS_DECL: "class",                 # Class declaration
        CursorKind.STRUCT_DECL: "struct",               # Struct declaration
        CursorKind.MACRO_DEFINITION: "macro",           # Macro definition
        # CursorKind.VAR_DECL: "variable",              # Non-member variable (commented out)
        # CursorKind.FIELD_DECL: "member_variable",     # Member variable (commented out)
    }

    def __init__(self, project_path: str):
        # The index is stored in the index.csv file under the project path
        self.project_path = os.path.abspath(project_path)  # Get the absolute path of the project
        self.output_csv = os.path.join(project_path, 'index.csv')  # Path to the index file
        self.source_files = []     # List to store source files
        # self.index = None          # Unknown why it causes an error, temporarily set to None
        self.index = Index.create()  # Originally might be used to create the index
        self.definitions = []      # List to store code definitions (functions, classes, etc.)
    

    def collect_source_files(self) -> list:
        """
        Recursively collect all C/C++ source files under the project path.
        """
        self.source_files = []
        for root, _, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(('.h', '.hpp', '.cpp', '.cc', '.cxx', '.c')):
                    self.source_files.append(os.path.join(root, file))
        return self.source_files


    def extract_definitions_from_file(self, filename: str) -> list:
        try:
            tu = self.index.parse(
                filename,
                args=['-x', 'c++', '-std=c++17'],
                options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            )
        except Exception as e:
            print(f"[ERROR] Failed to parse {filename}: {e}")
            return []

        # Read the source file content
        with open(filename, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()

        definitions = []
        for node in tu.cursor.walk_preorder():
            if node.kind in self.INTERESTED_KINDS:
                name = node.spelling
                start_line = node.extent.start.line
                end_line = node.extent.end.line

                # ----------------------------
                # Check if there is an attached comment above
                # ----------------------------
                comment_start = self._find_attached_comment(source_lines, start_line)
                if comment_start < start_line:
                    start_line = comment_start  # Extend the start line of the definition

                definitions.append({
                    'name': name,
                    'type': self.INTERESTED_KINDS[node.kind],
                    'filename': filename,
                    'start_line': start_line,
                    'end_line': end_line
                })

        return definitions

    def _find_attached_comment(self, source_lines, code_line):
        """
        Return the starting line number (1-based) of the nearest continuous comment block
        above the given code line (1-based). Supports both // and /* */ comment styles.
        """
        i = min(code_line - 2, len(source_lines) - 1)  # Start from the line above the code (0-based)
        comment_start = code_line  # Initially assume no comment

        while i >= 0:
            line = source_lines[i]

            # Case 1: Single-line // comment
            if re.match(r'^\s*//', line):
                comment_start = i + 1  # Convert to 1-based
                i -= 1
                continue

            # Case 2: /* ... */ block comment (possibly multi-line)
            if '*/' in line:
                # Look upward for the /* start
                j = i
                while j >= 0 and '/*' not in source_lines[j]:
                    j -= 1
                if j >= 0:  # Found a valid /* ... */ block
                    comment_start = j + 1  # 1-based
                    i = j - 1
                    continue
                else:
                    break  # Invalid block, stop

            # Case 3: Empty line (considered part of the comment)
            if line.strip() == '':
                i -= 1
                continue

            # Other cases: non-comment, stop searching
            break

        return comment_start


    def index_project(self):
        """
        Index the entire project, collect all definitions, and write them to a CSV file.
        """
        if not os.path.exists(self.output_csv):
            self.collect_source_files()
            all_definitions = []

            for f in self.source_files:
                defs = self.extract_definitions_from_file(f)
                all_definitions.extend(defs)

            self.definitions = all_definitions
            self.write_to_csv(all_definitions)


    def write_to_csv(self, definitions: list):
        """
        Write the definitions to a CSV file.
        """
        fieldnames = ['id', 'name', 'type', 'filename', 'start_line', 'end_line']
        definitions = sorted(definitions, key=lambda d: d.get('name', ''))

        with open(self.output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for idx, d in enumerate(definitions, start=1):
                row = {
                    'id': idx,
                    'name': d.get('name', ''),
                    'type': d.get('type', ''),
                    'filename': d.get('filename', ''),
                    'start_line': d.get('start_line', 0),
                    'end_line': d.get('end_line', 0)
                }
                writer.writerow(row)


    def get_function_calls(self, function_name: str) -> list:
        """
        Find all locations that call the specified function.
        """
        c = codeql(self.project_path)
        # c.create()
        result = {
            "Function calling this function is/are ": c.getcallfunc(function_name),
            "Macro calling this function is/are ": c.getcallmacro(function_name)
        }
        
        return result

    
    def get_body(self, name: str, type: str = None, cflag: int = cflag) -> list:
        """
        Look up definitions with the specified name from the index and return the corresponding source code snippet.
        If it is a function, optionally include information about who calls it.
        """
        results = []

        # Read the index CSV
        with open(self.output_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

            names = [row['name'] for row in rows]

            # Find the range of rows matching the name
            left = bisect.bisect_left(names, name)
            right = bisect.bisect_right(names, name)

            # Iterate over all rows with the same name
            for i in range(left, right):
                row = rows[i]
                # If a type is specified, skip rows that don't match
                if type and row['type'] != type:
                    continue

                filename = row['filename']
                start_line = int(row['start_line'])
                end_line = int(row['end_line'])

                if not os.path.exists(filename):
                    print(f"[WARNING] File not found: {filename}, skipping.")
                    continue

                try:
                    with open(filename, 'r', encoding='utf-8') as source_file:
                        lines = source_file.readlines()
                        snippet = lines[start_line - 1:end_line]
                        results.append({
                            'name': row['name'],
                            'type': row['type'],
                            'filename': filename,
                            'start_line': start_line,
                            'end_line': end_line,
                            'source': [line.rstrip('\n') for line in snippet]
                        })
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        res = "\n========== Begin of tool results ==========\n"
        seen = set()
        # Output each result
        for i, item in enumerate(results, 1):
            # Use the name and source as a unique identifier
            identifier = (item['name'], "\n".join(item['source']))
            if identifier not in seen:
                if len(seen) != 0:
                    res += "========== This is a delimiter ==========\n"
                seen.add(identifier)
                res += f"Result {len(seen)}:\n"
                res += f"Name: {item['name']} (Type: {item['type']}) in {item['filename']}\n"
                res += f"Lines: {item['start_line']} - {item['end_line']}\n"
                for line_num, line_content in enumerate(item['source'], start=item['start_line']):
                    res += f"{line_num}: {line_content}\n"

                # If the item is a function and cflag is set, include call information
                if item['type'] == "function" and cflag:
                    listresult = [f"{key}: {value}" for key, value 
                                in self.get_function_calls(item['name']).items()]
                    strresult = "\n".join(listresult)
                    res += '!!!!!!!Note:!!!!!!!\n'
                    res += strresult + '\n'
                res += "\n"

        # Output the number of results
        res += f"There are {len(seen)} corresponding results for {name}.\n"
        # Mark the end of scan results
        res += "========== End of tool results ==========\n"

        return res

    def get_body_without_hint(self, name: str, type: str = None, cflag: int = cflag) -> str:
        """
        Look up the definition of the given name from the index and return its source snippet.
        If it is a function and `cflag` is set, also append information about its callers.
        If no match is found, return the name itself.
        """
        results = []
        # function_body_chain = redis_util.get('FunctionBodyChain')
        # start_func = redis_util.get('FunctionName')
        # sink_code = redis_util.get('SinkCode')
        
        
        # Read the index CSV
        with open(self.output_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

            names = [row['name'] for row in rows]

            # Attempt binary search (requires names to be sorted)
            left = bisect.bisect_left(names, name)
            right = bisect.bisect_right(names, name)

            candidate_rows = []
            if left < right and all(n == name for n in names[left:right]):
                # Valid binary search result
                candidate_rows = rows[left:right]
            else:
                # Fallback: full scan if names are not sorted or mismatch occurs
                candidate_rows = [row for row in rows if row['name'] == name]

            # No match → return the name itself
            if not candidate_rows:
                return name

            # Process matched rows
            for row in candidate_rows:
                if type and row['type'] != type:
                    continue

                filename = row['filename']
                start_line = int(row['start_line'])
                end_line = int(row['end_line'])

                if not os.path.exists(filename):
                    print(f"[WARNING] File not found: {filename}, skipping.")
                    continue

                try:
                    with open(filename, 'r', encoding='utf-8') as source_file:
                        lines = source_file.readlines()
                        snippet = lines[start_line - 1:end_line]
                        results.append({
                            'name': row['name'],
                            'type': row['type'],
                            'filename': filename,
                            'start_line': start_line,
                            'end_line': end_line,
                            'source': [line.rstrip('\n') for line in snippet]
                        })
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        # If still no results, return the name itself
        if not results:
            return name
        # if _config.TRACEORDER == 'normal' and name != start_func:
        #     results = self._sort_results_by_value_range(results, start_func, sink_code, function_body_chain)
        #     results = results[0]
        # elif _config.TRACEORDER == 'random':
        #     random.shuffle(results)
        #     results = results[0]
            
        res = ""
        seen = set()
        for i, item in enumerate(results, 1):
            # Use name and source as a unique identifier to avoid duplicates
            identifier = (item['name'], "\n".join(item['source']))
            if identifier not in seen:
                seen.add(identifier)
                for line_num, line_content in enumerate(item['source'], start=item['start_line']):
                    res += f"{line_num}: {line_content}\n"

                # Append function call information if applicable
                if item['type'] == "function" and cflag:
                    listresult = [f"{key}: {value}" for key, value 
                                in self.get_function_calls(item['name']).items()]
                    strresult = "\n".join(listresult)
                    res += strresult + '\n'

        return res

    def _sort_results_by_value_range(self, results: list, start_func: str, sink_code: str, function_body_chain: str) -> list:
        if len(results) < 2:
            return results
        
        try:
            functions_info = []
            for i, item in enumerate(results):
                func_content = "\n".join(item['source'])
                functions_info.append(f"Function {i+1}:\nName: {item['name']}\nFile: {item['filename']}\nContent:\n{func_content}\n")
            
            functions_text = "\n---\n".join(functions_info)
            
            prompt = f"""
You are a code security expert. Please analyze the provided functions and rank them based on their relevance to the security vulnerability context.

Context information:
1. Start Function: {start_func or 'Not specified'}
2. Vulnerability Code (Sink): {sink_code or 'Not specified'}
3. Function Call Chain: {function_body_chain if function_body_chain != '0' else 'Not specified'}

Functions to analyze:
{functions_text}

Please perform the following analysis:

1. Analyze the vulnerability context to understand:
- The starting point of the data flow
- The vulnerable code pattern and its variable value ranges
- The call chain that leads to the vulnerability

2. For each function, evaluate its relevance based on:
- Proximity to the start function in the call chain
- Similarity of processed data types and value ranges to the sink code
- Likelihood of being part of the actual vulnerability data flow
- Position in the function call chain context

3. Rank the functions from most relevant to least relevant based on:
- Data flow continuity from start function to sink
- Value range compatibility with the sink code
- Positional relevance in the provided function call chain
- Semantic similarity to the vulnerability context

Return ONLY a JSON object with the following format:
```json
{{
"analysis": "Brief analysis of how each function relates to the vulnerability context",
"ranking": [3, 1, 2]
}}
```
Where "ranking" is an array of function numbers in order of relevance (e.g., [3, 1, 2] for function 3 most relevant, then 1, then 2).
Do not include any other text outside the JSON object.
    """

            llm = LLM("gpt-4.1-mini")
            messages = [{"role": "system", "content": prompt}]
            response = llm.action(messages=messages)
            
            
            response = response.replace("```json", "").replace("```", "").strip()
            ranking = None
            
            try:
                result = json.loads(response)
                ranking = result.get("ranking", [])
            except json.JSONDecodeError:
                try:
                    json_pattern = r'\{(?:[^{}]|(?R))*\}' 
                    matches = re.findall(json_pattern, response, re.DOTALL)
                    
                    for match in matches:
                        try:
                            result = json.loads(match)
                            if "ranking" in result:
                                ranking = result.get("ranking", [])
                                break
                        except json.JSONDecodeError:
                            continue
                except Exception:
                    pass
            
            if ranking is not None:
                try:
                    ranked_indices = []
                    for func_num in ranking:
                        idx = int(func_num) - 1 
                        if 0 <= idx < len(results):
                            ranked_indices.append(idx)
                    
                    remaining_indices = [i for i in range(len(results)) if i not in ranked_indices]
                    ranked_indices.extend(remaining_indices)
                    
                    sorted_results = [results[i] for i in ranked_indices]
                    return sorted_results
                    
                except (ValueError, TypeError) as e:
                    print(f"[WARNING] Error processing ranking data: {e}")
            
            print("[WARNING] Failed to extract valid ranking from LLM response")
            
            return results
            
        except Exception as e:
            print(f"[WARNING] Failed to sort functions by context relevance: {e}")
            return results
    
    
if __name__ == "__main__":
    browser = CodeBrowser("projects/gawk")
    browser.index_project() # init

# Initialization: input the project directory
# Usage: input a name and type, returns the function body
# Output: all matching results
# Current limitation: 
#   if multiple macros are defined using #ifdef, the browser cannot determine which one is the correct source code
#   There may also be issues with inherited classes
# Possible improvement: 
#   add the current filename and prioritize outputting content from the current file

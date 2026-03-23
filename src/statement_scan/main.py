import glob
import json
import subprocess
import os
import csv
from bisect import bisect_right
import re
import argparse
import shutil

import openai
openai.base_url = ""
openai.default_headers = {"x-foo": "true"}
openai.api_key = ""
MODEL = ""


PRUNE = '''
Role
You are an expert in C++ program analysis.

Task
Based on the given function call chain and vulnerability description, determine whether the vulnerability is guaranteed not to occur.

Input Information
- Vulnerability description: ${vul_des}$
- Calling relationship in the vulnerability context: ${funcname}$
- Detailed implementation in the vulnerability context: ${funcbody}$

Steps
1. From the type of vulnerability described, identify five specific conditions under which the vulnerability is guaranteed not to occur (e.g., for an integer overflow vulnerabil
2. Check whether the given execution path matches any of these conditions.
3. Re-check and verify your reasoning to ensure the reliability of your conclusion.

Output
- If the vulnerability is guaranteed not to occur on this path: output @@@no vulnerability@@@.
- If the vulnerability may still occur: output @@@may vulnerability@@@.

Notes
- The analysis must be based strictly on program semantics and logical reasoning.
- Avoid overlooking potential conditions.
- Do not misclassify situations where the vulnerability could still be triggered.
'''




PROJECT_NAME = "your_project"
DEFAULT_SRC = "/path/to/your_project/src" 
DEFAULT_DST = "/path/to/your_project/output" 


COMMON_OPTS="-- -I. -I./src -I./include $LANG_STD" #sqilte  libpilst v8
# COMMON_OPTS="-- -I. -I./src -I./include $(pkg-config --cflags libxml-2.0) -std=gnu89" #libxml2

# Query patterns for integer overflow detection
RULES = [
    'match unaryOperator(hasOperatorName("-"), hasUnaryOperand(allOf(hasType(isInteger()), unless(integerLiteral()), unless(hasType(type(hasSize(8)))), unless(hasType(hasCanonicalType(asString("long long")))), unless(hasType(hasCanonicalType(asString("unsigned long long"))))))).bind("root")',
    'match unaryOperator(hasOperatorName("++"), hasUnaryOperand(allOf(hasType(isInteger()), unless(integerLiteral()), unless(hasType(type(hasSize(8)))), unless(hasType(hasCanonicalType(asString("long long")))), unless(hasType(hasCanonicalType(asString("unsigned long long"))))))).bind("root")',
    'match unaryOperator(hasOperatorName("--"), hasUnaryOperand(allOf(hasType(isInteger()), unless(integerLiteral()), unless(hasType(type(hasSize(8)))),  unless(hasType(hasCanonicalType(asString("long long")))), unless(hasType(hasCanonicalType(asString("unsigned long long"))))))).bind("root")',
    'match binaryOperator(hasOperatorName("+"), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
    'match binaryOperator(hasOperatorName("+="), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
    'match binaryOperator(hasOperatorName("*"), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
    'match binaryOperator(hasOperatorName("*="), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
    'match binaryOperator(hasOperatorName("-"), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
    'match binaryOperator(hasOperatorName("-="), unless(hasLHS(integerLiteral())), unless(hasRHS(integerLiteral())), unless(hasLHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), unless(hasRHS(hasType(anyOf(asString("long long"), asString("unsigned long long"), asString("int64_t"), asString("uint64_t"))))), hasLHS(hasType(isInteger())), hasRHS(hasType(isInteger()))).bind("add")',
]


def unique(input_file: str) -> None:
    """
    Remove duplicate entries from clang-query output file and overwrite it.
    
    Args:
        input_file: Path to the file to deduplicate
    """
    # Read input file
    with open(input_file, "r", encoding="utf-8") as f:
        text = f.read()
    
    lines = text.splitlines()
    output = []
    current_block = []
    seen_keys = set()
    in_block = False
    i = 0

    while i < len(lines):
        line = lines[i]

        # Detect Match block start
        if re.match(r'^Match #\d+:', line):
            # Output previous block if exists
            if current_block:
                output.extend(current_block)
                current_block = []
                seen_keys.clear()
            
            in_block = True
            current_block.append(line)
            i += 1
            continue

        # Match path line (e.g. /path/to/file:123:45:)
        m = re.match(r'^(.*?):(\d+:\d+):', line)
        if in_block and m:
            key = m.group(0)
            
            # Skip if duplicate line number
            if key in seen_keys:
                # Skip path line + next code line + next arrow line
                i += 3
                continue
            
            seen_keys.add(key)

            # Add this line and next two lines (if exist)
            current_block.append(lines[i])
            if i + 1 < len(lines):
                current_block.append(lines[i + 1])
            if i + 2 < len(lines):
                current_block.append(lines[i + 2])
            i += 3
            continue

        # Regular line
        if in_block:
            current_block.append(line)
        else:
            output.append(line)
        i += 1

    # Output last block
    if current_block:
        output.extend(current_block)

    # Write back to the same file (overwrite)
    result = "\n".join(output)
    with open(input_file, "w", encoding="utf-8") as f:
        f.write(result)

def txt2json(input_txt, output_json, index_csv):
    """
    Convert clang-query output to JSON format
    1. Load function index from CSV
    2. Parse txt file and output to JSON
    """
    
    def load_function_index(csv_path):
        """
        Load function index from CSV file.
        Returns:
        {
            'file1.c': [(start, end, func_name), ...],  # sorted by start
            'file2.c': [...]
        }
        """
        file_index = {}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['type'] != 'function':
                    continue  # Only process functions

                filename = row['filename']
                start = int(row['start_line'])
                end = int(row['end_line'])
                func_name = row['name']

                if filename not in file_index:
                    file_index[filename] = []
                file_index[filename].append((start, end, func_name))

        # Sort function list by start_line for each file (for binary search)
        for key in file_index:
            file_index[key].sort(key=lambda x: x[0])

        return file_index

    def find_function_for_line(file_func_list, line_num):
        """
        Find function info for given line number.
        
        Args:
            file_func_list: List of (start, end, func_name) tuples
            line_num: Line number to search
            
        Returns:
            Tuple of (func_name, start_line, end_line) or None if not found
        """
        if not file_func_list:
            return None

        # Build start_line list for bisect
        starts = [item[0] for item in file_func_list]

        # Find the largest start <= line_num
        pos = bisect_right(starts, line_num) - 1

        if pos >= 0:
            start, end, func_name = file_func_list[pos]
            if start <= line_num <= end:
                return (func_name, start, end)

        return None

    # Load function index
    func_index = load_function_index(index_csv)
    
    # Read input file
    with open(input_txt, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Split by Match blocks
    match_blocks = re.split(r'\n\s*Match #\d+:\s*\n', content)[1:]
    results = []

    for block in match_blocks:
        # Find all note lines
        all_notes = re.findall(
            r'^(.*?):(\d+):\d+: note: "([^"]+)" binds here',
            block,
            re.MULTILINE
        )
        for file_path, line_str, tag in all_notes:
            line_num = int(line_str)

            # Find function info from index
            func_info = find_function_for_line(
                func_index.get(file_path, []), 
                line_num
            )
            
            # Skip if function not found
            if func_info is None:
                continue
            
            func_name, start_line, end_line = func_info

            # Read code line from source file
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as src_f:
                    source_lines = src_f.readlines()
                code_line = source_lines[line_num - 1].strip() if 1 <= line_num <= len(source_lines) else "<line not found>"
            except Exception:
                code_line = "<source file not accessible>"

            results.append({
                "function": func_name,
                "vulnerable_code": code_line,
                "file": file_path,
                "line_number": line_num,
                "start_line": start_line,
                "end_line": end_line
            })

    # Save results to JSON
    with open(output_json, 'w', encoding='utf-8') as out:
        json.dump(results, out, indent=2, ensure_ascii=False)


import re

KEYWORDS = ['sizeof', 'char', 'hash','INT64_MIN', 'MIN', 'INT64_MAX']
def syntaxfilter(output_json: str, rule_index: int) -> None:
    """
    Filter JSON results based on rule_index (1-9).
    Remove entries where 'vulnerable_code':
    1. Does not contain the corresponding operator (+, -, *)
    2. Contains any keyword from KEYWORDS list
    3. Contains 'for' with loop bounds (>=, >, <=, <)
    """
    
    # Map rule index to target operator
    operator_map = {
        1: '-', 2: '+', 3: '-',
        4: '+', 5: '+', 6: '*',
        7: '*', 8: '-', 9: '-'
    }
    
    target_operator = operator_map.get(rule_index)
    if not target_operator:
        return
    
    # Read JSON file
    try:
        with open(output_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return
    
    # Filter data
    filtered_data = []
    for record in data:
        code = record.get("vulnerable_code", "")
        # Check 1: Must contain target operator
        if target_operator not in code:
            continue
        # Check 2: Must not contain keywords
        if any(kw in code for kw in KEYWORDS):
            continue
        # Check 3: Must not be a for loop with bounds
        if 'for' in code and re.search(r'[<>=]=?', code):
            continue
        filtered_data.append(record)
    
    # Save back to file
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=2, ensure_ascii=False)

from tqdm import tqdm
import pandas as pd

def semanticfilter(csvfile):
    def get_func(file_path, startline, endline):
        with open(file_path, 'r', encoding='utf-8') as f:
            return ''.join(f.readlines()[startline-1:endline])
    
    def action(messages, temperature: float = 0.0):
        """Send prompt to OpenAI and return response."""
        response = openai.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=temperature
        )
        return response.choices[0].message.content

    # Read CSV file
    df = pd.read_csv(csvfile)
    
    # Add LLM column if it doesn't exist
    if 'LLM' not in df.columns:
        df['LLM'] = None
    
    # Add progress bar
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing vulnerabilities"):
        vulnerable_code = row.get('vulnerable_code', '')
        funcname = row.get('function', '')
        file_path = row.get('file', '')
        startline = row.get('start_line')
        endline = row.get('end_line')
        
        # Get function body
        funcbody = get_func(file_path, int(startline), int(endline))
        
        # Build prompt
        base_content = f"Please determine if there is an integer overflow vulnerability at {vulnerable_code}"
        vul_des = base_content + '\n' + f'Function call:\n{funcname}\n' + \
                  f'Function detailed context:\n{funcbody}\n'
        
        temp_PRUNE = PRUNE.format(
            funcname=funcname,
            funcbody=funcbody,
            vul_des=vul_des
        )
        
        message = [{"role": "system", "content": temp_PRUNE}]
        
        response = action(messages=message)
        
        # Check if vulnerability is confirmed
        if "@@@no vulnerability@@@" in response.lower():
            df.at[idx, 'LLM'] = 0
        else:
            df.at[idx, 'LLM'] = 1
        
        # Write to CSV after each row
        df.to_csv(csvfile, index=False)
    
    return df
    

def run_clang_queries(source_file: str, output_file: str, index_path: str) -> None:
    """
    Run clang-query to detect integer overflow patterns in C/C++ code.
    
    Args:
        source_file: Path to source file to analyze
        output_dir: Directory to save output files
    """
    source_file = os.path.abspath(source_file)
    output_file = os.path.abspath(output_file)

    source_dir = os.path.dirname(source_file)
    output_dir = os.path.dirname(output_file)
    source_index_csv = index_path


    tmp_dir = os.path.join(output_dir, 'tmp') 
    os.makedirs(tmp_dir, exist_ok=True)  # Create the directory

    # Run each query
    for i, query in enumerate(RULES, start=1):
        output_txt = f"{tmp_dir}/{i}.txt"
        output_json = f"{tmp_dir}/{i}.json"
        if source_file.endswith('.c'):
            current_std = "-std=gnu89"
        elif source_file.endswith(('.cc', '.cpp', '.h')):
            current_std = "-std=c++11"
        else:
            current_std = "-std=gnu89" 

        file_specific_opts = f"{COMMON_OPTS} {current_std}"
        cmd = f"clang-query -c '{query}' {source_file} {file_specific_opts}"
        
        # print(f"Running query {i}...")
        
        try:
            # Copy all existing environment variables and set TERM='dumb'
            # TERM='dumb' forces clang-query to output plain text without color codes
            # This makes the output files easier to parse
            with open(output_txt, 'w') as f:
                subprocess.run(
                    cmd,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.DEVNULL,
                    env={**os.environ, 'TERM': 'dumb'}
                )

            unique(output_txt)
            # print(output_txt)
            txt2json(output_txt, output_json, source_index_csv) # unique + txt2json
            
            syntaxfilter(output_json,i)
            # semanticfilter(output_json)

        except Exception as e:
            print(f"Error running query {i}: {e}")
        
    merge_json_files(tmp_dir, output_file)
    shutil.rmtree(tmp_dir)
    
    return output_file


def merge_json_files(input_dir='.', output_file='merged_vulnerabilities.json'):
    """
    9 => 1
    Merge all JSON files in a directory, remove duplicates, and save to output file.
    
    Args:
        input_dir: Directory containing JSON files
        output_file: Output file path for merged results
    """
    
    # Find all JSON files in the directory
    json_files = glob.glob(f"{input_dir}/*.json")
    
    if not json_files:
        print(f"No JSON files found in {input_dir}")
        return
    
    seen = set()
    records = []
    
    # Process each JSON file
    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Normalize data to list format
                items = [data] if isinstance(data, dict) else data if isinstance(data, list) else []
                
                # Filter and deduplicate records
                for item in items:
                    # Check required fields
                    required_fields = ("function", "vulnerable_code", "file", "line_number")
                    if not all(field in item for field in required_fields):
                        continue
                    
                    # Create unique key for deduplication
                    key = (item["file"], item["line_number"])
                    if key not in seen:
                        seen.add(key)
                        records.append(item)
                        
        except json.JSONDecodeError as e:
            print(f"Error parsing {file_path}: {e}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    # Sort by file and line number
    records.sort(key=lambda x: (x["file"], x["line_number"]))
    
    # Write merged results
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    
    print(f"Merge complete: {len(records)} unique records saved to {output_file}")


def json2csv(output_json, output_csv):
    """
    Convert JSON file to CSV format with an ID column.
    
    Args:
        output_json: Path to input JSON file
        output_csv: Path to output CSV file
    """
    # Read JSON file
    with open(output_json, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Write to CSV
    with open(output_csv, 'w', encoding='utf-8', newline='') as f:
        # Define CSV columns
        fieldnames = ['id', 'function', 'vulnerable_code', 'file', 'line_number', 'start_line', 'end_line']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        # Write header
        writer.writeheader()
        
        # Write data with ID
        for idx, item in enumerate(data, start=1):
            row = {
                'id': idx,
                'function': item.get('function', ''),
                'vulnerable_code': item.get('vulnerable_code', ''),
                'file': item.get('file', ''),
                'line_number': item.get('line_number', ''),
                'start_line': item.get('start_line', ''),
                'end_line': item.get('end_line', '')
            }
            writer.writerow(row)
    
    print(f"CSV file created: {output_csv} ({len(data)} records)")


import sys

if __name__ == "__main__": 
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default=DEFAULT_SRC, help="source_dir")
    parser.add_argument("--dst", default=DEFAULT_DST, help="output_dir")  # output the final json
    args = parser.parse_args()
    
    # Create tmp directory
    tmp_dir = os.path.join(args.dst, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)
    
    # Step1: create index.csv
    print("Step 1: Creating index.csv...")
    code_browser_script = os.path.abspath("code_browser.py")
    cmd = [sys.executable, code_browser_script, args.src]
    subprocess.run(cmd, check=True)
    
    # Step2: Scan all C/C++ files
    print("Step 2: Scanning source files...")
    global_index_csv = os.path.join(args.src, 'index.csv')
    for root, dirs, files in os.walk(args.src):
        for file in files:
            if file.endswith(('.c', '.cpp', '.cc', '.h')):
                source_file = os.path.join(root, file)
                
                # Get relative path from src and replace separators
                rel_path = os.path.relpath(source_file, args.src)
                filename = rel_path.replace(os.sep, '_')
                
                # Create output file
                output_file = os.path.join(tmp_dir, f"{filename}.json")
                
                print(f"Processing {source_file}...")
                run_clang_queries(source_file, output_file, global_index_csv)

    # Step3: Merge all results
    print("Step 3: Merging results...")
    abs_src = os.path.abspath(args.src)
    project_name = os.path.basename(abs_src)
    if project_name == 'src':
        project_name = os.path.basename(os.path.dirname(abs_src))
    output_json = os.path.join(args.dst, f"{project_name}.json")
    output_csv = os.path.join(args.dst, f"{project_name}.csv")
    merge_json_files(tmp_dir, output_json)

    json2csv(output_json,output_csv)
    semanticfilter(output_csv)
    
    # Clean up tmp directory (optional)
    # shutil.rmtree(tmp_dir)
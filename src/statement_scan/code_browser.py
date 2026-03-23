from pathlib import Path
from tree_sitter import Language, Parser, Node
import tree_sitter_cpp as tscpp
import csv
import bisect
import os
from typing import List, Dict, Generator
import sys

cur_path = Path(__file__).parent

class CodeBrowser:
    # name,type,filename,start_line,end_line
    def __init__(self, project_path: str):

        self.project_path: Path = Path(project_path) # project path
        self.source_files: List[Path] = self.collect_source_files() # source files
        self.lang: Language = Language(tscpp.language()) # language
        self.parser: Parser = Parser(self.lang) # tree_sitter parser
        self.definitions: List[dict] = [] # result of definitions
        self.output_csv: Path = self.project_path / 'index.csv'
        self.INTERESTED_NODES = { 
            'preproc_def': 'macro', 
            'preproc_function_def': 'macro', 
            'struct_specifier': 'struct', 
            'function_definition': 'function', 
            'class_specifier': 'class', 
            'type_definition': 'typedef', 
            'comment': 'comment' 
        }
        if not os.path.exists(self.output_csv):
            self.index_project()

    def collect_source_files(self) -> List[Path]:
        '''collect all source files'''
        suffixs = ['.h', '.hpp', '.cpp', '.cc', '.cxx', '.c']
        return [file for file in self.project_path.rglob('*') if file.suffix in suffixs]
    
    def extract_definitions_from_file(self, filename: Path) -> List[dict]:
        '''extract definitions from a file'''

        file_bytes = filename.read_bytes()
        source_code = file_bytes.decode('utf-8', errors='replace')  
        source_lines = source_code.splitlines()  
        
        tree = self.parser.parse(file_bytes)
        root = tree.root_node

        definitions = []
        comments = []
        for node in self._traverse_tree(root):
            if node.type in self.INTERESTED_NODES:
                elem_info = self._extract_node_info(node, source_code, source_lines, str(filename))
                if elem_info: 
                    if elem_info['elem_name'] == 'comment':
                        comments.append(elem_info)
                    else:
                        definitions.append(elem_info)

        # Associate comments with following definitions
        for i in range(len(definitions)):
            definition = definitions[i]
            for j in range(len(comments)):
                comment = comments[j]
                if (comment['end_row'] <= definition['start_row'] 
                    and definition['start_row'] - comment['end_row'] <= 2
                ):
                    definitions[i]['start_row'] = comment['start_row']
                    comments.pop(j)
                    break

        return definitions
    
    def _traverse_tree(self, node: Node) -> Generator[Node, None, None]:
        yield node  
        for child in node.children:
            yield from self._traverse_tree(child)

    def _extract_node_info(self, node: Node, source_code: str, source_lines: List[str], filename: str) -> Dict:
        node_type = node.type
        elem_category = self.INTERESTED_NODES[node_type]  
        start_row = node.start_point[0] + 1 
        end_row = node.end_point[0] + 1
        start_col = node.start_point[1] + 1  
        end_col = node.end_point[1] + 1

        if end_col == 1 and node_type != 'comment' and end_row > start_row:
            end_row -= 1

        # Extract element name based on node type
        elem_name = self._get_node_name(node)

        if elem_name == None:
            return None

        # Extract full code snippet
        code_snippet = source_code[node.start_byte:node.end_byte].strip()

        # Build element info dictionary
        return {
            'filename': filename,
            'elem_category': elem_category,
            'elem_name': elem_name.split()[-1] if elem_name.split() else 'anonymous',
            'node_type': node_type,
            'start_row': start_row,
            'end_row': end_row,
            'start_col': start_col,
            'end_col': end_col,
            'code_snippet': code_snippet,
            'line_count': end_row - start_row + 1
        }

    def _get_node_name(self, node: Node) -> str:
        """
        Extract name based on node type using field names or child traversal.
        """
        node_type = node.type

        # 1. Macro definitions: Name is in the "name" field
        if node_type in ['preproc_def', 'preproc_function_def']:
            macro_name_node = node.child_by_field_name('name')
            if macro_name_node:
                return macro_name_node.text.decode('utf-8')
            return None

        # 2. Structs: Name is a "type_identifier" node
        elif node_type == 'struct_specifier':
            def find_type_identifier(current_node):
                if current_node.type == 'type_identifier':
                    return current_node
                for child in current_node.children:
                    result = find_type_identifier(child)
                    if result:
                        return result
                return None
            
            type_id_node = find_type_identifier(node)
            if type_id_node:
                return type_id_node.text.decode('utf-8')
            return None  # Anonymous struct

        # 3. Classes: Name is a "type_identifier" node
        elif node_type == 'class_specifier':
            def find_type_identifier(current_node):
                if current_node.type == 'type_identifier':
                    return current_node
                for child in current_node.children:
                    result = find_type_identifier(child)
                    if result:
                        return result
                return None
                
            type_id_node = find_type_identifier(node)
            if type_id_node:
                return type_id_node.text.decode('utf-8')
            return None

        # 4. Function definitions: Name is in function_declarator -> identifier
        elif node_type == 'function_definition':
            def find_function_declarator(current_node):
                if current_node.type == 'function_declarator':
                    return current_node
                for child in current_node.children:
                    result = find_function_declarator(child)
                    if result:
                        return result
                return None
                
            def find_identifier(current_node):
                if current_node.type in ['identifier', 'qualified_identifier']:
                    return current_node
                for child in current_node.children:
                    result = find_identifier(child)
                    if result:
                        return result
                return None

            func_declarator = find_function_declarator(node)
            if func_declarator:
                identifier_node = find_identifier(func_declarator)
                if identifier_node:
                    return identifier_node.text.decode('utf-8')
            return None  # Anonymous function

        # 5. Declarations: Check if it's a function declaration
        elif node_type == 'declaration':
            def find_function_declarator(current_node):
                if current_node.type == 'function_declarator':
                    return current_node
                for child in current_node.children:
                    result = find_function_declarator(child)
                    if result:
                        return result
                return None
                
            def find_identifier(current_node):
                if current_node.type == 'identifier':
                    return current_node
                for child in current_node.children:
                    result = find_identifier(child)
                    if result:
                        return result
                return None

            func_declarator = find_function_declarator(node)
            if func_declarator:
                identifier_node = find_identifier(func_declarator)
                if identifier_node:
                    return identifier_node.text.decode('utf-8')
            return None  # Non-function declaration

        elif node_type == 'type_definition':
            text = node.text.decode('utf-8')[:-1]
            def get_type_name(text):
                # Search backwards for the identifier
                i = len(text) - 1
                while i >= 0 and (text[i].isalpha() or text[i].isdigit() or text[i] == '_'):
                    i -= 1
                return text[i+1:].strip()
            return get_type_name(text)

        elif node_type == 'comment':
            return 'comment'
            
        return None
        
    def index_project(self):
        # Parse content
        for file in self.source_files:
            definitions = self.extract_definitions_from_file(file)
            for definition in definitions:
                self.definitions.append({
                    'name': definition['elem_name'],
                    'type': self.INTERESTED_NODES[definition['node_type']],
                    'file': str(file.resolve()),
                    'start_line': definition['start_row'],
                    'end_line': definition['end_row'],
                })
        self.write2csv()
    
    def write2csv(self):
        with open(self.output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'name', 'type', 'filename', 'start_line', 'end_line'])
            # Sort definitions by name for binary search compatibility
            self.definitions.sort(key=lambda x: x['name'])
            for i, definition in enumerate(self.definitions, 1):
                writer.writerow([
                    f"{i}",
                    definition['name'],
                    definition['type'],
                    definition['file'],
                    definition['start_line'],
                    definition['end_line'],
                ])

    def get_body(self, name: str, type: str = None, cflag: int = 0) -> str:
        """
        Look up definitions with the specified name from the index and return the source snippet.
        """
        results = []
        with open(self.output_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            names = [row['name'] for row in rows]

            left = bisect.bisect_left(names, name)
            right = bisect.bisect_right(names, name)

            count = 0
            for i in range(left, right):
                if count >= 2:  # Limit to 2 results
                    break
                    
                row = rows[i]
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
                        count += 1
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        res = "\n========== Begin of tool results ==========\n"
        seen = set()
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:
                break
                
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

                res += "\n"
                output_count += 1

        actual_count = min(len(seen), 2)
        res += f"There are {actual_count} corresponding results for {name}.\n"
        res += "========== End of tool results ==========\n"

        return res

    def get_body_to_call_function(self, name: str, call_function: str, type: str = None, cflag: int = 0) -> str:
        """
        Look up definitions and return snippet. 
        Truncate at the line containing call_function if found.
        """
        results = []

        with open(self.output_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            names = [row['name'] for row in rows]

            left = bisect.bisect_left(names, name)
            right = bisect.bisect_right(names, name)

            count = 0
            for i in range(left, right):
                if count >= 2:
                    break
                    
                row = rows[i]
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
                        
                        truncated_snippet = []
                        call_line_index = -1
                        
                        for idx, line in enumerate(snippet):
                            stripped_line = line.rstrip('\n')
                            truncated_snippet.append(stripped_line)
                            # Check for function call, skipping comment lines
                            if (call_function and line and call_function in line and 
                                not line.lstrip().startswith('**') 
                                and not line.lstrip().startswith('//')
                                and not line.lstrip().startswith('/*')):
                                call_line_index = idx
                                break
                        
                        if call_line_index != -1:
                            truncated_snippet = truncated_snippet[:call_line_index + 1]
                        
                        results.append({
                            'name': row['name'],
                            'type': row['type'],
                            'filename': filename,
                            'start_line': start_line,
                            'end_line': start_line + len(truncated_snippet) - 1 if truncated_snippet else start_line,
                            'source': truncated_snippet
                        })
                        count += 1
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        res = "\n========== Begin of tool results ==========\n"
        seen = set()
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:
                break
                
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

                res += "\n"
                output_count += 1

        actual_count = min(len(seen), 2)
        res += f"There are {actual_count} corresponding results for {name}.\n"
        res += "========== End of tool results ==========\n"

        return res

    def get_body_without_hint(self, name: str, type: str = None, cflag: int = 0) -> str:
        """
        Return the source snippet of the given name. Returns the name itself if no match is found.
        """
        results = []

        with open(self.output_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            names = [row['name'] for row in rows]

            left = bisect.bisect_left(names, name)
            right = bisect.bisect_right(names, name)

            candidate_rows = []
            if left < right and all(n == name for n in names[left:right]):
                candidate_rows = rows[left:right]
            else:
                candidate_rows = [row for row in rows if row['name'] == name]

            if not candidate_rows:
                return name

            count = 0
            for row in candidate_rows:
                if count >= 2:
                    break
                    
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
                        count += 1
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        if not results:
            return name

        res = ""
        seen = set()
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:
                break
                
            identifier = (item['name'], "\n".join(item['source']))
            if identifier not in seen:
                seen.add(identifier)
                for line_num, line_content in enumerate(item['source'], start=item['start_line']):
                    res += f"{line_num}: {line_content}\n"
                output_count += 1

        return res

    def print_ast_node(self, node, code, indent=0, max_depth=5, output_file=None):
        """
        Recursively prints AST nodes.
        """
        if indent > max_depth:
            return
            
        indent_str = '  ' * indent
        
        node_text = code[node.start_byte:node.end_byte].decode('utf8', errors='replace')
        node_text_truncated = (node_text[:50] + '...') if len(node_text) > 50 else node_text
        
        node_info = f"{indent_str}[{node.type}] (Lines: {node.start_point[0]+1}-{node.end_point[0]+1})\n"
        node_info += f"{indent_str}  Content: {node_text_truncated}\n"
        
        if output_file:
            output_file.write(node_info)
        else:
            print(node_info, end='')
        
        for child in node.children:
            self.print_ast_node(child, code, indent + 1, max_depth, output_file)

# Test script
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 code_browser.py <project_path>")
        sys.exit(1)

    project_path = sys.argv[1]

    if not Path(project_path).exists():
        print(f"Error: The path '{project_path}' does not exist.")
        sys.exit(1)

    browser = CodeBrowser(Path(project_path))
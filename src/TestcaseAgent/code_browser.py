from pathlib import Path
from tree_sitter import Language, Parser, Node
import tree_sitter_cpp as tscpp
import csv
import bisect
import os
from typing import List, Dict, Generator
from logger_config import logger

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
            logger.info(f'project index file not found, creating...')
            self.index_project()
            logger.info(f"Indexing project {self.project_path}")

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

        elem_name = self._get_node_name(node)

        if elem_name == None:
            return None


        code_snippet = source_code[node.start_byte:node.end_byte].strip()

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

        node_type = node.type

        if node_type in ['preproc_def', 'preproc_function_def']:
            macro_name_node = node.child_by_field_name('name')
            if macro_name_node:
                return macro_name_node.text.decode('utf-8')  
            return None

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
            return None  

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
            return None  # Anonymous function (e.g., lambda)

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
            return None  # Non-function declaration (e.g., int a;), filtered out
        elif node_type == 'type_definition':
            text = node.text.decode('utf-8')[:-1]
            def get_type_name(text):
                i = len(text) - 1
                while i >= 0 and (text[i].isalpha() or text[i].isdigit() or text[i] == '_'):
                    i -= 1
                return text[i+1:].strip()
            return get_type_name(text)
        elif node_type == 'comment':
            return 'comment'
        return None
        
    def index_project(self):
        if self.output_csv.exists():
            logger.info(f"{self.output_csv} already exists. Skipping indexing.")
            return
        # 解析content
        for file in self.source_files:
            definitions = self.extract_definitions_from_file(file)
            for definition in definitions:
                self.definitions.append({
                    'name': definition['elem_name'],
                    'type': self.INTERESTED_NODES[definition['node_type']],
                    'file': str(file.resolve()),
                    'start_line': definition['start_row'],
                    'end_line': definition['end_row'],
                    #'content': definition['code_snippet'],
                })
        self.write2csv()
        logger.info(f"Indexing complete. {len(self.definitions)} definitions extracted to {self.output_csv}")
    
    def write2csv(self):
        with open(self.output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'name', 'type', 'filename', 'start_line', 'end_line']) # 保持一致 `file` -> `filename``
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
    # reuse
    def get_body(self, name: str, type: str = None, cflag: int = 0) -> str:
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

            # Iterate over all rows with the same name, but limit to 2 results
            count = 0
            for i in range(left, right):
                if count >= 2:  # Limit to at most 2 results
                    break
                    
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
                        count += 1
                except Exception as e:
                    print(f"[ERROR] Failed to read {filename}: {e}")

        res = "\n========== Begin of tool results ==========\n"
        seen = set()
        # Output each result, but limit to 2 results
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:  # Limit to at most 2 results
                break
                
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

                res += "\n"
                output_count += 1

        # Output the number of results
        actual_count = min(len(seen), 2)
        res += f"There are {actual_count} corresponding results for {name}.\n"
        # Mark the end of scan results
        res += "========== End of tool results ==========\n"

        return res

    def get_body_to_call_function(self, name: str, call_function: str, type: str = None, cflag: int = 0) -> str:
        """
        Look up definitions with the specified name from the index and return the corresponding source code snippet.
        If it contains call_function, truncate at the line containing call_function.
        Otherwise, return the complete function body.
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

            # Iterate over all rows with the same name, but limit to 2 results
            count = 0
            for i in range(left, right):
                if count >= 2:  # Limit to at most 2 results
                    break
                    
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
                        
                        truncated_snippet = []
                        call_line_index = -1
                        
                        for idx, line in enumerate(snippet):
                            stripped_line = line.rstrip('\n')
                            truncated_snippet.append(stripped_line)
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
        # Output each result, but limit to 2 results
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:  # Limit to at most 2 results
                break
                
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

                res += "\n"
                output_count += 1

        # Output the number of results
        actual_count = min(len(seen), 2)
        res += f"There are {actual_count} corresponding results for {name}.\n"
        # Mark the end of scan results
        res += "========== End of tool results ==========\n"

        return res

    # reuse
    def get_body_without_hint(self, name: str, type: str = None, cflag: int = 0) -> str:
        """
        Look up the definition of the given name from the index and return its source snippet.
        If it is a function and `cflag` is set, also append information about its callers.
        If no match is found, return the name itself.
        """
        results = []

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

            # Process matched rows, but limit to 2 results
            count = 0
            for row in candidate_rows:
                if count >= 2:  # Limit to at most 2 results
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

        # If still no results, return the name itself
        if not results:
            return name

        res = ""
        seen = set()
        # Output each result, but limit to 2 results
        output_count = 0
        for i, item in enumerate(results):
            if output_count >= 2:  # Limit to at most 2 results
                break
                
            # Use name and source as a unique identifier to avoid duplicates
            identifier = (item['name'], "\n".join(item['source']))
            if identifier not in seen:
                seen.add(identifier)
                for line_num, line_content in enumerate(item['source'], start=item['start_line']):
                    res += f"{line_num}: {line_content}\n"
                output_count += 1

        return res

    def print_ast_node(self, node, code, indent=0, max_depth=5, output_file=None):
        if indent > max_depth:
            return
            
        # Generate indentation string
        indent_str = '  ' * indent
        
        # Get node text (truncated)
        node_text = code[node.start_byte:node.end_byte].decode('utf8', errors='replace')
        node_text_truncated = (node_text[:50] + '...') if len(node_text) > 50 else node_text
        
        # Construct output string
        node_info = f"{indent_str}[{node.type}] (lines: {node.start_point[0]+1}-{node.end_point[0]+1})\n"
        node_info += f"{indent_str}  Content: {node_text_truncated}\n"
        
        # Output to file or console
        if output_file:
            output_file.write(node_info)
        else:
            print(node_info, end='')
        
        # Recursively print child nodes
        for child in node.children:
            self.print_ast_node(child, code, indent + 1, max_depth, output_file)

    def print_ast_from_file(self, file_path, max_depth=5, output_path="./output.txt"):
        try:
            with open(file_path, 'rb') as f:
                code = f.read()
            
            # Parse code to generate syntax tree
            tree = self.parser.parse(code)
            root_node = tree.root_node
            
            # Redirect output to file
            with open(output_path, 'w', encoding='utf-8') as output_file:
                output_file.write(f"===== AST Tree (max depth: {max_depth}) =====\n")
                self.print_ast_node(root_node, code, max_depth=max_depth, output_file=output_file)
                
            print(f"AST structure saved to {output_path}")
            
        except Exception as e:
            print(f"Error processing file: {e}")
        

# Write a test
if __name__ == "__main__":

    project_path = "/home/xxx/CProjects/v8-workdir/v8/src"

    browser = CodeBrowser(Path(project_path))
    # browser.print_ast_from_file(Path('/home/xxx/CProjects/libxml2/include/libxml/parser.h'))
    # Generate index.csv file
    # browser.index_project()
    # print(browser.get_body("jsonbPayloadSize"))
    # print(browser.get_body_to_call_function("jsonbPayloadSize", "jsonbPayloadSize"))
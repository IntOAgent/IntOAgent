import subprocess
from _codeql.QL import FUNCCALL,FUNCFLOW, MACROCALL
import os
import shutil
import csv
import pandas as pd
import traceback
import _config
import importlib


class codeql:
    def __init__(self, project_path, compile="make", codeql_path="_codeql/data"):
        self.project_path = project_path
        self.compile = compile
        self.codeql_path = codeql_path

        importlib.reload(_config)
        project_name = _config.project_name

        # Ensure the base codeql_path and project subdirectory exist
        project_dir = os.path.join(self.codeql_path, "projects" , project_name)
        os.makedirs(project_dir, exist_ok=True)

        # CodeQL database path
        self.db = os.path.abspath(os.path.join(project_dir, f"{project_name}_db"))

        # CodeQL query files
        self.call_ql = os.path.join(project_dir, "funccall.ql")
        self.flow_ql = os.path.join(project_dir, "funcflow.ql")
        self.macro_ql = os.path.join(project_dir, "macrocall.ql")
        self.funcline_ql = os.path.join(self.codeql_path, "funcline.ql")

        # CSV files for storing results
        self.pot_csv = os.path.join(project_dir, f"{project_name}_pot.csv")
        
        self.call_csv = os.path.join(project_dir, f"{project_name}_funccall.csv")
        self.flow_csv = os.path.join(project_dir, f"{project_name}_funcflow.csv")
        self.macro_csv = os.path.join(project_dir, f"{project_name}_macrocall.csv")
        self.funcline_csv = os.path.join(project_dir, f"{project_name}_funcline.csv")
        # Temporary BQRS file
        self.temp_bqrs = os.path.abspath(os.path.join(project_dir, f"{project_name}_temp.bqrs"))


    def create(self):
        """
        Create a CodeQL database for the project.
        Returns (success: bool, message: str).
        """
        try:
            if self.compile == "make":
                # Run `make clean` to ensure a fresh build
                subprocess.run(["make", "clean"], cwd=self.project_path)

            # Delete existing database directory if it exists
            if os.path.exists(self.db):
                shutil.rmtree(self.db)

            # Create the CodeQL database
            result = subprocess.run(
                ["codeql", "database", "create", "--language=cpp", "--command=make", self.db],
                cwd=self.project_path,
                text=True,
                capture_output=True
            )

            if result.returncode == 0:
                return True, "✅ CodeQL database has been created successfully."
            else:
                return False, f"❌ Failed to create CodeQL database.\nError details:\n{result.stderr}"

        except Exception as e:
            return False, f"❌ Unexpected error occurred: {e}"
    
    def scan(self, option=None):
        """
        Perform vulnerability scanning on the CodeQL database.

        Args:
            option: (Optional) Reserved for future customization of queries.

        Returns:
            tuple(bool, str): 
                - True + success message if scan succeeded.
                - False + error message (including stderr) if scan failed.
        """
        try:
            if option is None:
                result = subprocess.run(
                    [
                        "codeql", "database", "analyze",
                        self.db, "--format=csv",
                        f"--output={self.pot_csv}",
                        "--download", "codeql/cpp-queries"
                    ],
                    check=True, text=True, capture_output=True
                )
            else:
                # You can add custom option handling here
                result = subprocess.run(
                    ["codeql", "database", "analyze", self.db, option],
                    check=True, text=True, capture_output=True
                )

            return (True, "✅ CodeQL scan completed successfully.\n"
                        f"Output saved at: {self.pot_csv}")

        except subprocess.CalledProcessError as e:
            return (False, "❌ CodeQL scan failed.\n"
                        f"Error details:\n{e.stderr}")


    def getbody(self, file, startline, endline):
        '''
        Read and return the content from the specified start line to end line of a file
        '''
        try:
            with open(file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if startline < 1 or endline > len(lines) or startline > endline:
                raise ValueError("Invalid line range")
            
            selected_lines = lines[startline - 1:endline]
            content = ''.join(selected_lines).strip()
            return content
        except FileNotFoundError:
            print(f"Error: File '{file}' not found.")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def getcallfunc(self, funcname):
        print(f"[INFO] Starting getcallfunc for function: {funcname}")

        try:
            # Replace the placeholder in the system prompt with the function name
            self.FUNCCALL = FUNCCALL.format(funcname=funcname)
            with open(self.call_ql, "w", encoding="utf-8") as f:
                f.write(self.FUNCCALL)

            # Run the CodeQL query
            subprocess.run(
                [
                    "codeql", "query", "run",
                    f"{self.call_ql}",
                    f"--database={self.db}",
                    f"--output={self.temp_bqrs}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Decode the BQRS result into a CSV file
            subprocess.run(
                [
                    "codeql", "bqrs", "decode",
                    "--format=csv",
                    f"--output={self.call_csv}",
                    f"{self.temp_bqrs}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Remove the temporary BQRS file
            subprocess.run(["rm", f"{self.temp_bqrs}"], check=True)

            # Read the CSV file and collect all rows
            csv_data = []
            with open(self.call_csv, mode="r", newline="", encoding="utf-8") as csv_file:
                csv_reader = csv.reader(csv_file)
                next(csv_reader, None)  # Skip the header row if present
                for row in csv_reader:
                    if row:  # Ensure the row is not empty
                        csv_data.append(row)

            # Extract the first item of each row
            first_items = [row[0] for row in csv_data]
            # Deduplicate by converting to a set
            unique_items = set(first_items)
            # Convert the set back to a list
            result = list(unique_items)

            if not result:
                result = None

            print(f"[INFO] Finished getcallfunc for {funcname}, results: {len(result) if result else 0}")
            return result

        except Exception as e:
            print(f"[ERROR] getcallfunc failed for {funcname}: {e}")
            traceback.print_exc()
            return None
    
    def getcallmacro(self, funcname):
        print(f"[INFO] Starting getcallmacro for function: {funcname}")

        try:
            # Replace the placeholder in the system prompt with the function name
            self.MACROCALL = MACROCALL.format(funcname=funcname)
            with open(self.macro_ql, "w", encoding="utf-8") as f:
                f.write(self.MACROCALL)

            # Run the CodeQL query
            subprocess.run(
                [
                    "codeql", "query", "run",
                    f"{self.macro_ql}",
                    f"--database={self.db}",
                    f"--output={self.temp_bqrs}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Decode the BQRS result into a CSV file
            subprocess.run(
                [
                    "codeql", "bqrs", "decode",
                    "--format=csv",
                    f"--output={self.macro_csv}",
                    f"{self.temp_bqrs}"
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Remove the temporary BQRS file
            subprocess.run(["rm", f"{self.temp_bqrs}"], check=True)

            # Read the CSV file and collect all rows
            csv_data = []
            with open(self.macro_csv, mode="r", newline="", encoding="utf-8") as csv_file:
                csv_reader = csv.reader(csv_file)
                next(csv_reader, None)  # Skip the header row if it exists
                for row in csv_reader:
                    csv_data.append(row)

            # Extract the function bodies using the line ranges from the CSV
            result = [
                self.getbody(row[1], int(row[2]), int(row[3]))
                for row in csv_data
            ]

            if not result:
                result = None

            print(f"[INFO] Finished getcallmacro for {funcname}, results: {len(result) if result else 0}")
            return result

        except Exception as e:
            print(f"[ERROR] getcallmacro failed for {funcname}: {e}")
            traceback.print_exc()
            return None

    def getflow(self, funcname):
        # Replace the placeholder in the system prompt with the function name
        self.FUNCFLOW = FUNCFLOW.format(funcname=funcname)
        with open(self.flow_ql, 'w') as f:
            f.write(self.FUNCFLOW)

        # Run the CodeQL query
        subprocess.run([
            "codeql", "query", "run",
            f"{self.flow_ql}",
            f"--database={self.db}",
            f"--output={self.temp_bqrs}"
        ], check=True)

        # Decode the BQRS result into a CSV file
        subprocess.run([
            "codeql", "bqrs", "decode",
            "--format=csv",
            f"--output={self.flow_csv}",
            f"{self.temp_bqrs}"
        ], check=True)

        # Remove the temporary BQRS file
        subprocess.run(["rm", f"{self.temp_bqrs}"], check=True)

        # Read the CSV file and collect all rows
        csv_data = []
        with open(self.flow_csv, mode='r', newline='', encoding='utf-8') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader)  # Skip the header row
            for row in csv_reader:
                csv_data.append(row)

        # Return all extracted flow data
        return csv_data

    def autoconfigure(self):
        """
        Run the ./configure script with debug and AddressSanitizer enabled.
        Returns (success: bool, message: str).
        On failure, stderr output is included for debugging.
        """
        original_cwd = os.getcwd()
        try:
            os.chdir(self.project_path)

            env = os.environ.copy()
            env["CFLAGS"] = "-O0 -g -fsanitize=address"

            result = subprocess.run(
                ["./configure", "--enable-debug"],
                text=True,
                capture_output=True,
                env=env
            )

            if result.returncode == 0:
                return True, "✅ Configuration succeeded. You can now run 'make' to build the project."
            else:
                return False, f"❌ Configuration failed.\nError details:\n{result.stderr}"

        finally:
            os.chdir(original_cwd)
    
    def addHeader(self):
        file_path = self.pot_csv

        # Define the column names for the CSV exported by CodeQL
        columns = [
            "Name",         # Vulnerability type
            "Description",  # Vulnerability description
            "Severity",     # Severity level
            "Message",      # Alert message
            "Path",         # File path
            "Start line",   # Starting line
            "Start column", # Starting column
            "End line",     # Ending line
            "End column"    # Ending column
        ]
        
        # Attempt to read the first line to check if headers already exist
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                first_line = file.readline().strip()
            
            # If the first line matches the first column name, headers already exist
            if first_line.split(',')[0] == columns[0]:
                return f"❌ The file {file_path} already has headers. No changes made."
        except Exception as e:
            return f"❌ Error reading the file: {e}"
        
        # If no headers exist, read the CSV and add headers
        df = pd.read_csv(file_path, header=None, names=columns)
        df.to_csv(file_path, index=False)
        return f"✅ The new file has been saved in: {file_path}"


    def find_closest_function(self, file_path, start_line):
        # Read the CSV containing function line information
        df_1 = pd.read_csv(
            self.funcline_csv,
            header=0,
            names=['col0', 'Function Name', 'File', 'Line Number']
        )
        
        # Filter rows where 'File' column matches the given file_path
        filtered_df = df_1[df_1['File'] == str(file_path)].copy()
        
        # Convert 'Line Number' column to integer type
        filtered_df['Line Number'] = filtered_df['Line Number'].astype(int)
        
        # Calculate the difference between start_line and each function's line number
        filtered_df['Difference'] = start_line - filtered_df['Line Number']
        
        # Keep only rows where the difference is positive (functions before start_line)
        valid_df = filtered_df[filtered_df['Difference'] >= 0]

        # Find the function with the smallest positive difference (closest preceding function)
        if not valid_df.empty:
            closest_function = valid_df.loc[valid_df['Difference'].idxmin()]
            return closest_function['Function Name'], int(closest_function['Line Number'])
        else:
            # Return None if no preceding function is found
            return None, None

    def getfuncline(self):
        """
        Run the custom CodeQL query to extract function line information.

        Returns:
            tuple(bool, str): 
                - True + success message if query and decoding succeed.
                - False + error message (including stderr) if any step fails.
        """
        try:
            if os.path.exists(self.funcline_csv):
                return (True, f"⚠️ Skipped: function line CSV already exists.\n"
                            f"CSV path: {self.funcline_csv}")

            # Run the query
            result1 = subprocess.run(
                ["codeql", "query", "run",
                f"{self.funcline_ql}",
                f"--database={self.db}",
                f"--output={self.temp_bqrs}"],
                check=True, text=True, capture_output=True
            )

            # Decode the query results into CSV
            result2 = subprocess.run(
                ["codeql", "bqrs", "decode",
                "--format=csv",
                f"--output={self.funcline_csv}",
                f"{self.temp_bqrs}"],
                check=True, text=True, capture_output=True
            )

            # Clean up temporary file
            subprocess.run(
                ["rm", f"{self.temp_bqrs}"],
                check=True, text=True, capture_output=True
            )

            return (True, "✅ Function line extraction completed successfully.\n"
                        f"CSV output saved at: {self.funcline_csv}")

        except subprocess.CalledProcessError as e:
            return (False, "❌ Failed during function line extraction.\n"
                        f"Error details:\n{e.stderr}")


    def readCsvGenVulCode(self):
        """
        Read the vulnerability CSV file and append vulnerable code 
        and its surrounding context for each entry.

        Returns:
            tuple(bool, str):
                - True + success message if processing succeeds.
                - False + error message (including details) if any step fails.
        """
        csv_file_path = self.pot_csv
        base_directory = os.path.abspath(self.project_path)
        if _config.project_name == "tcl":
            base_directory = os.path.join(base_directory,"unix")

        try:
            # Load CSV into DataFrame
            df = pd.read_csv(csv_file_path)

            # Ensure required columns exist
            required_columns = ["Path", "Start line", "Start column", "End line", "End column"]
            for col in required_columns:
                if col not in df.columns:
                    return (False, f"❌ Missing required column in CSV: {col}")

            # Iterate over each vulnerability entry
            for index, row in df.iterrows():
                file_name = row["Path"]
                file_path = os.path.join(base_directory, file_name.lstrip('/'))

                try:
                    start_line = int(row["Start line"])
                    start_column = int(row["Start column"])
                    end_line = int(row["End line"])
                    end_column = int(row["End column"])
                except Exception as e:
                    return (False, f"❌ Invalid line/column values in row {index}: {e}")

                if not os.path.exists(file_path):
                    return (False, f"❌ File not found: {file_path}")

                try:
                    with open(file_path, 'r') as file:
                        lines = file.readlines()
                except Exception as e:
                    return (False, f"❌ Failed to read file {file_path}: {e}")

                if start_line < 1 or end_line > len(lines):
                    return (False, f"❌ Line numbers out of range in {file_path}: "
                                f"start={start_line}, end={end_line}, file length={len(lines)}")

                extracted_code = []
                code_content_string_list = []

                for line_num in range(start_line - 1, end_line):
                    line = lines[line_num]

                    if line_num == start_line - 1 and line_num == end_line - 1:
                        # Vulnerability on a single line
                        extracted_code.append(line[start_column - 1:end_column])
                        if line_num > 0:
                            code_content_string_list.append(lines[line_num - 1])
                        code_content_string_list.append(lines[line_num])
                        if line_num + 1 < len(lines):
                            code_content_string_list.append(lines[line_num + 1])
                    elif line_num == start_line - 1:
                        extracted_code.append(line[start_column - 1:])
                        code_content_string_list.append(line)
                    elif line_num == end_line - 1:
                        extracted_code.append(line[:end_column])
                        code_content_string_list.append(line)
                    else:
                        extracted_code.append(line)
                        code_content_string_list.append(line)

                # Format vulnerable code
                code_string = "'''" + "".join(extracted_code) + "'''"
                df.at[index, "Vul code"] = code_string

                # Format surrounding code context
                code_content_string = "'''" + "".join(code_content_string_list).replace('"', '') + "'''"
                df.at[index, "Code content"] = code_content_string

                # Add closest function information
                closest_function_name, closest_function_line = self.find_closest_function(file_path, start_line)
                if closest_function_name is None:
                    print(f"[ERROR] ❌ Vulnerability {index} Failed to find closest_function_name.")
                    continue
                df.at[index, "Closest Function Name"] = closest_function_name
                df.at[index, "Closest Function Line"] = int(closest_function_line)
                df["Closest Function Line"] = df["Closest Function Line"].astype("Int64")  # 支持缺失值

            # Save updated CSV
            df.to_csv(csv_file_path, index=False)
            print(True, f"✅ Vulnerability code and context successfully added.")
            return (f"Updated CSV saved at: {csv_file_path}")

        except Exception as e:
            return (False, f"❌ Unexpected error while processing CSV: {e}")


    def add_id_column_inplace(self):
        """
        Adds or overwrites an 'ID' column in the CSV file at self.pot_csv.
        - IDs start from 1.
        - 'ID' is always the first column.
        - The original file is overwritten in-place.
        """
        csv_path = self.pot_csv

        try:
            # 1. Load the CSV
            df = pd.read_csv(csv_path)

            if df.empty:
                return (False, f"❌ The CSV file '{csv_path}' is empty.")

            # 2. Always overwrite ID column and put it at the front
            df.drop(columns=["ID"], errors="ignore", inplace=True)
            df.insert(0, "ID", range(1, len(df) + 1))

            # 3. Save back to CSV
            df.to_csv(csv_path, index=False)

            return (True, f"✅ Successfully (re)generated ID column as the first column in '{csv_path}'.")
        
        except Exception as e:
            return (False, f"❌ Error while processing '{csv_path}': {e}")


    def run(self):
        importlib.reload(_config)

        print("[*] Adding header ...")
        print(c.addHeader())

        print("[*] Getting function lines ...")
        print(c.getfuncline())

        print("[*] Generating vulnerable code CSV ...")
        print(c.readCsvGenVulCode())

        print("[*] Adding ID column inplace ...")
        print(c.add_id_column_inplace())

        print("[✔] Done")
        return
if __name__ == "__main__":
    c = codeql(_config.project_path,"make")
    c.run()

'''
Auto Construct:
    # print(c.autoconfigure()) # update _configure: project_name, project_path
    # print(c.create()) 
    # print(c.scan())

Test:
    # print(c.getflow("concatwsFunc")) # getflow
    # print(c.getcallfunc("openDatabase")) # getcallfunc
'''
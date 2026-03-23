# IntOAgent — Setup & Analysis Guide

This document describes how to prepare the environment and run analysis for a target project using IntOAgent. IntOAgent uses TestcaseAgent at runtime, so ensure the TestcaseAgent environment is configured before running IntOAgent.

## 1. Prerequisites & system packages

Install system packages and tools required by the toolchain:

```bash
sudo apt update
sudo apt install python3.10
sudo apt install python3-pip
sudo apt install libclang1-14
sudo apt-get install python3-clang
```

Install Python packages:

```bash
pip3 install libclang
pip install clang
pip3 install pandas
pip3 install numpy
pip3 install openai
```
Install codeql:
```bash
# download codeql-linux64.zip using the following command
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.23.5/codeql-linux64.zip
# extract it
unzip codeql-linux64.zip -d /path/to/codeql
# add it to your PATH environment variable:
export PATH="/path/to/codeql:$PATH"
# check your codeql
codeql --help
```

## 2. Edit configuration files

You must complete values in two files: `llm.py` and `_config.py`. Example values to add:

- In `llm.py` :

```python
openai.base_url = "https://your-model-server.example.com"  # Base URL for the large model
openai.api_key  = "YOUR_API_KEY"                           # API key for the model
```

- In `_config.py` set project-specific paths and variables:
```python
project_name = "sqlite"   # The name of the target project
project_path = "/path/to/sqlite"   # Path to the target project to analyze
bin_path = "/path/to/sqlite/sqlite3"  # Executable/script that can be used to trigger behavior
vul_path = "_codeql/data/projects/sqlite/sqlite_pot.csv"  # Vulnerability CSV to be checked
testcase_agent_path = '/path/to/testcase_agent' # Path to your configured TestcaseAgent
```

Important: after editing `_config.py`, append 10 blank lines at the end of the file. This prevents intermediate run-time outputs from accidentally overwriting configuration content.

## 3. Create required directories

Create these directories :

```
../IntOAgent/chat_history
../IntOAgent/extra
../IntOAgent/output
../IntOAgent/poc
../IntOAgent/pytemp
../IntOAgent/reports
../IntOAgent/temp
../IntOAgent/_codeql/data/projects/{your_project_name}
```


## 4. Build the target project for analysis and create CodeQL database

Configure and build the project with debug flags and generate the compilation database used by CodeQL. 

An example with SQLite:
```bash
cd sqlite
CFLAGS="-O0 -g -fsanitize=signed-integer-overflow" ./configure --enable-debug  # Generate a Makefile with debug/report support
codeql database create --language=cpp --command=make ../IntOAgent/_codeql/data/projects/sqlite/sqlite_db
```
Then install CodeQL packs:

```bash
cd ../IntOAgent/_codeql/data
codeql pack install
```
## 5. Required Files

Make sure the following file exists (Manually create this file if it does not exist.):

```
../IntOAgent/_codeql/data/projects/{your_project_name}/{project_name}_pot.csv
```
A sample `sqlite_pot.csv` for testing is created.


## 6. Run the analysis

Once everything is set up, analyze your target project with:

```bash
python3 PathAgentRun.py
```
This will execute the IntOAgent analysis workflow and will call TestcaseAgent where configured.
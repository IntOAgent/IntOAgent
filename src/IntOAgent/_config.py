project_name = "sqlite"
project_path = "/path/to/sqlite"
bin_path = "/path/to/sqlite/sqlite3"
vul_path = "_codeql/data/projects/sqlite/sqlite_pot.csv"

type = "Normal"
PRUNEflag = 1
CODESLICEflag = 1
EARLYSTOPflag = 1
TRACEORDER = 'normal' # normal / random / none

# max output length
MAX_OUTPUT_LENGTH = 100
llm_model = 'gpt-4.1-mini'
# llm_model = "4o-mini"
max_iterations = 100
num_history = 25

testcase_agent_path = '/path/to/testcase_agent'  








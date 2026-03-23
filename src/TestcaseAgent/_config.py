
PROJECT_TYPE = 'c++'
COMPILE_CMD = 'gcc' if PROJECT_TYPE == 'c' else 'g++'
COMPILE_CONDITION = '-lsqlite3'
MAX_OUTPUT_LENGTH = 100

PROJECT_NAME = 'sqlite'
PROJECT_PATH = '/path/to/sqlite'
POC_PATH = './poc'
OUTPUT_PATH = './output'
BIN_PATH = "/path/to/sqlite/sqlite3"
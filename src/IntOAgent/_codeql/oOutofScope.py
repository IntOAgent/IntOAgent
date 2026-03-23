import os
import pandas as pd

oScope = [
    "Futile conditional",
    "Padding increased in 64-bit migration",
    "Time-of-check time-of-use filesystem race condition",
    "Logical expression could be simplified",
    "Suboptimal type definition",
    "Lock may not be released",
    "Mutex locked twice",
    "Error-prone name of loop variable",
    "Suspicious 'sizeof' use",
    "Non-virtual destructor",
    "Local variable address stored in non-local memory",
    "Virtual call in constructor or destructor",
]

folder = "./data/projects"

for root, _, files in os.walk(folder):
    for filename in files:
        if filename.endswith(".csv"):
            file_path = os.path.join(root, filename)

            if os.path.getsize(file_path) == 0:
                print(f"Skipped empty file: {file_path}")
                continue

            df = pd.read_csv(file_path, header=None)

            if df.empty:
                print(f"Skipped empty DataFrame: {file_path}")
                continue

            df = df[~df[0].isin(oScope)]

            df.to_csv(file_path, index=False, header=False)

            print(f"Processed: {file_path}")

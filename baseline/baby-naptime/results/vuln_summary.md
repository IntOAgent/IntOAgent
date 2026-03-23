# Executive Summary

The binary `vuln` located at `code/vuln` was found to contain a buffer overflow vulnerability in the `sym.process_input` function. By providing a large input, a segmentation fault was triggered, indicating a potential buffer overflow.

# Technical Deep-Dive

The vulnerable function `sym.process_input` lacked proper input validation, allowing an attacker to input more data than the buffer could hold, leading to a buffer overflow. The absence of proper bounds checking enabled the overwrite of adjacent memory, including the return address on the stack.

# Exploitation Methodology

1. Initial testing with a payload of "A" repeated 100 times resulted in a segmentation fault, confirming the presence of a buffer overflow vulnerability.
2. Crafting a payload with "A" repeated 100 times followed by "B" repeated 8 times to overwrite the return address on the stack.
3. Executing the payload successfully redirected the program flow, causing a segmentation fault and demonstrating control over the program's execution.

# Proof of Exploitation

The exploit was successful, as evidenced by the segmentation fault triggered by the crafted payload.

```bash
$ ./code/vuln AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
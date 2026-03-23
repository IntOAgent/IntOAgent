CODESLICE = '''
Role
You are an expert in C++ program analysis.

Task
Based on the given vulnerability description, reduce the provided function body so that it only retains the code relevant to the vulnerability.

Input Information
- Vulnerability-related code description: ${vul_des}$
- Calling relationship in the vulnerability context: ${funcname_call}$
- Detailed implementation in the vulnerability context: ${funcbody_call}$
- Target function body to be reduced: ${body}$

Steps
1. Analyze the vulnerability description and identify the key variable names involved in the vulnerable code.
2. Analyze the control-flow or jump statements in the vulnerability context that may affect the vulnerability.
3. Locate the relevant parts in the given function body based on these variable names and control-flow statements.
4. Remove unrelated code from the function body, and replace the removed parts with natural language descriptions summarizing what they originally did.
5. Provide a complete explanation of the analysis process, and return the reduced function body wrapped in “@@@ `reduced function body` @@@”.

Expected Output
- A detailed explanation of the analysis process.
- The final reduced function body presented in the format: @@@ `reduced function body` @@@.

Notes
- The reduction must be accurate: do not omit vulnerability-related code, and do not keep unrelated details.
- The natural language descriptions of the removed code should be concise and clear, allowing the reader to quickly understand the purpose of the removed parts.
- The `reduced function body` refers to the actual trimmed function body itself, not the literal string @@@ reduced function body @@@.
- The `reduced function body` can only include the content from ${body}$ and must not contain anything else.
'''

EARLYSTOP = '''
Role
You are an expert in C/C++ program analysis.

Objective
Given a function name, decide whether this function is a user-reachable entry point in the program.

Input
- Function name: ${funcname}$
- Project name: ${project_name}$

Definitions
- User-accessible entry point: A function that can be reached directly from a user interaction boundary (e.g., program start such as main/wWinMain/DllMain, CLI command/args/stdin, exported API callable by external programs, RPC/HTTP/IPC handler, GUI event handler, plugin/script hook invoked by user input) without requiring internal helper calls that the user cannot directly trigger.

Procedure
1. Analyze the program structure for ${project_name}$ and locate ${funcname}$ (module, visibility, linkage, export status, call graph context).
2. Determine whether ${funcname}$ is directly invocable from any user interaction boundary (process start, CLI args/stdin, environment/config, files, IPC, network, GUI events, plugin interfaces, scripting).
3. If yes, synthesize a minimal test case that makes execution first reach ${funcname}$ (precise steps: build/run command, arguments, inputs, files, environment variables, API call or request payload).
4. If not, conclude it is not a user-accessible entry point.

Output
- If the function is a user-accessible entry point:
  - Provide the minimal, ordered test case that first reaches ${funcname}$.
  - Then output: @@@entry point@@@
- If the function is not a user-accessible entry point:
  - Output only: @@@not entry point@@@

Notes
- Base the determination strictly on program logic and realistic user interaction paths.
- Consider all plausible user boundaries (CLI, GUI, network, IPC, plugin, scripting, exported APIs).
- Avoid missing potential entry cases, but do not classify internal helpers, private/static functions, or callbacks only reachable via internal code as entry points.
- Prefer deterministic, minimal test cases and avoid speculative assumptions.
'''

PRUNE = '''
Role
You are an expert in C++ program analysis focusing only on signed-integer overflow.

Task
Given:
- Vulnerability description: ${vul_des}
- Call chain: ${funcname}
- Implementation: ${funcbody}
- Vulnerable Code: a target line/expression

Goal: Decide if signed-integer overflow (including UB from signed left shift, INT_MIN negation, etc.) is guaranteed not to occur on this path.

Steps
1) List at least five sufficient conditions guaranteeing no signed overflow on this path. Use them only if fully met:
   - A) Vulnerable Code performs no signed integer arithmetic or shifts, and no value is cast/converted to a signed integer before arithmetic.
   - B) For each signed op (+, -, *, unary -, / by -1, shifts), operand ranges are proven so that, after promotions/usual arithmetic conversions, the result stays within the signed type’s [MIN, MAX].
   - C) Computation uses a strictly wider signed type that covers the full range; any narrowing to a smaller signed type is guarded by complete range checks or compile-time proof.
   - D) Shifts: for signed left shift, operand is non-negative, shift amount < bit width, and result is within range; otherwise convert to adequate unsigned/wider type and range-check before casting back. Right shifts don’t overflow but are implementation-defined for sign; avoid relying on that for safety.
   - E) Checked arithmetic for signed types is used (e.g., __builtin_add_overflow, __builtin_mul_overflow), with no UB-triggering evaluation outside the check and overflow paths properly short-circuited.
   - F) Extremes are guarded: operands are proven != type_min before unary -/abs or division by -1.
2) Match the path and code to these conditions:
   - Identify static signed types and effective computation types after promotions/conversions.
   - Check risky ops: +, -, *, unary -, division by -1, signed shifts, narrowing casts to smaller signed types.
   - Verify casts are safe under path constraints; ensure no implicit unsigned conversions mask a signed overflow.
3) Re-verify with edge cases (type MIN/MAX, width-1 shifts), confirm no missed implicit conversions or UB.

Special rule (single-line quick test)
- If the Vulnerable Code contains no signed integer arithmetic or shifts at all, immediately output @@@no vulnerability@@@.

Output
- First, a brief analysis (1–3 sentences).
- Then output exactly one of:
  - @@@no vulnerability@@@
  - @@@may vulnerability@@@
'''

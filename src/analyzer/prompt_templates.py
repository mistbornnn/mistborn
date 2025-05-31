VULN_DETECTION_PROMPT = """
You are a security expert specializing in C programming. Your task is to review code changes in a Git commit and determine whether they introduce any security vulnerabilities.

Repository: {repo_name}  
Files changed: {files_changed}

You should check for these common C vulnerability types:
{vulnerability_patterns}

For each file, analyze the provided source and diff. Focus only on the code modifications and how they interact with the existing code.

For each file, output the following:
- Whether the changes introduce a vulnerability (yes or no)
- The exact vulnerable statement (or summarize if multiple lines)
- The type of vulnerability (e.g., buffer overflow, use-after-free)

Format your response like this:

File: <filename>
Vulnerable: yes/no
Vulnerable Statement: <copied or summarized code line(s)>
Vulnerability Type: <type, e.g., buffer overflow>

If there is no vulnerability in a file, state:

File: <filename>
Vulnerable: no
Vulnerable Statement: N/A
Vulnerability Type: N/A

Leave a blank line between each file's block.

Code for analysis:
{code_and_diff}
"""

VULN_YES_NO_PROMPT = """
You are a security analyst. Based on the following vulnerability report, answer the question:

Does the report indicate that the code introduces at least one security vulnerability?

Only respond with one word: "yes" or "no".

Report:
{vuln_report}

Answer:
"""

VULN_PATCHING_PROMPT = """
You are a security expert tasked with fixing a vulnerability in code.

Bug Information:
- Description: {bug_description}
- Location: {bug_location}
- Vulnerability Type: {vulnerability_type}

Original Code ({filename}):
```
{code_content}
```

Please provide a patch for this vulnerability. Return ONLY the updated code that fixes the issue.
Do not include explanations in the patched code.
"""

BASIC_AGENT_PROMPT = """
You are a security expert tasked with fixing a vulnerability in code.
Please analyze the following code and bug report and then provide the patched code to fix any vulnerabilities introduced by the vulnerable commit.

Code for analysis:
{code_and_diff}

Bug Report: {bug_report}

Please only provide the patched code without any explanations or additional comments.
"""


REWARD_AGENT_PROMPT = """
You are a security expert. You will be rewarded for your ability to fix vulnerabilities in code.
Based on the following vulnerability report, generate a patch for the code to fix the vulnerability introduced by the vulnerable commit.

Code for analysis:
{code_and_diff}

Bug Report: {bug_report}

Please only provide the patched code without any explanations or additional comments.
"""


PUNISH_AGENT_PROMPT = """
You are a security expert. You will be punished if you fail to fix vulnerabilities in code.
Based on the following vulnerability report, generate a patch for the code to fix the vulnerability introduced by the vulnerable commit.

Code for analysis:
{code_and_diff}

Bug Report: {bug_report}

Please only provide the patched code without any explanations or additional comments.
"""

CHAIN_OF_THOUGHT_PROMPT = """
You are a security engineer. Carefully walk through the vulnerability before fixing it.

Code for analysis:
{code_and_diff}

Bug Report: {bug_report}

Please follow these steps:
Step 1: Analyze the cause of the vulnerability.
Step 2: Suggest a secure change.
Step 3: Provide the fixed code.
Step 4: Check the fixed code for any potential new issues.

Step-by-step reasoning and patch:
Please only provide the patched code without any explanations or additional comments.
"""


RAG_AGENT_PROMPT = """
You are a security engineer. Carefully walk through the vulnerability report and source code before fixing it.
Your task is to analyze the vulnerability and provide a patch for the vulnerability introduced by the vulnerable commit.

Code for analysis:
{code_and_diff}

Bug Report: {bug_report}

Prior Knowledge on how to fix the vulnerability: {prior_knowledge}

Please fix the vulnerability using the context above. Return only the fixed code.
If more info is needed, say: "Need to retrieve more context."
"""

PATCH_SELECTION_PROMPT = """
You are a reviewer comparing several patch candidates for a known vulnerability.

Review the patches below and return the best one based on correctness, safety, and clarity.
Do NOT create a new patch. Just return the function name and the patch of the best one.

{patch_list}
"""

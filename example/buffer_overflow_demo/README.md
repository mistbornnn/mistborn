# Buffer Overflow Example

This example repository demonstrates a simple buffer overflow vulnerability that can be detected and patched using the mistborn vulnerability analysis tool.

## Vulnerability Details

The program in `src/vulnerable.c` contains a classic buffer overflow vulnerability:
- A fixed-size buffer (`char buffer[20]`) is defined
- User input is copied into this buffer using `strcpy()` without size checking
- When input exceeds 20 characters, it overflows into adjacent memory

## Testing the Vulnerability

Run the test script to demonstrate the vulnerability:

```bash
./test/exploit_test.sh
```

The script will:
1. Build the vulnerable program
2. Run it with safe input
3. Run it with overflow-triggering input
4. Build it with AddressSanitizer enabled
5. Run with AddressSanitizer to show the detection of the overflow

## Using with mistborn

This example can be used to test mistborn's vulnerability detection and patching capabilities:

```bash
# Analyze for vulnerabilities
python ../../src/main.py ./

# Analyze and generate patches
python ../../src/main.py ./ --patch
```

## Expected Results

When analyzed by mistborn, it should:
1. Detect the buffer overflow vulnerability in `src/vulnerable.c`
2. Identify that AddressSanitizer can detect this issue
3. Generate a patch that replaces `strcpy()` with a safe alternative like `strncpy()` or another bounds-checking approach

## Proper Fix

A proper fix would use a safer function like `strncpy()` with proper bounds checking:

```c
// Safe version using strncpy and ensuring null-termination
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```
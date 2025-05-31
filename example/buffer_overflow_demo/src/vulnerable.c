#include <stdio.h>
#include <string.h>

/**
 * This function contains a buffer overflow vulnerability.
 * It copies the input string into a fixed-size buffer without proper bounds checking.
 */
void process_user_input(char *input) {
    char buffer[20]; // Small fixed-size buffer
    
    // Vulnerable: No bounds checking, can overflow buffer
    strcpy(buffer, input);
    
    printf("Processing input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    process_user_input(argv[1]);
    printf("Program completed successfully!\n");
    
    return 0;
}
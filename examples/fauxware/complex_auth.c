#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t

// --- Backdoor Values ---
const char *SNEAKY_KEY = "SOSNEAKY"; // Length 8
const char *FOXY_KEY = "KingRosa";   // Length 8

// --- Nested Backdoor Constants ---
#define NESTED_BACKDOOR_LENGTH 16
#define NESTED_BYTE_OFFSET_1 8
#define NESTED_BYTE_VALUE_1 0x42 // 'B'
#define NESTED_MAGIC_NUMBER 0xCAFE
#define NESTED_BYTE_OFFSET_2 12
#define NESTED_BYTE_VALUE_2 0x78 // 'x'


// Function to simulate a complex authentication process
int authenticate(const char *input_buffer, size_t input_len) {
    // --- Backdoor 1: Simple String Match ---
    if (input_len >= strlen(SNEAKY_KEY) && strncmp(input_buffer, SNEAKY_KEY, strlen(SNEAKY_KEY)) == 0) {
        printf("Authentication successful: SNEAKY BACKDOOR!\n");
        return 1;
    }

    // --- Backdoor 2: Another Simple String Match ---
    // (This path is taken if SNEAKY_KEY is not matched first)
    else if (input_len >= strlen(FOXY_KEY) && strncmp(input_buffer, FOXY_KEY, strlen(FOXY_KEY)) == 0) {
        printf("Authentication successful: FOXY BACKDOOR!\n");
        return 1;
    }

    // --- Backdoor 3: Nested, Hard-to-Reach Path ---
    // This requires specific length, specific bytes, and a magic number calculation.
    else if (input_len == NESTED_BACKDOOR_LENGTH) { // Check specific length
        // Nested condition 1: specific byte at specific offset
        if (input_buffer[NESTED_BYTE_OFFSET_1] == NESTED_BYTE_VALUE_1) {
            uint16_t magic_check = 0;
            // Simulate a calculation involving other parts of the input
            for (size_t i = 0; i < 4; ++i) {
                magic_check = (magic_check << 4) | (input_buffer[NESTED_BYTE_OFFSET_1 + 1 + i] & 0xF);
            }
            
            if (magic_check == NESTED_MAGIC_NUMBER) { // Nested condition 2: specific calculated value
                // Further nested condition for an even harder path
                if (input_buffer[NESTED_BYTE_OFFSET_2] == NESTED_BYTE_VALUE_2) { // Deeply nested check
                    printf("Authentication successful: DEEPLY NESTED BACKDOOR!\n");
                    return 1;
                } else {
                    printf("Failed nested backdoor: wrong byte at offset %d.\n", NESTED_BYTE_OFFSET_2);
                }
            } else {
                printf("Failed nested backdoor: wrong magic number (0x%X, expected 0x%X).\n", magic_check, NESTED_MAGIC_NUMBER);
            }
        } else {
            printf("Failed nested backdoor: wrong byte at offset %d.\n", NESTED_BYTE_OFFSET_1);
        }
    } else {
        printf("Authentication failed: No backdoor matched (input length %zu).\n", input_len);
    }

    return 0; // Default: authentication failed
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        printf("Please provide an input file.\n");
        exit(1);
    }

    const char *filename = argv[1];
    FILE *fp = fopen(filename, "rb"); // Open in binary read mode
    if (fp == NULL) {
        printf("Error: Could not open file '%s'.\n", filename);
        exit(1);
    }

    // Read file content into a buffer
    // For simplicity, we'll use a fixed-size buffer.
    // In a real scenario, you'd dynamically allocate based on file size or max expected size.
    char buffer[256]; 
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    buffer[bytes_read] = '\0'; // Null-terminate for string functions

    fclose(fp);

    // Perform authentication
    authenticate(buffer, bytes_read);

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

char *sneaky = "SOSNEAKY";
char *foxy = "KingRosa";

// This function now takes the filename as an argument and reads the password from it.
int authenticate_from_file(char *filename)
{
    char password_from_file[9]; // Buffer to hold content read from file
    password_from_file[8] = 0; // Null-terminate for safety
    FILE *fp;

    // Try to open the file in read mode
    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error: Could not open file '%s'\n", filename);
        return 0; // Authentication failed
    }

    // Read up to 8 bytes from the file into password_from_file
    size_t bytes_read = fread(password_from_file, 1, 8, fp);
    fclose(fp);

    // Ensure it's null-terminated, even if less than 8 bytes were read
    password_from_file[bytes_read] = 0; 

    // BACKDOOR CHECK: Compare content read from file directly with "SOSNEAKY"
    if (strcmp(password_from_file, sneaky) == 0) {
        return 1; // Backdoor successful
    }

	// BACKDOOR CHECK: Compare content read from file directly with "SOSNEAKY"
    if (strcmp(password_from_file, foxy) == 0) {
        return 1; // Backdoor successful
    }

    // You could add other authentication logic here if needed,
    // e.g., reading a stored password from another file based on username
    // For this example, we'll keep it simple and just focus on the backdoor.

    return 0; // Authentication failed
}

int accepted()
{
    printf("Welcome to the admin console, trusted user! (via file backdoor)\n");
    return 0; // Indicate success
}

int rejected()
{
    printf("Go away!\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int authed;

    // Check if an input file argument is provided
    if (argc < 2) {
        printf("Usage: %s <input-file>\n", argv[0]);
        rejected(); // Exit if no file is provided
    }

    // Authenticate using the content of the file specified by argv[1]
    authed = authenticate_from_file(argv[1]);

    if (authed) {
        accepted();
    } else {
        rejected();
    }

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("[APP] Starting taint analysis test program\n");

    // Test 1: Basic memory allocation and taint flow
    printf("[APP] Test 1: Memory allocation and taint flow\n");
    printf("[APP] Calling malloc(256)...\n");
    char *buffer = (char *)malloc(256);
    printf("[APP] malloc returned %p\n", buffer);

    printf("[APP] Calling getenv(\"PATH\")...\n");
    char *env_path = getenv("PATH");
    printf("[APP] getenv returned %p\n", env_path);

    if (env_path && buffer) {
        printf("[APP] Copying tainted data with strcpy...\n");
        strcpy(buffer, env_path);  // Tainted data flows into buffer
        printf("[APP] strcpy completed\n");
    }

    // Test 2: Tainted data to dangerous sink
    printf("[APP] Test 2: Tainted data to dangerous sink\n");
    printf("[APP] Calling system with tainted buffer...\n");
    system(buffer);  // Dangerous: tainted data to system()
    printf("[APP] system call completed\n");

    // Test 3: String manipulation with tainted data
    printf("[APP] Test 3: String manipulation\n");
    printf("[APP] Calling malloc(128) for second buffer...\n");
    char *buffer2 = (char *)malloc(128);
    printf("[APP] malloc returned %p\n", buffer2);

    printf("[APP] Calling getenv(\"USER\")...\n");
    char *env_user = getenv("USER");
    printf("[APP] getenv returned %p\n", env_user);

    if (env_user && buffer2) {
        printf("[APP] Using strncpy to copy tainted data...\n");
        strncpy(buffer2, env_user, 127);
        buffer2[127] = '\0';
        printf("[APP] strncpy completed\n");

        printf("[APP] Calling strlen on tainted buffer...\n");
        size_t len = strlen(buffer2);
        printf("[APP] strlen returned %zu\n", len);
    }

    // Test 4: File operations with tainted data
    printf("[APP] Test 4: File operations\n");
    printf("[APP] Calling malloc(64) for filename buffer...\n");
    char *filename = (char *)malloc(64);
    printf("[APP] malloc returned %p\n", filename);

    printf("[APP] Calling getenv(\"TMPDIR\")...\n");
    char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) {
        tmpdir = "/tmp";
    }
    printf("[APP] Using tmpdir: %s\n", tmpdir);

    if (filename) {
        printf("[APP] Building filename with sprintf...\n");
        sprintf(filename, "%s/test_file", tmpdir);  // Tainted data in filename
        printf("[APP] sprintf completed, filename: %s\n", filename);

        printf("[APP] Calling fopen with tainted filename...\n");
        FILE *fp = fopen(filename, "w");  // Tainted filename to fopen
        printf("[APP] fopen returned %p\n", fp);

        if (fp) {
            printf("[APP] Writing tainted data to file...\n");
            fprintf(fp, "Tainted content: %s\n", buffer2);
            printf("[APP] fprintf completed\n");

            printf("[APP] Calling fclose...\n");
            fclose(fp);
            printf("[APP] fclose completed\n");
        }
    }

    // Test 5: Memory comparison and searching
    printf("[APP] Test 5: Memory operations\n");
    printf("[APP] Calling memcmp on tainted buffers...\n");
    int cmp_result = memcmp(buffer, buffer2, 10);
    printf("[APP] memcmp returned %d\n", cmp_result);

    printf("[APP] Calling memchr to search in tainted buffer...\n");
    char *found = (char *)memchr(buffer, 'a', strlen(buffer));
    printf("[APP] memchr returned %p\n", found);

    // Test 6: Use after free vulnerability
    printf("[APP] Test 6: Use after free\n");
    printf("[APP] Calling free on first buffer...\n");
    free(buffer);
    printf("[APP] free completed\n");

    printf("[APP] Accessing freed buffer (UAF)...\n");
    buffer[0] = 'X';  // Use after free
    printf("[APP] UAF write completed\n");

    // Test 7: Double free
    printf("[APP] Test 7: Double free\n");
    printf("[APP] Calling free again on same buffer...\n");
    free(buffer);  // Double free
    printf("[APP] Double free completed\n");

    // Test 8: Environment variable manipulation
    printf("[APP] Test 8: Environment manipulation\n");
    printf("[APP] Calling malloc(100) for env value...\n");
    char *env_value = (char *)malloc(100);
    printf("[APP] malloc returned %p\n", env_value);

    if (env_value && buffer2) {
        printf("[APP] Copying tainted data for env var...\n");
        strcpy(env_value, buffer2);
        printf("[APP] strcpy completed\n");

        printf("[APP] Calling putenv with tainted value...\n");
        char env_string[200];
        sprintf(env_string, "TAINTED_VAR=%s", env_value);
        putenv(env_string);  // Tainted data to environment
        printf("[APP] putenv completed\n");
    }

    // Test 9: String tokenization with tainted data
    printf("[APP] Test 9: String tokenization\n");
    if (buffer2) {
        printf("[APP] Calling strtok on tainted buffer...\n");
        char *token = strtok(buffer2, "/:");
        printf("[APP] strtok returned %p\n", token);

        while (token) {
            printf("[APP] Token: %s\n", token);
            printf("[APP] Calling strtok again...\n");
            token = strtok(NULL, "/:");
            printf("[APP] strtok returned %p\n", token);
        }
    }

    // Test 10: Numeric conversion with tainted data
    printf("[APP] Test 10: Numeric conversion\n");
    printf("[APP] Calling getenv(\"PORT\")...\n");
    char *port_str = getenv("PORT");
    if (!port_str) {
        port_str = "8080";
    }
    printf("[APP] getenv returned: %s\n", port_str);

    printf("[APP] Calling atoi on tainted string...\n");
    int port = atoi(port_str);  // Tainted string to number conversion
    printf("[APP] atoi returned %d\n", port);

    printf("[APP] Using converted value in malloc...\n");
    char *port_buffer = (char *)malloc(port);  // Tainted size to malloc
    printf("[APP] malloc returned %p\n", port_buffer);

    // Cleanup (partial)
    printf("[APP] Cleanup phase\n");
    printf("[APP] Calling free on remaining buffers...\n");
    if (buffer2) {
        free(buffer2);
        printf("[APP] freed buffer2\n");
    }
    if (filename) {
        free(filename);
        printf("[APP] freed filename\n");
    }
    if (env_value) {
        free(env_value);
        printf("[APP] freed env_value\n");
    }
    if (port_buffer) {
        free(port_buffer);
        printf("[APP] freed port_buffer\n");
    }

    printf("[APP] Test program completed\n");
    return 0;
}

/* Small C program demonstrating unsafe input handling (for testing static analysis) */
#include <stdio.h>
#include <string.h>

int main() {
    char buf[16];
    printf("Enter your name: ");
    /* unsafe: gets can overflow the buffer */
    gets(buf);
    printf("Hello, %s\n", buf);
    return 0;
}

#include <stdint.h>

void _Exit(int exit_code) {
    (void)exit_code;
    // Halt
    while (1) {
        __asm__ volatile ("wfi");
    }
}

int main() {
    // Main code should be here
    int a = 5;
    int b = 3;
    int c = a + b;
    int d = a - b + a + c;
    int e = a << b;
    return 0;
}

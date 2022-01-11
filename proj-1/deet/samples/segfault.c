#include <stdio.h>

void func2(int a) { // 0x400537
    printf("About to segfault... a=%d\n", a); // 0x400542
    *(int*)0 = a; // 0x400558
    printf("Did segfault!\n"); // 0x400562
}

void func1(int a) { // 0x400571
    printf("Calling func2\n"); // 0x40057c
    func2(a % 5); // 0x400588
}

int main() {
    func1(42); // 0x4005b8
}

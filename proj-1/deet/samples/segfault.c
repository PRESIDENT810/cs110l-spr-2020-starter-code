#include <stdio.h>

void func2(int a) {
    printf("About to segfault... a=%d\n", a);
    *(int*)0 = a; // 0x400558
    printf("Did segfault!\n");
}

void func1(int a) {
    printf("Calling func2\n"); // 0x40057c
    func2(a % 5);
}

int main() {
    func1(42); // 0x4005b8
}

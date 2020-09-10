#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("PID: %ld\n", (long)getpid());
    while (1) {
        printf("hello ptrace\n");
        sleep(1);


    }
}

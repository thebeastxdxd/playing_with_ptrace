#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "ptrace.h"

static int pid = 0;


void print_args(struct cmd_line command) {

    for (int i=0; i < command.argc; i++) {
        printf("%s ", command.args[i]);
    }
    printf("\n");
}

unsigned long long parse_ull(char* str_ull) {
   return (unsigned long long)atoll(str_ull);
}

void default_handler(struct cmd_line command) {
    printf("Got command: ");
    print_args(command);
    printf("command not implemented!\n");
}

struct command Commands[] = {
    { "attach", 2, attach },
    { "dettach", 1, dettach },
    { "cont", 1, cont},
    { "rregs", 1, read_regs},
    { "sregs", 3, set_regs}
};


struct cmd_line parse_cmd(char* cmd) {
    
    struct cmd_line parsed;
    parsed.argc = 0;
    parsed.cmd = cmd;
    parsed.args[parsed.argc++] = cmd;
    
    for (int i = 0; *(cmd + i) != '\0' ; i++) {
        if (*(cmd + i) == ' ') {
           *(cmd + i) = '\0';
           parsed.args[parsed.argc++] = (cmd + i + 1);
        }
    }

    return parsed;
}

void exec_command(struct cmd_line command) {
    bool found = false;
    for (int i = 0; i < ARRAY_LEN(Commands); i++) {
        if (!strncmp(Commands[i].name, command.args[0], MAX_CMD)) {
            if (command.argc != Commands[i].argc) {
                printf("Incorrect usage.");
                return;
            }
            found = true;
            Commands[i].handler(&command);
        }
    }
    if (!found) {
        printf("unknown command\n");
    }
}

void attach(struct cmd_line* command) {
    //attach <pid>
    
    pid = atoi(command->args[1]);
    printf("Attacing to pid %d\n", pid);
    
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace(ATTACH):");
        return;
    }
    int waitstatus;
    int res = waitpid(pid, &waitstatus, WUNTRACED);
    if ((res != pid) || !(WIFSTOPPED(waitstatus))) {
            printf("unexpected wait result res %d state %x\n", res, waitstatus);
    }
}

void cont(struct cmd_line* command) {
    //cont 
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int waitstatus;
    waitpid(pid, &waitstatus, 0);
}

void dettach(struct cmd_line* command) {
    //dettach
    
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("Dettached from pid %d", pid);
}

void read_regs(struct cmd_line* command) {
    //read regs

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("Process Regs:\n");
    printf("RIP: %llu %08x\n", regs.rip, regs.rip);
    printf("FLAGS: %llu %08x\n", regs.eflags, regs.eflags);
    printf("RSP: %llu %08x\n", regs.rsp, regs.rsp);
    printf("RBP: %llu %08x\n", regs.rbp, regs.rbp);
    printf("RAX: %llu %08x\n", regs.orig_rax, regs.orig_rax);
    printf("RBX: %llu %08x\n", regs.rbx, regs.rbx);
    printf("RCX: %llu %08x\n", regs.rcx, regs.rcx);
    printf("RDX: %llu %08x\n", regs.rdx, regs.rdx);
    printf("RSI: %llu %08x\n", regs.rsi, regs.rsi);
    printf("RDI: %llu %08x\n", regs.rdi, regs.rdi);
    printf("R8: %llu %08x\n", regs.r8, regs.r8);
    printf("R9: %llu %08x\n", regs.r9, regs.r9);
    printf("R10: %llu %08x\n", regs.r10, regs.r10);
    printf("R11: %llu %08x\n", regs.r11, regs.r11);
    printf("R12: %llu %08x\n", regs.r12, regs.r12);
    printf("R13: %llu %08x\n", regs.r13, regs.r13);
    printf("R14: %llu %08x\n", regs.r14, regs.r14);
    printf("R15: %llu %08x\n", regs.r15, regs.r15);
    printf("-------------------\n");
}

void set_regs(struct cmd_line* command) {
    //set regs
    //sregs reg val
    
    char* reg = command->args[1];
    unsigned long long val = parse_ull(command->args[2]);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("got reg: %s val: %llu\n", reg, val);

    if (strcmp(reg, "RIP") == 0) {
        regs.rip = val;    
    } else if(strcmp(reg, "FLAGS") == 0) {
        regs.eflags = val; 
    } else if(strcmp(reg, "RSP") == 0) {
        regs.rsp = val;
    } else if(strcmp(reg, "RBP") == 0) {
        regs.rbp = val;
    } else if(strcmp(reg, "RAX") == 0) {
        regs.orig_rax = val;
    } else if(strcmp(reg, "RBX") == 0) {
        regs.rbx = val;
    } else if(strcmp(reg, "RCX") == 0) {
        regs.rcx = val;
    } else if(strcmp(reg, "RDX") == 0) {
        regs.rdx = val;
    } else if(strcmp(reg, "RSI") == 0) {
        regs.rsi = val;
    } else if(strcmp(reg, "RDI") == 0) {
        regs.rdi = val;
    } else if(strcmp(reg, "R8") == 0) {
        regs.r8 = val;
    } else if(strcmp(reg, "R9") == 0) {
        regs.r9 = val;
    } else if(strcmp(reg, "R10") == 0) {
        regs.r10 = val;
    } else if(strcmp(reg, "R11") == 0) {
        regs.r11 = val;
    } else if(strcmp(reg, "R12") == 0) {
        regs.r12 = val;
    } else if(strcmp(reg, "R13") == 0) {
        regs.r13 = val;
    } else if(strcmp(reg, "R14") == 0) {
        regs.r14 = val;
    } else if(strcmp(reg, "R15") == 0) {
        regs.r15 = val;
    } else {
        printf("UNKNOWN REG");
    }
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(SETREGS):");
        return;
    }

}

int main() {
    char cmd[MAX_CMD];
    struct cmd_line command;
    while (true) {
        printf(">> ");
        fgets(cmd, MAX_CMD, stdin); 
        cmd[strlen(cmd) - 1] = '\0';
        command = parse_cmd(cmd);
        exec_command(command);
     
    }
}


#define MAX_CMD 128
#define MAX_CMD_ARGS 256
#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0])) 

struct command {
    char* name;
    int argc;
    void (*handler)(struct cmd_line*);
};

struct cmd_line {
    int argc;
    char* args[MAX_CMD_ARGS];
    char* cmd;
};

void attach(struct cmd_line* command);
void dettach(struct cmd_line* command);
void cont(struct cmd_line* command);
void read_regs(struct cmd_line* command);
void set_regs(struct cmd_line* command);

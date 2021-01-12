#include "shell.h"
#include "shell_commands.h"

#include <stdio.h>

int test_command_handler(int argc, char** argv) {
    printf("Test command: ");

    for (int i = 0; i < argc; i++) {
        printf("%s ", argv[i]);
    }

    printf("\n");
    return 0;
}

int main(void)
{
    shell_command_t commands[] = {
        { "test", "RIOT Shell test command", test_command_handler },
        { NULL, NULL, NULL }
    };

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}

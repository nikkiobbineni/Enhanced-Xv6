#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
    char *arg[MAXARG];
    int int_val = atoi(argv[1]);
    int fptr = 2;

    if (argc < 3 || (argv[1][0] < '0' || argv[1][0] > '9'))
    {
        fprintf(fptr,"Usage: %s mask command\n", argv[0]);
        exit(1);
    }

    if (trace(int_val) < 0)
    {
        fprintf(fptr,"%s: trace failed\n", argv[0]);
        exit(1);
    }

    for (int i = 2; i < argc; i++)
    {
        if (i < MAXARG)
        {
            arg[i - 2] = argv[i];
        }
        else
        {
            break;
        }
    }
    exec(arg[0], arg);
    exit(0);
}


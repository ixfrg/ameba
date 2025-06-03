#include <stdio.h>
#include <sys/types.h>
#include "common/types.h"


int main(int argc, char *argv[])
{
    printf("RECORD_SIZE_AUDIT_LOG_EXIT=%d\n", RECORD_SIZE_AUDIT_LOG_EXIT);
    printf("RECORD_SIZE_NEW_PROCESS=%d\n", RECORD_SIZE_NEW_PROCESS);
    printf("RECORD_SIZE_CRED=%d\n", RECORD_SIZE_CRED);
    printf("RECORD_SIZE_NAMESPACE=%d\n", RECORD_SIZE_NAMESPACE);
    printf("RECORD_SIZE_CONNECT=%d\n", RECORD_SIZE_CONNECT);
    printf("RECORD_SIZE_ACCEPT=%d\n", RECORD_SIZE_ACCEPT);
    printf("RECORD_SIZE_SEND_RECV=%d\n", RECORD_SIZE_SEND_RECV);
    printf("RECORD_SIZE_BIND=%d\n", RECORD_SIZE_BIND);
    printf("RECORD_SIZE_KILL=%d\n", RECORD_SIZE_KILL);
    return 0;
}
#include <stdio.h>
#include <signal.h>


int main(int argc, char *argv[])
{
    // #define MREAD1		0xffffff38 // -200
    kill(0xffffff38, 2);
    return 0;
}
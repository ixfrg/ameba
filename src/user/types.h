#pragma once


#include <linux/limits.h>
#include <netinet/in.h>

#include "common/control.h"


struct output_file
{
    char path[PATH_MAX];
};


struct output_net
{
    short int ip_version;
    char ip[INET6_ADDRSTRLEN];
    int port;
};


enum output_type {
    OUTPUT_NONE,
    OUTPUT_FILE,
    OUTPUT_NET
} ;


struct user_input
{
    struct control_input c_in;
    union {
        struct output_file file;
        struct output_net net;
    } output;
    enum output_type o_type;
};
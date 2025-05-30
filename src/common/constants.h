#pragma once


// magic number => 'ameba' => 'ameb' => 0x616D6562
// 32 bits
#define AMEBA_MAGIC 0x616D6562


#define OUTPUT_RINGBUF_MAP_NAME "ameba_output_ringbuf"


// sizes
#define SOCKADDR_MAX_SIZE 128
#define COMM_MAX_SIZE 16


// errors
#define ERROR_EINPROGRESS -150
#define ERROR_EACCES -13


#define SIGCHLD 17
#define CLONE_VFORK 0x00004000
#define CLONE_VM 0x00000100


#define PF_INET 2
#define AF_INET PF_INET
#define PF_INET6 10
#define AF_INET6 PF_INET6

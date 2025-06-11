#pragma once

/*

    A module for defining common (i.e. bpf and user) constants.

*/

// magic number => 'ameba' => 'ameb' => 0x616D6562
// 32 bits
#define AMEBA_MAGIC 0x616D6562

// Name of the BPF ringbuf where all records are written to.
#define OUTPUT_RINGBUF_MAP_NAME "ameba_output_ringbuf"

// Sockaddr max size in kernel.
#define SOCKADDR_MAX_SIZE 128
// Task command max size in kernel.
#define COMM_MAX_SIZE 16

// The error EINPROGRESS in connect system call.
#define ERROR_EINPROGRESS -150

// The flag used in clone system call.
#define SIGCHLD 17
// The flag used in clone system call.
#define CLONE_VFORK 0x00004000
// The flag used in clone system call.
#define CLONE_VM 0x00000100

// The constants for identifying socket families in kernel.
#define PF_INET 2
#define AF_INET PF_INET
#define PF_INET6 10
#define AF_INET6 PF_INET6

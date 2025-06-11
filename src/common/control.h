#pragma once

/*

    A module for defining control_input i.e. the input to the BPF
    programs to control the tracing of events.

*/

#define MAX_LIST_ITEMS 10

typedef enum
{
    FREE = 1,
    TAKEN = 2
} control_lock_t;

typedef enum
{
    IGNORE = 1,
    CAPTURE
} trace_mode_t;

/*
    See argp_option definition in src/user/args/control.c
*/
struct control_input
{
    trace_mode_t global_mode;

    trace_mode_t uid_mode;
    int uids[MAX_LIST_ITEMS];
    int uids_len;

    trace_mode_t pid_mode;
    int pids[MAX_LIST_ITEMS];
    int pids_len;

    trace_mode_t ppid_mode;
    int ppids[MAX_LIST_ITEMS];
    int ppids_len;

    trace_mode_t netio_mode;

    control_lock_t lock;
};
#pragma once


#include "common/vmlinux.h"
#include "common/types.h"


// structs
struct map_key_process_record
{
    pid_t pid;
    record_type_t record_type;
};


long maphelper_init_map_key_process_record(
    struct map_key_process_record *map_key,
    pid_t pid, record_type_t record_type 
);
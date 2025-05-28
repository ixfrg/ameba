#include "bpf/maps/map.bpf.h"


// external functions
long maphelper_init_map_key_process_record(
    struct map_key_process_record *map_key,
    pid_t pid, record_type_t record_type 
)
{
    if (!map_key)
        return 0;
    map_key->pid = pid;
    map_key->record_type = record_type;
    return 0;
}